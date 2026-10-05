"""TiTaN Panel — desired-state builder + node agent transport.

The panel is the single source of truth. ``build_desired_state()`` renders the
complete node payload (Xray config, Nginx main/vhosts, sysctl, decoy, optional
extra cores, firewall plan) and ``push_state()`` ships it to the node agent,
which validates and hot-reloads. Nothing is written to a node without passing
``xray -test`` / ``nginx -t`` first.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models import ActivityLog, Client, Inbound, Node, NodeStatus, Protocol, Security, Transport, User, utcnow
from ..settings import settings
from . import xray_config as xc

logger = logging.getLogger("titan.provisioner")

AGENT_TIMEOUT = httpx.Timeout(30.0, connect=8.0)


# ── desired state ────────────────────────────────────────────────────────────
async def load_node_bundle(session: AsyncSession, node_id: int) -> tuple[Node, list[Inbound]]:
    node = await session.get(Node, node_id)
    if node is None:
        raise ValueError(f"node {node_id} not found")
    result = await session.execute(
        select(Inbound)
        .where(Inbound.node_id == node_id)
        .options(selectinload(Inbound.clients).selectinload(Client.user))
        .order_by(Inbound.id)
    )
    inbounds = list(result.scalars().all())
    return node, inbounds


def _stream_routes(node: Node, inbounds: list[Inbound]) -> list[tuple[str, str]]:
    """SNI → xray loopback port for REALITY passthrough inbounds."""
    routes: list[tuple[str, str]] = []
    for inbound in inbounds:
        if not inbound.is_active or xc.routing_mode(inbound) != "passthrough":
            continue
        sni = (inbound.reality_server_names.split(",")[0].strip() if inbound.reality_server_names else "") or inbound.sni or node.address
        routes.append((sni, f"127.0.0.1:{inbound.internal_port}"))
    return routes


def preflight(node: Node, inbounds: list[Inbound]) -> dict:
    """Catch problems *before* touching a live node.

    Returns ``{"errors": [...], "warnings": [...]}``. Errors block deployment,
    warnings are shown to the operator (e.g. "issue a certificate first").
    """
    errors: list[str] = []
    warnings: list[str] = []
    active = [i for i in inbounds if i.is_active]

    if not active:
        warnings.append("هیچ کانفیگ فعالی روی این سرور وجود ندارد — فقط سایت پوششی و Nginx مستقر می‌شود.")

    needs_cert = any(xc.routing_mode(i) in ("fronted", "direct") and i.security is Security.TLS for i in active)
    if needs_cert and not node.cert_expires_at:
        warnings.append("برای کانفیگ‌های TLS هنوز گواهی صادر نشده است؛ ابتدا از صفحه‌ی سرور «صدور گواهی TLS» را بزنید.")

    public_ports: dict[int, str] = {}
    for inbound in active:
        mode = xc.routing_mode(inbound)
        if mode == "direct":
            if inbound.port == node.port:
                errors.append(f"کانفیگ «{inbound.name}» پورت {inbound.port} را می‌خواهد که در اختیار Nginx (ورودی ۴۴۳) است؛ یک پورت اختصاصی بدهید.")
            if inbound.port in public_ports:
                errors.append(f"تداخل پورت {inbound.port} بین «{public_ports[inbound.port]}» و «{inbound.name}».")
            public_ports[inbound.port] = inbound.name
        if inbound.security is Security.REALITY and not inbound.reality_private_key:
            errors.append(f"کلید REALITY برای «{inbound.name}» تنظیم نشده است.")
        if mode == "fronted" and not inbound.path:
            errors.append(f"مسیر (path) برای «{inbound.name}» تعیین نشده است.")
    return {"errors": errors, "warnings": warnings}


def build_desired_state(node: Node, inbounds: list[Inbound]) -> dict:
    """Everything the node needs, as one JSON document."""
    clients_by_inbound = {inbound.id: list(inbound.clients) for inbound in inbounds}
    xray = xc.build_xray_config(node, inbounds, clients_by_inbound)

    state: dict = {
        "node": {
            "id": node.id,
            "name": node.name,
            "address": node.address,
            "port": node.port,
            "generated_at": datetime.utcnow().isoformat(),
        },
        "xray_config": xray,
        "nginx_main": xc.build_nginx_main(node, _stream_routes(node, inbounds)),
        "nginx_vhost": xc.build_nginx_vhost(node, inbounds),
        "nginx_redirect": xc.build_nginx_http_redirect(),
        "sysctl": xc.build_sysctl_conf(),
        "decoy_html": xc.DEFAULT_DECOY_HTML,
        "firewall_rules": xc.build_ufw_rules(node, inbounds),
    }

    hy2 = xc.build_hysteria2_config(node, inbounds)
    if node.hysteria2_enabled and hy2:
        state["hysteria2_yaml"] = _yaml_dump(hy2)

    wg = xc.build_wireguard_config(node, inbounds)
    if node.wireguard_enabled and wg:
        state["wireguard_conf"] = wg

    return state


def _yaml_dump(data: dict, indent: int = 0) -> str:
    """Tiny YAML writer so the panel needs no PyYAML at runtime."""
    pad = "  " * indent
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{pad}{key}:")
            lines.append(_yaml_dump(value, indent + 1))
        elif isinstance(value, list):
            lines.append(f"{pad}{key}:")
            for item in value:
                if isinstance(item, dict):
                    first = True
                    for sub_key, sub_value in item.items():
                        prefix = f"{pad}  - " if first else f"{pad}    "
                        lines.append(f"{prefix}{sub_key}: {_scalar(sub_value)}")
                        first = False
                else:
                    lines.append(f"{pad}  - {_scalar(item)}")
        else:
            lines.append(f"{pad}{key}: {_scalar(value)}")
    return "\n".join(lines)


def _scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "''"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or any(ch in text for ch in ":#{}[]&*!|>'\"%@`"):
        return json.dumps(text, ensure_ascii=False)
    return text


def shaping_plan_for(node: Node, inbounds: list[Inbound]) -> dict:
    """Per-user speed limits → per-IP shaper rules (see agent ``/shaping``)."""
    limits: dict[str, int] = {}
    for inbound in inbounds:
        for client in inbound.clients:
            user = client.user
            if user and user.speed_limit:
                limits[client.email_tag] = user.speed_limit
    return {"limits": limits}


# ── agent transport ──────────────────────────────────────────────────────────
def agent_base(node: Node) -> str:
    return f"{node.agent_scheme}://{node.address}:{node.agent_port}"


def _headers(node: Node) -> dict:
    return {"X-Titan-Token": node.agent_token, "Content-Type": "application/json"}


async def agent_get(node: Node, path: str, timeout: float = 15.0) -> dict:
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=6.0), verify=False) as client:
        response = await client.get(f"{agent_base(node)}{path}", headers=_headers(node))
        response.raise_for_status()
        return response.json()


async def agent_post(node: Node, path: str, payload: dict, timeout: float = 120.0) -> dict:
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=6.0), verify=False) as client:
        response = await client.post(f"{agent_base(node)}{path}", headers=_headers(node), json=payload)
        response.raise_for_status()
        return response.json()


def _mock_health(node: Node) -> dict:
    """Plausible health payload for UI demos (NODE_METRICS_MODE=mock).

    Never used in production: it only exists so the dashboard can be shown —
    or screenshotted — without a fleet of real servers attached.
    """
    import math
    import random

    tick = int(__import__("time").time() // 15)
    random.seed(f"{node.id}-{tick}")
    cpu = max(4.0, min(92.0, node.cpu_pct + random.uniform(-6, 6)))
    ram_ratio = (node.ram_used / node.ram_total) if node.ram_total else 0.45
    return {
        "ok": True,
        "agent_version": node.agent_version or "1.0.0",
        "hostname": node.address.split(".")[0],
        "os": node.os_info or "Linux Ubuntu 24.04",
        "uptime": node.uptime_sec + 900,
        "cpu_cores": node.cpu_cores or 2,
        "cpu_pct": round(cpu, 1),
        "ram_total": node.ram_total or 2 * 1024**3,
        "ram_used": int((node.ram_total or 2 * 1024**3) * min(0.95, max(0.15, ram_ratio + random.uniform(-0.03, 0.03)))),
        "disk_total": node.disk_total or 40 * 1024**3,
        "disk_used": node.disk_used or 12 * 1024**3,
        "load_avg": [round(cpu / 100 * (node.cpu_cores or 2), 2), 0.4, 0.3],
        "ping_ms": node.ping_ms or int(20 + 10 * math.sin(tick / 4) + random.uniform(-3, 3)),
        "xray_version": node.xray_version or "Xray 26.3.27",
        "nginx_version": node.nginx_version or "nginx/1.26.2",
        "services": {"xray": True, "nginx": True},
        "cert": {"present": True, "expires_at": node.cert_expires_at.isoformat() if node.cert_expires_at else None,
                 "issuer": node.cert_issuer, "days_left": None},
        "mock": True,
    }


async def probe_node(node: Node, *, persist: bool = True, session: AsyncSession | None = None) -> dict:
    """Fetch live health from the agent and (optionally) persist it."""
    started = asyncio.get_event_loop().time()

    if settings.metrics_mode == "mock":
        data = _mock_health(node)
        node.status = NodeStatus.ONLINE
        node.status_message = "حالت دمو (NODE_METRICS_MODE=mock)"
        _apply_health(node, data, int((asyncio.get_event_loop().time() - started) * 1000))
        if persist and session is not None:
            session.add(node)
            await session.commit()
        return data

    try:
        data = await agent_get(node, "/health", timeout=12.0)
    except Exception as exc:  # network down, agent not installed, wrong token…
        node.status = NodeStatus.OFFLINE
        node.status_message = str(exc)[:180]
        if persist and session is not None:
            session.add(node)
            await session.commit()
        return {"ok": False, "error": str(exc)}

    elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
    _apply_health(node, data, elapsed_ms)

    if persist and session is not None:
        session.add(node)
        await session.commit()
    return {"ok": True, **data}


def _apply_health(node: Node, data: dict, elapsed_ms: int) -> None:
    """Copy an agent health payload onto the node row."""
    node.status = NodeStatus.ONLINE if data.get("services", {}).get("xray", True) else NodeStatus.DEGRADED
    node.status_message = "" if node.status is NodeStatus.ONLINE else "xray is not running"
    node.cpu_pct = float(data.get("cpu_pct") or 0)
    node.cpu_cores = int(data.get("cpu_cores") or node.cpu_cores or 1)
    node.ram_total = int(data.get("ram_total") or 0)
    node.ram_used = int(data.get("ram_used") or 0)
    node.disk_total = int(data.get("disk_total") or 0)
    node.disk_used = int(data.get("disk_used") or 0)
    node.uptime_sec = int(data.get("uptime") or 0)
    node.os_info = (data.get("os") or "")[:120]
    node.xray_version = (data.get("xray_version") or "")[:32]
    node.nginx_version = (data.get("nginx_version") or "")[:32]
    node.agent_version = (data.get("agent_version") or "")[:32]
    node.load_avg = " ".join(str(v) for v in (data.get("load_avg") or []))[:32]
    node.ping_ms = int(data.get("ping_ms") or elapsed_ms)
    node.last_seen = utcnow()
    cert = data.get("cert") or {}
    if cert.get("expires_at"):
        try:
            node.cert_expires_at = datetime.fromisoformat(cert["expires_at"]).replace(tzinfo=None)
        except ValueError:
            node.cert_expires_at = None
    node.cert_issuer = (cert.get("issuer") or None) and str(cert["issuer"])[:64]


async def push_state(session: AsyncSession, node_id: int, *, actor: str = "system", force: bool = False) -> dict:
    """Render + deploy the full node configuration (with preflight validation)."""
    node, inbounds = await load_node_bundle(session, node_id)
    checks = preflight(node, inbounds)
    if checks["errors"] and not force:
        return {"ok": False, "error": "؛ ".join(checks["errors"]), "preflight": checks}
    state = build_desired_state(node, inbounds)
    try:
        result = await agent_post(node, "/apply", state, timeout=180.0)
    except Exception as exc:
        node.status = NodeStatus.ERROR
        node.status_message = f"deploy failed: {exc}"[:180]
        session.add(ActivityLog(actor=actor, kind="deploy", level="error", message=f"استقرار روی {node.name} ناموفق بود: {exc}"[:400]))
        await session.commit()
        return {"ok": False, "error": str(exc)}

    level = "ok" if result.get("ok") else "error"
    message = "استقرار موفق" if result.get("ok") else f"استقرار ناموفق: {result}"
    session.add(ActivityLog(actor=actor, kind="deploy", level=level, message=f"{node.name}: {message}"[:400]))
    if not result.get("ok"):
        node.status = NodeStatus.ERROR
    await session.commit()
    return result


async def sync_shaping(session: AsyncSession, node_id: int) -> dict:
    node, inbounds = await load_node_bundle(session, node_id)
    plan = shaping_plan_for(node, inbounds)
    if not plan["limits"]:
        return {"ok": True, "message": "no speed limits configured"}
    try:
        stats = await agent_get(node, "/ips", timeout=20.0)
        return await agent_post(node, "/shaping", {"user_map": stats.get("ips", {}), **plan}, timeout=60.0)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def node_action(session: AsyncSession, node_id: int, action: str, actor: str = "system") -> dict:
    node = await session.get(Node, node_id)
    if node is None:
        return {"ok": False, "error": "node not found"}
    try:
        result = await agent_post(node, "/exec", {"action": action}, timeout=600.0)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    session.add(
        ActivityLog(
            actor=actor,
            kind="node-action",
            level="ok" if result.get("ok") else "error",
            message=f"{action} روی {node.name}: {'موفق' if result.get('ok') else 'ناموفق'}",
        )
    )
    await session.commit()
    return result


async def issue_certificate(session: AsyncSession, node_id: int, domain: str, email: str, actor: str = "system") -> dict:
    node = await session.get(Node, node_id)
    if node is None:
        return {"ok": False, "error": "node not found"}
    try:
        result = await agent_post(node, "/cert", {"domain": domain, "email": email}, timeout=600.0)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    session.add(
        ActivityLog(
            actor=actor,
            kind="certificate",
            level="ok" if result.get("ok") else "error",
            message=f"گواهی TLS برای {domain}: {'صادر شد' if result.get('ok') else 'ناموفق'}",
        )
    )
    await session.commit()
    return result


async def collect_stats(session: AsyncSession, node: Node) -> dict:
    """Pull per-user traffic + online lists from the agent."""
    if settings.metrics_mode == "mock":
        return {"ok": False, "mock": True, "users": {}, "inbounds": {}, "ips": {}}
    try:
        return await agent_get(node, "/stats", timeout=25.0)
    except Exception as exc:
        logger.debug("stats fetch failed for %s: %s", node.name, exc)
        return {"ok": False, "error": str(exc), "users": {}, "inbounds": {}, "ips": {}}
