"""Inbound (config) management: protocol services bound to nodes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models import (
    ActivityLog,
    Admin,
    Client,
    Inbound,
    Node,
    Protocol,
    Security,
    Transport,
    XhttpMode,
    human_bytes,
    utcnow,
)
from ..services import provisioner
from ..services import xray_config as xc
from ..services.reality import generate_reality_keypair, generate_short_id, generate_ss_password, random_service_name
from ..services.security import current_admin
from ..settings import settings
from ..web import base_context, render

router = APIRouter(tags=["inbounds"], prefix="/inbounds")

DEFAULT_PATHS = {
    Transport.WS: "/titan/ws",
    Transport.XHTTP: "/titan/xhttp",
    Transport.HTTPUPGRADE: "/titan/hu",
    Transport.GRPC: "/titan-grpc",
}

DEFAULT_ALPN = {
    Transport.WS: "http/1.1",
    Transport.XHTTP: "h2,http/1.1",
    Transport.GRPC: "h2",
    Transport.TCP: "http/1.1",
    Transport.HTTPUPGRADE: "http/1.1",
}


def _form_int(form, key: str, default: int = 0) -> int:
    try:
        return int(float(str(form.get(key) or "").strip() or default))
    except (TypeError, ValueError):
        return default


DIRECT_PORT_POOL = [8443, 2053, 2083, 2087, 2096, 2095, 8444, 8445, 8880, 9443]


async def _next_public_port(session: AsyncSession, node: Node, requested: int) -> int:
    """Direct (raw-TCP / UDP) inbounds own a public port — never the nginx one."""
    taken = {
        row[0]
        for row in (
            await session.execute(
                select(Inbound.port).where(Inbound.node_id == node.id, Inbound.transport.in_([Transport.TCP, Transport.QUIC]))
            )
        ).all()
    }
    taken.add(node.port)  # nginx owns this one
    if requested and requested not in taken and requested != node.port:
        return requested
    for candidate in DIRECT_PORT_POOL:
        if candidate not in taken:
            return candidate
    return max(taken) + 1


async def _next_internal_port(session: AsyncSession, node_id: int) -> int:
    current = (
        await session.execute(select(func.max(Inbound.internal_port)).where(Inbound.node_id == node_id))
    ).scalar_one()
    base = max(current or 0, settings.first_internal_port - 1)
    return base + 1


@router.get("")
@router.get("/")
async def inbounds_list(
    request: Request,
    node_id: int = 0,
    protocol: str = "",
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "inbounds", request)

    query = select(Inbound).options(selectinload(Inbound.node), selectinload(Inbound.clients)).order_by(Inbound.id.desc())
    if node_id:
        query = query.where(Inbound.node_id == node_id)
    if protocol:
        try:
            query = query.where(Inbound.protocol == Protocol(protocol))
        except ValueError:
            pass
    inbounds = list((await session.execute(query)).scalars().all())

    for inbound in inbounds:
        inbound.clients_count = len([c for c in inbound.clients if c.is_active])

    usage = dict(
        (
            await session.execute(
                select(Client.inbound_id, func.count(Client.id)).group_by(Client.inbound_id)
            )
        ).all()
    )

    context.update(
        {
            "inbounds": inbounds,
            "nodes": (await session.execute(select(Node).order_by(Node.sort_order))).scalars().all(),
            "node_filter": node_id,
            "protocol_filter": protocol,
            "usage": usage,
            "protocols": [p.value for p in Protocol],
            "transports": [t.value for t in Transport],
            "securities": [s.value for s in Security],
            "xhttp_modes": [m.value for m in XhttpMode],
            "fingerprints": ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"],
        }
    )
    return render(request, "inbounds.html", **context)


@router.post("/create")
async def inbound_create(request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    form = await request.form()
    node_id = _form_int(form, "node_id", 0)
    node = await session.get(Node, node_id)
    if node is None:
        return {"ok": False, "message": "ابتدا یک سرور انتخاب کنید"}

    try:
        protocol = Protocol(str(form.get("protocol") or "vless"))
        transport = Transport(str(form.get("transport") or "ws"))
        security = Security(str(form.get("security") or "tls"))
    except ValueError as exc:
        return {"ok": False, "message": f"پارامتر نامعتبر: {exc}"}

    if protocol is Protocol.HYSTERIA2 or protocol is Protocol.WIREGUARD:
        security = Security.NONE
        transport = Transport.QUIC if protocol is Protocol.HYSTERIA2 else Transport.TCP

    if security is Security.REALITY and protocol not in (Protocol.VLESS, Protocol.VMESS):
        return {"ok": False, "message": "REALITY فقط برای VLESS و VMess پشتیبانی می‌شود"}

    name = str(form.get("name") or "").strip() or f"{protocol.value.upper()}-{transport.value.upper()}"
    port = _form_int(form, "port", node.port or 443)
    if transport in (Transport.TCP, Transport.QUIC):
        port = await _next_public_port(session, node, port)
    internal_port = _form_int(form, "internal_port", 0) or await _next_internal_port(session, node.id)
    path = str(form.get("path") or "").strip() or DEFAULT_PATHS.get(transport, "/titan")
    alpn = str(form.get("alpn") or "").strip() or DEFAULT_ALPN.get(transport, "http/1.1")

    private_key = public_key = short_id = ""
    if security is Security.REALITY:
        private_key, public_key = generate_reality_keypair()
        short_id = generate_short_id()

    cipher = str(form.get("cipher") or "2022-blake3-aes-128-gcm")
    password = str(form.get("password") or "").strip()
    if protocol is Protocol.SHADOWSOCKS and not password:
        password = generate_ss_password(cipher)

    inbound = Inbound(
        node_id=node.id,
        name=name,
        note=str(form.get("note") or "").strip(),
        protocol=protocol,
        transport=transport,
        security=security,
        port=port,
        internal_port=internal_port,
        path=path,
        host_header=str(form.get("host") or "").strip() or node.address,
        sni=str(form.get("sni") or "").strip() or node.address,
        alpn=alpn,
        fingerprint=str(form.get("fingerprint") or "chrome"),
        service_name=random_service_name() if transport is Transport.GRPC else str(form.get("service_name") or "titan-grpc"),
        xhttp_mode=XhttpMode(str(form.get("xhttp_mode") or "auto")),
        flow=str(form.get("flow") or ("xtls-rprx-vision" if security is Security.REALITY else "")),
        reality_dest=str(form.get("reality_dest") or "www.cloudflare.com:443"),
        reality_server_names=str(form.get("reality_server_names") or "www.cloudflare.com"),
        reality_private_key=private_key,
        reality_public_key=public_key,
        reality_short_id=short_id,
        cipher=cipher,
        password=password,
        tag=str(form.get("tag") or ""),
        is_active=True,
    )
    session.add(inbound)

    # attach every active user that opted into "all configs" on this node
    if str(form.get("attach_all_users")) == "1":
        from ..models import User, UserStatus

        users = (
            await session.execute(select(User).where(User.status != UserStatus.DISABLED))
        ).scalars().all()
        await session.flush()
        for user in users:
            session.add(
                Client(
                    user_id=user.id,
                    inbound_id=inbound.id,
                    uuid=user.uuid,
                    email_tag=f"{user.username}-{inbound.id}",
                    is_active=True,
                )
            )

    node.config_dirty = True
    session.add(node)
    session.add(
        ActivityLog(
            actor=admin.username,
            kind="config",
            level="ok",
            message=f"کانفیگ «{name}» روی {node.name} ساخته شد ({protocol.value}/{transport.value})",
        )
    )
    await session.commit()
    return {"ok": True, "message": f"کانفیگ {name} ساخته شد — در صف استقرار روی {node.name}"}


@router.post("/{inbound_id}/update")
async def inbound_update(
    inbound_id: int, request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None:
        return {"ok": False, "message": "کانفیگ پیدا نشد"}
    form = await request.form()

    inbound.name = str(form.get("name") or inbound.name).strip()
    inbound.note = str(form.get("note") or "").strip()
    inbound.port = _form_int(form, "port", inbound.port)
    inbound.path = str(form.get("path") or inbound.path).strip()
    inbound.sni = str(form.get("sni") or inbound.sni).strip()
    inbound.host_header = str(form.get("host") or inbound.host_header).strip()
    inbound.alpn = str(form.get("alpn") or inbound.alpn).strip()
    inbound.fingerprint = str(form.get("fingerprint") or inbound.fingerprint).strip()
    inbound.allow_insecure = str(form.get("allow_insecure")) == "1"
    if form.get("xhttp_mode"):
        try:
            inbound.xhttp_mode = XhttpMode(str(form.get("xhttp_mode")))
        except ValueError:
            pass

    node = await session.get(Node, inbound.node_id)
    if node:
        node.config_dirty = True
        session.add(node)
    session.add(inbound)
    session.add(ActivityLog(actor=admin.username, kind="config", level="info", message=f"کانفیگ «{inbound.name}» ویرایش شد"))
    await session.commit()
    return {"ok": True, "message": "کانفیگ بروزرسانی شد"}


@router.post("/{inbound_id}/toggle")
async def inbound_toggle(
    inbound_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None:
        return {"ok": False, "message": "کانفیگ پیدا نشد"}
    inbound.is_active = not inbound.is_active
    node = await session.get(Node, inbound.node_id)
    if node:
        node.config_dirty = True
        session.add(node)
    session.add(inbound)
    session.add(
        ActivityLog(
            actor=admin.username,
            kind="config",
            level="warn",
            message=f"کانفیگ «{inbound.name}» {'فعال' if inbound.is_active else 'غیرفعال'} شد",
        )
    )
    await session.commit()
    return {"ok": True, "message": "وضعیت کانفیگ تغییر کرد"}


@router.post("/{inbound_id}/delete")
async def inbound_delete(
    inbound_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None:
        return {"ok": False, "message": "کانفیگ پیدا نشد"}
    name = inbound.name
    node_id = inbound.node_id
    await session.delete(inbound)
    node = await session.get(Node, node_id)
    if node:
        node.config_dirty = True
        session.add(node)
    session.add(ActivityLog(actor=admin.username, kind="config", level="warn", message=f"کانفیگ «{name}» حذف شد"))
    await session.commit()
    return {"ok": True, "message": "کانفیگ حذف شد"}


@router.post("/{inbound_id}/deploy")
async def inbound_deploy(
    inbound_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None:
        return {"ok": False, "message": "کانفیگ پیدا نشد"}
    result = await provisioner.push_state(session, inbound.node_id, actor=admin.username)
    if result.get("ok"):
        node = await session.get(Node, inbound.node_id)
        if node:
            node.config_dirty = False
            session.add(node)
            await session.commit()
        return {"ok": True, "message": "استقرار با موفقیت انجام شد"}
    return {"ok": False, "message": f"استقرار ناموفق بود: {result.get('error') or result}"}


@router.get("/{inbound_id}/preview")
async def inbound_preview(
    inbound_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    """Show the exact Xray inbound object that will be pushed to the node."""
    node, inbounds = await provisioner.load_node_bundle(session, (await session.get(Inbound, inbound_id)).node_id)
    target = next((i for i in inbounds if i.id == inbound_id), None)
    if target is None:
        return JSONResponse({"ok": False, "message": "کانفیگ پیدا نشد"}, status_code=404)
    clients = list(target.clients)
    payload = xc.build_inbound(target, node, clients)
    return JSONResponse({"ok": True, "inbound": payload, "clients": len(clients)})


@router.get("/{inbound_id}/links")
async def inbound_links(
    inbound_id: int,
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    """Every client link served by this inbound (top 100)."""
    from ..services import links as link_service

    context = await base_context(session, admin, "inbounds", request)
    inbound = (
        await session.execute(
            select(Inbound).where(Inbound.id == inbound_id).options(selectinload(Inbound.node), selectinload(Inbound.clients).selectinload(Client.user))
        )
    ).scalars().first()
    if inbound is None:
        return render(request, "inbound_links.html", **context, inbound=None, rows=[])

    rows = [
        {"client": client, "user": client.user, "link": link_service.build_link(inbound.node, inbound, client.user)}
        for client in inbound.clients[:100]
    ]
    context.update({"inbound": inbound, "rows": rows, "human_bytes": human_bytes})
    return render(request, "inbound_links.html", **context)
