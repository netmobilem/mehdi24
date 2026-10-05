"""Server (node) management: bootstrap, deploy, health, certificates."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models import ActivityLog, Admin, Inbound, Node, NodeStatus, NodeTask, User, utcnow
from ..services import bootstrap as bootstrap_service
from ..services import provisioner
from ..services import xray_config as xc
from ..services import geo
from ..services.geo import country_name, default_city, flag_for
from ..services.reality import generate_reality_keypair
from ..services.security import current_admin
from ..settings import settings
from ..web import base_context, render

router = APIRouter(tags=["nodes"], prefix="/nodes")


def _form_int(form, key: str, default: int = 0) -> int:
    try:
        return int(float(str(form.get(key) or "").strip() or default))
    except (TypeError, ValueError):
        return default


@router.get("")
@router.get("/")
async def nodes_list(
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "nodes", request)
    nodes = list(
        (
            await session.execute(
                select(Node).options(selectinload(Node.inbounds)).order_by(Node.sort_order, Node.id)
            )
        ).scalars().all()
    )
    online = [node for node in nodes if node.status is NodeStatus.ONLINE]
    avg_cpu = round(sum(node.cpu_pct for node in online) / len(online), 1) if online else 0.0
    avg_ping = round(sum(node.ping_ms for node in online) / len(online)) if online else 0
    total_traffic = sum(node.traffic_up + node.traffic_down for node in nodes)

    for node in nodes:
        node.inbounds_count = len([i for i in node.inbounds if i.is_active])
        node.status_label = {
            NodeStatus.ONLINE: "آنلاین",
            NodeStatus.OFFLINE: "آفلاین",
            NodeStatus.DEGRADED: "ناپایدار",
            NodeStatus.CONNECTING: "در حال اتصال",
            NodeStatus.INSTALLING: "در حال نصب",
            NodeStatus.ERROR: "خطا",
        }.get(node.status, node.status.value)

    context.update(
        {
            "nodes": nodes,
            "online": online,
            "total": len(nodes),
            "avg_cpu": avg_cpu,
            "avg_ping": avg_ping,
            "total_traffic": total_traffic,
            "countries": geo.COUNTRIES,
            "cities": geo.CITY_PRESETS,
            "now": utcnow(),
        }
    )
    return render(request, "nodes.html", **context)


@router.post("/create")
async def node_create(request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    form = await request.form()
    name = str(form.get("name") or "").strip()
    address = str(form.get("address") or "").strip().lower()
    address = address.replace("https://", "").replace("http://", "").split("/")[0]
    if not name or not address:
        return {"ok": False, "message": "نام و آدرس سرور الزامی است"}

    exists = (await session.execute(select(Node).where(Node.address == address))).scalar_one_or_none()
    if exists:
        return {"ok": False, "message": "این آدرس قبلاً ثبت شده است"}

    code = str(form.get("country_code") or "").strip().upper()[:2]
    node = Node(
        name=name,
        address=address,
        ip=str(form.get("ip") or "").strip() or None,
        port=_form_int(form, "port", 443),
        country_code=code,
        country_name=country_name(code) if code else "",
        city=str(form.get("city") or "").strip() or default_city(code),
        flag=flag_for(code),
        agent_port=_form_int(form, "agent_port", settings.agent_port),
        agent_scheme=str(form.get("agent_scheme") or settings.agent_scheme),
        ssh_host=str(form.get("ssh_host") or address).strip(),
        ssh_port=_form_int(form, "ssh_port", 22),
        ssh_user=str(form.get("ssh_user") or "root").strip(),
        ssh_password=str(form.get("ssh_password") or "") or None,
        ssh_key_path=str(form.get("ssh_key_path") or "") or None,
        sort_order=_form_int(form, "sort_order", 0),
        status=NodeStatus.CONNECTING,
        reality_enabled=str(form.get("reality_enabled", "1")) == "1",
        hysteria2_enabled=str(form.get("hysteria2_enabled")) == "1",
        wireguard_enabled=str(form.get("wireguard_enabled")) == "1",
    )
    session.add(node)
    session.add(ActivityLog(actor=admin.username, kind="node", level="ok", message=f"سرور «{name}» اضافه شد ({address})"))
    await session.commit()
    return {
        "ok": True,
        "message": f"سرور {name} اضافه شد — اکنون «نصب خودکار» را بزنید",
        "redirect": "/nodes",
    }


@router.post("/{node_id}/update")
async def node_update(
    node_id: int, request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    node = await session.get(Node, node_id)
    if node is None:
        return {"ok": False, "message": "سرور پیدا نشد"}
    form = await request.form()

    node.name = str(form.get("name") or node.name).strip()
    node.address = str(form.get("address") or node.address).strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    node.ip = str(form.get("ip") or node.ip or "").strip() or None
    node.port = _form_int(form, "port", node.port)
    node.agent_port = _form_int(form, "agent_port", node.agent_port)
    node.agent_scheme = str(form.get("agent_scheme") or node.agent_scheme)
    node.ssh_host = str(form.get("ssh_host") or node.ssh_host or node.address).strip()
    node.ssh_port = _form_int(form, "ssh_port", node.ssh_port)
    node.ssh_user = str(form.get("ssh_user") or node.ssh_user).strip()
    if form.get("ssh_password"):
        node.ssh_password = str(form.get("ssh_password"))
    node.reality_enabled = str(form.get("reality_enabled", "1")) == "1"
    node.hysteria2_enabled = str(form.get("hysteria2_enabled")) == "1"
    node.wireguard_enabled = str(form.get("wireguard_enabled")) == "1"
    code = str(form.get("country_code") or node.country_code).strip().upper()[:2]
    if code:
        node.country_code = code
        node.country_name = country_name(code)
        node.flag = flag_for(code)
    node.city = str(form.get("city") or node.city).strip()
    node.config_dirty = True
    session.add(node)
    session.add(ActivityLog(actor=admin.username, kind="node", level="info", message=f"سرور «{node.name}» ویرایش شد"))
    await session.commit()
    return {"ok": True, "message": "اطلاعات سرور ذخیره شد"}


@router.post("/{node_id}/delete")
async def node_delete(node_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    node = await session.get(Node, node_id)
    if node is None:
        return {"ok": False, "message": "سرور پیدا نشد"}
    name = node.name
    await session.delete(node)
    session.add(ActivityLog(actor=admin.username, kind="node", level="warn", message=f"سرور «{name}» حذف شد"))
    await session.commit()
    return {"ok": True, "message": "سرور حذف شد", "redirect": "/nodes"}


@router.post("/{node_id}/bootstrap")
async def node_bootstrap(node_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    """Install Xray + Nginx + agent over SSH."""
    node = await session.get(Node, node_id)
    if node is None:
        return {"ok": False, "message": "سرور پیدا نشد"}

    node.status = NodeStatus.INSTALLING
    node.status_message = "در حال نصب خودکار…"
    session.add(node)
    await session.commit()

    result = await bootstrap_service.bootstrap_node(node)

    node.status = NodeStatus.CONNECTING if result.get("ok") else NodeStatus.ERROR
    node.status_message = (result.get("message") or "")[:180]
    session.add(node)
    session.add(
        NodeTask(
            node_id=node.id,
            action="bootstrap",
            payload={"ssh_host": node.ssh_host},
            status="done" if result.get("ok") else "failed",
            result=(result.get("message") or "")[:2000],
            finished_at=utcnow(),
        )
    )
    session.add(
        ActivityLog(
            actor=admin.username,
            kind="node",
            level="ok" if result.get("ok") else "error",
            message=f"نصب خودکار روی {node.name}: {'موفق' if result.get('ok') else 'ناموفق'}",
        )
    )
    await session.commit()

    if result.get("ok"):
        probe = await provisioner.probe_node(node, session=session)
        if probe.get("ok"):
            deploy = await provisioner.push_state(session, node.id, actor=admin.username)
            return {"ok": True, "message": "نصب و استقرار با موفقیت انجام شد" if deploy.get("ok") else "نصب انجام شد اما استقرار ناموفق بود", "redirect": "/nodes"}
        return {"ok": True, "message": "نصب انجام شد ولی ایجنت پاسخ نداد — فایروال پورت ایجنت را بررسی کنید", "redirect": "/nodes"}

    return {
        "ok": False,
        "message": result.get("message") or "نصب ناموفق بود",
        "log": (result.get("log") or [])[-20:],
    }


@router.post("/{node_id}/deploy")
async def node_deploy(node_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    result = await provisioner.push_state(session, node_id, actor=admin.username)
    if result.get("ok"):
        node = await session.get(Node, node_id)
        if node:
            node.config_dirty = False
            node.status = NodeStatus.ONLINE
            session.add(node)
            await session.commit()
        return {"ok": True, "message": "استقرار انجام شد (Xray + Nginx ری‌استارت شدند)"}
    return {"ok": False, "message": f"استقرار ناموفق: {result.get('error') or result.get('results')}"}


@router.post("/{node_id}/action")
async def node_action(
    node_id: int, request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    form = await request.form()
    action = str(form.get("action") or request.query_params.get("action") or "")
    allowed = {"restart-xray", "restart-nginx", "reload-nginx", "upgrade-xray", "upgrade-nginx", "geo-update", "reboot"}
    if action not in allowed:
        return {"ok": False, "message": "عملیات مجاز نیست"}
    result = await provisioner.node_action(session, node_id, action, actor=admin.username)
    return {"ok": bool(result.get("ok")), "message": ("عملیات انجام شد" if result.get("ok") else f"ناموفق: {result.get('error') or result.get('stderr')}")}


@router.post("/{node_id}/cert")
async def node_cert(
    node_id: int, request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    form = await request.form()
    domain = str(form.get("domain") or "").strip() or (await session.get(Node, node_id)).address
    email = str(form.get("email") or f"admin@{domain}").strip()
    result = await provisioner.issue_certificate(session, node_id, domain, email, actor=admin.username)
    if result.get("ok"):
        return {"ok": True, "message": f"گواهی TLS برای {domain} صادر شد"}
    return {"ok": False, "message": f"صدور گواهی ناموفق: {result.get('message') or result.get('error')}"}


@router.post("/{node_id}/ssh-check")
async def node_ssh_check(node_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    node = await session.get(Node, node_id)
    if node is None:
        return {"ok": False, "message": "سرور پیدا نشد"}
    result = await __import__("asyncio").get_event_loop().run_in_executor(None, lambda: bootstrap_service.check_ssh(node))
    return {"ok": bool(result.get("ok")), "message": (result.get("message") or "")[:300]}


@router.get("/{node_id}/script")
async def node_script(node_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    """Download the manual bootstrap script (for hosts without SSH access)."""
    node = await session.get(Node, node_id)
    if node is None:
        return PlainTextResponse("node not found", status_code=404)
    script = bootstrap_service.generate_bootstrap_script(node)
    return PlainTextResponse(
        script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": f'attachment; filename="titan-bootstrap-{node.id}.sh"'},
    )


@router.post("/{node_id}/regenerate-reality")
async def regenerate_reality(node_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    """Roll new REALITY keys for every reality inbound on this node."""
    inbounds = (
        await session.execute(select(Inbound).where(Inbound.node_id == node_id))
    ).scalars().all()
    count = 0
    for inbound in inbounds:
        if inbound.reality_private_key:
            private, public = generate_reality_keypair()
            inbound.reality_private_key = private
            inbound.reality_public_key = public
            session.add(inbound)
            count += 1
    node = await session.get(Node, node_id)
    if node:
        node.config_dirty = True
        session.add(node)
    await session.commit()
    return {"ok": True, "message": f"کلیدهای REALITY برای {count} کانفیگ بازتولید شد"}


@router.get("/{node_id}")
async def node_detail(
    node_id: int,
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "nodes", request)
    node = (
        await session.execute(select(Node).where(Node.id == node_id).options(selectinload(Node.inbounds)))
    ).scalars().first()
    if node is None:
        return RedirectResponse("/nodes?notice=سرور پیدا نشد", status_code=303)

    users_count = (
        await session.execute(
            select(func.count(func.distinct(Inbound.id))).where(Inbound.node_id == node_id, Inbound.is_active == True)  # noqa: E712
        )
    ).scalar_one()

    config_preview = None
    try:
        _, inbounds = await provisioner.load_node_bundle(session, node_id)
        config_preview = xc.dumps(xc.build_xray_config(node, inbounds, {i.id: list(i.clients) for i in inbounds})).replace(
            '"id": "[^"]+"', '"id": "…"'
        )
    except Exception:
        config_preview = None

    tasks = (
        await session.execute(select(NodeTask).where(NodeTask.node_id == node_id).order_by(NodeTask.id.desc()).limit(10))
    ).scalars().all()

    context.update(
        {
            "node": node,
            "inbounds": node.inbounds,
            "inbounds_active": users_count,
            "config_preview": config_preview,
            "tasks": tasks,
            "logs": None,
        }
    )
    return render(request, "node_detail.html", **context)


@router.get("/{node_id}/logs")
async def node_logs(node_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    node = await session.get(Node, node_id)
    if node is None:
        return JSONResponse({"ok": False, "message": "node not found"}, status_code=404)
    try:
        data = await provisioner.agent_get(node, "/logs?tail=200", timeout=25.0)
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=502)
    return JSONResponse(data)
