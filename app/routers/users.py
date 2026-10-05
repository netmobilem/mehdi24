"""Users, quota management, links and QR codes."""

from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, or_, select
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
    ResetStrategy,
    Security,
    Transport,
    User,
    UserStatus,
    XhttpMode,
    human_bytes,
    new_uuid,
    parse_bytes,
    utcnow,
)
from ..services import links as link_service
from ..services.security import current_admin
from ..web import base_context, render

router = APIRouter(tags=["users"], prefix="/users")

PER_PAGE = 25


async def _active_inbounds(session: AsyncSession) -> list[Inbound]:
    result = await session.execute(
        select(Inbound).where(Inbound.is_active == True).options(selectinload(Inbound.node)).order_by(Inbound.id)  # noqa: E712
    )
    return list(result.scalars().all())


def _form_float(form, key: str, default: float = 0.0) -> float:
    try:
        return float(str(form.get(key) or "").strip() or default)
    except (TypeError, ValueError):
        return default


def _form_int(form, key: str, default: int = 0) -> int:
    try:
        return int(float(str(form.get(key) or "").strip() or default))
    except (TypeError, ValueError):
        return default


@router.get("")
@router.get("/")
async def users_list(
    request: Request,
    q: str = "",
    status: str = "",
    page: int = 1,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "users", request)

    query = select(User).options(selectinload(User.clients)).order_by(User.created_at.desc())
    if q:
        like = f"%{q.strip()}%"
        query = query.where(or_(User.username.like(like), User.display_name.like(like), User.email.like(like), User.note.like(like)))
    if status:
        try:
            query = query.where(User.status == UserStatus(status))
        except ValueError:
            pass

    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    page = max(1, page)
    rows = (
        await session.execute(query.offset((page - 1) * PER_PAGE).limit(PER_PAGE))
    ).scalars().all()

    context.update(
        {
            "users": rows,
            "total": total,
            "page": page,
            "pages": max(1, (total + PER_PAGE - 1) // PER_PAGE),
            "q": q,
            "status_filter": status,
            "inbounds": await _active_inbounds(session),
            "nodes": (await session.execute(select(Node).order_by(Node.sort_order))).scalars().all(),
            "protocols": [p.value for p in Protocol],
            "transports": [t.value for t in Transport],
            "securities": [s.value for s in Security],
            "xhttp_modes": [m.value for m in XhttpMode],
            "reset_strategies": [r.value for r in ResetStrategy],
            "now": utcnow(),
        }
    )
    return render(request, "users.html", **context)


@router.post("/create")
async def user_create(request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    form = await request.form()
    username = str(form.get("username") or "").strip()
    if not username:
        return {"ok": False, "message": "نام کاربری الزامی است"}

    exists = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if exists:
        return {"ok": False, "message": "این نام کاربری قبلاً ثبت شده است"}

    unit = str(form.get("limit_unit") or "GB").upper()
    volume = _form_float(form, "limit_value", 0)
    data_limit = parse_bytes(volume, unit) if volume > 0 else 0
    days = _form_int(form, "expire_days", 0)
    ip_limit = _form_int(form, "ip_limit", 0)
    speed = _form_int(form, "speed_limit", 0)

    user = User(
        username=username,
        display_name=str(form.get("display_name") or "").strip(),
        email=str(form.get("email") or f"{username}@titan").strip(),
        uuid=new_uuid(),
        password=secrets.token_urlsafe(12),
        note=str(form.get("note") or "").strip(),
        data_limit=data_limit,
        ip_limit=ip_limit,
        speed_limit=speed,
        status=UserStatus.ACTIVE,
        reset_strategy=ResetStrategy(str(form.get("reset_strategy") or "monthly")),
        created_by=admin.username,
        activated_at=utcnow() if days else None,
        expire_at=utcnow() + timedelta(days=days) if days else None,
    )
    session.add(user)
    await session.flush()

    # ── bind to inbounds ────────────────────────────────────────────────────
    selected = [int(value) for value in form.getlist("inbound_ids") if str(value).isdigit()]
    node_id = _form_int(form, "node_id", 0)
    flow = str(form.get("flow") or "")

    if not selected and node_id:
        auto = (
            await session.execute(
                select(Inbound).where(Inbound.node_id == node_id, Inbound.is_active == True).limit(1)  # noqa: E712
            )
        ).scalars().first()
        if auto:
            selected = [auto.id]

    if not selected:
        # "auto nearest": pick the first active inbound on the lowest-latency node
        best = (
            await session.execute(
                select(Inbound)
                .join(Node, Node.id == Inbound.node_id)
                .where(Inbound.is_active == True)  # noqa: E712
                .order_by(Node.ping_ms.asc(), Node.id.asc())
                .limit(1)
            )
        ).scalars().first()
        if best:
            selected = [best.id]

    for inbound_id in selected:
        session.add(
            Client(
                user_id=user.id,
                inbound_id=inbound_id,
                uuid=user.uuid,
                email_tag=f"{user.username}-{inbound_id}",
                flow=flow,
                is_active=True,
            )
        )

    touched_nodes = {
        inbound.node_id
        for inbound in (await session.execute(select(Inbound).where(Inbound.id.in_(selected or [0])))).scalars().all()
    }
    if touched_nodes:
        nodes = (await session.execute(select(Node).where(Node.id.in_(touched_nodes)))).scalars().all()
        for node in nodes:
            node.config_dirty = True
            session.add(node)

    session.add(ActivityLog(actor=admin.username, kind="create", level="ok", message=f"کاربر «{username}» ساخته شد"))
    await session.commit()
    return {"ok": True, "message": f"کاربر {username} ساخته شد و در صف استقرار قرار گرفت", "redirect": "/users"}


@router.post("/{user_id}/update")
async def user_update(
    user_id: int,
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    user = await session.get(User, user_id)
    if user is None:
        return {"ok": False, "message": "کاربر پیدا نشد"}
    form = await request.form()

    user.display_name = str(form.get("display_name") or "").strip()
    user.note = str(form.get("note") or "").strip()
    unit = str(form.get("limit_unit") or "GB").upper()
    volume = _form_float(form, "limit_value", 0)
    user.data_limit = parse_bytes(volume, unit) if volume > 0 else 0
    user.ip_limit = _form_int(form, "ip_limit", 0)
    user.speed_limit = _form_int(form, "speed_limit", 0)
    days = _form_int(form, "expire_days", 0)
    if days > 0:
        user.expire_at = utcnow() + timedelta(days=days)
    elif str(form.get("clear_expiry")) == "1":
        user.expire_at = None
    user.refresh_status()
    session.add(user)
    session.add(ActivityLog(actor=admin.username, kind="update", level="info", message=f"کاربر «{user.username}» ویرایش شد"))
    await session.commit()
    return {"ok": True, "message": "تغییرات ذخیره شد"}


@router.post("/{user_id}/toggle")
async def user_toggle(user_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    user = await session.get(User, user_id)
    if user is None:
        return {"ok": False, "message": "کاربر پیدا نشد"}
    user.status = UserStatus.DISABLED if user.status is not UserStatus.DISABLED else UserStatus.ACTIVE
    session.add(user)
    session.add(
        ActivityLog(
            actor=admin.username,
            kind="update",
            level="warn",
            message=f"کاربر «{user.username}» {'غیرفعال' if user.status is UserStatus.DISABLED else 'فعال'} شد",
        )
    )
    await _flag_user_nodes(session, user)
    await session.commit()
    return {"ok": True, "message": "وضعیت کاربر تغییر کرد"}


@router.post("/{user_id}/reset")
async def user_reset(user_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    user = await session.get(User, user_id)
    if user is None:
        return {"ok": False, "message": "کاربر پیدا نشد"}
    user.used_up = 0
    user.used_down = 0
    user.activated_at = utcnow()
    user.refresh_status()
    session.add(user)
    session.add(ActivityLog(actor=admin.username, kind="update", level="info", message=f"مصرف «{user.username}» صفر شد"))
    await session.commit()
    return {"ok": True, "message": "مصرف کاربر صفر شد و کانفیگ‌ها بروزرسانی می‌شوند"}


@router.post("/{user_id}/rotate")
async def user_rotate(user_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    """Regenerate UUID + subscription token (useful after a link leak)."""
    user = await session.get(User, user_id)
    if user is None:
        return {"ok": False, "message": "کاربر پیدا نشد"}
    user.uuid = new_uuid()
    user.sub_token = secrets.token_urlsafe(20)[:28]
    clients = (await session.execute(select(Client).where(Client.user_id == user.id))).scalars().all()
    for client in clients:
        client.uuid = user.uuid
        session.add(client)
    session.add(user)
    await _flag_user_nodes(session, user)
    session.add(ActivityLog(actor=admin.username, kind="update", level="warn", message=f"لینک‌های «{user.username}» بازتولید شد"))
    await session.commit()
    return {"ok": True, "message": "لینک‌ها و UUID بازتولید شد"}


@router.post("/{user_id}/delete")
async def user_delete(user_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    user = await session.get(User, user_id)
    if user is None:
        return {"ok": False, "message": "کاربر پیدا نشد"}
    username = user.username
    await _flag_user_nodes(session, user)
    await session.delete(user)
    session.add(ActivityLog(actor=admin.username, kind="delete", level="warn", message=f"کاربر «{username}» حذف شد"))
    await session.commit()
    return {"ok": True, "message": "کاربر حذف شد"}


async def _flag_user_nodes(session: AsyncSession, user: User) -> None:
    result = await session.execute(
        select(Inbound.node_id).join(Client, Client.inbound_id == Inbound.id).where(Client.user_id == user.id)
    )
    node_ids = {row[0] for row in result.all()}
    if not node_ids:
        return
    nodes = (await session.execute(select(Node).where(Node.id.in_(node_ids)))).scalars().all()
    for node in nodes:
        node.config_dirty = True
        session.add(node)


@router.get("/{user_id}/links")
async def user_links(
    user_id: int,
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "users", request)
    user = await session.get(User, user_id)
    if user is None:
        return RedirectResponse("/users?notice=کاربر پیدا نشد", status_code=303)

    rows = []
    result = await session.execute(
        select(Client, Inbound, Node)
        .join(Inbound, Client.inbound_id == Inbound.id)
        .join(Node, Inbound.node_id == Node.id)
        .where(Client.user_id == user.id)
    )
    for client, inbound, node in result.all():
        rows.append(
            {
                "client": client,
                "inbound": inbound,
                "node": node,
                "link": link_service.build_link(node, inbound, user),
                "client_json": link_service.build_client_json(node, inbound, user),
                "wireguard": link_service.build_wireguard_conf(node, inbound, user) if inbound.protocol is Protocol.WIREGUARD else "",
            }
        )

    context.update({"user": user, "rows": rows, "sub_url": f"/sub/{user.sub_token}"})
    return render(request, "user_links.html", **context)
