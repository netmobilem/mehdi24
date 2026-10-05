"""Subscription groups + public share pages (`/sub/…`, `/s/…`, QR)."""

from __future__ import annotations

import secrets
from datetime import timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models import (
    ActivityLog,
    Admin,
    Client,
    Inbound,
    Node,
    Setting,
    Subscription,
    SubscriptionItem,
    User,
    UserStatus,
    human_bytes,
    new_token,
    utcnow,
)
from ..services import links as link_service
from ..services.links import clash_subscription
from ..services.security import current_admin, hash_password, verify_password
from ..web import DEFAULT_LINKS, base_context, render

router = APIRouter(tags=["subscriptions"])
public_router = APIRouter(tags=["public"])

_COLORS = ["#7c70db", "#13a9cb", "#315c96", "#f6bf3d", "#268fdb", "#7d8eaf", "#8065ff", "#19d89a"]


def _qr_svg(data: str, size: int = 220) -> str:
    """Inline SVG QR (segno) — no external requests, works offline."""
    try:
        import segno

        qr = segno.make(data, error="m")
        return qr.svg_inline(scale=4, dark="#0b1220", light="#ffffff", border=0)
    except Exception:
        return f'<div class="muted small">QR در دسترس نیست: {data[:40]}</div>'


# ── panel: manage groups ─────────────────────────────────────────────────────
@router.get("/subscriptions")
async def subscriptions_list(
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "subscriptions", request)
    groups = list(
        (
            await session.execute(
                select(Subscription)
                .options(selectinload(Subscription.items).selectinload(SubscriptionItem.inbound).selectinload(Inbound.node),
                         selectinload(Subscription.items).selectinload(SubscriptionItem.user))
                .order_by(Subscription.id.desc())
            )
        ).scalars().all()
    )
    users = (await session.execute(select(User).order_by(User.username))).scalars().all()
    inbounds = list(
        (
            await session.execute(
                select(Inbound).where(Inbound.is_active == True).options(selectinload(Inbound.node)).order_by(Inbound.id)  # noqa: E712
            )
        ).scalars().all()
    )
    context.update({"groups": groups, "users": users, "inbounds": inbounds, "panel_domain": context["panel_domain"]})
    return render(request, "subscriptions.html", **context)


@router.post("/subscriptions/create")
async def subscription_create(
    request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    form = await request.form()
    name = str(form.get("name") or "").strip() or "گروه اشتراک"
    password = str(form.get("password") or "").strip()

    group = Subscription(
        name=name,
        token=new_token(24),
        password_hash=hash_password(password) if password else None,
        note=str(form.get("note") or "").strip(),
        is_active=True,
    )
    session.add(group)
    await session.flush()

    pairs: set[tuple[int, int]] = set()
    for value in form.getlist("user_ids"):
        if not str(value).isdigit():
            continue
        user_id = int(value)
        inbound_ids = [int(v) for v in form.getlist("inbound_ids") if str(v).isdigit()]
        if not inbound_ids:
            rows = (await session.execute(select(Client.inbound_id).where(Client.user_id == user_id))).all()
            inbound_ids = [row[0] for row in rows]
        for inbound_id in inbound_ids:
            pairs.add((inbound_id, user_id))

    if str(form.get("auto_all")) == "1":
        users = (await session.execute(select(User).where(User.status != UserStatus.DISABLED))).scalars().all()
        inbounds = (await session.execute(select(Inbound).where(Inbound.is_active == True))).scalars().all()  # noqa: E712
        for user in users:
            for inbound in inbounds:
                pairs.add((inbound.id, user.id))

    for inbound_id, user_id in pairs:
        session.add(SubscriptionItem(subscription_id=group.id, inbound_id=inbound_id, user_id=user_id))

    session.add(ActivityLog(actor=admin.username, kind="subscription", level="ok", message=f"گروه اشتراک «{name}» ساخته شد ({len(pairs)} آیتم)"))
    await session.commit()
    return {"ok": True, "message": f"گروه «{name}» با {len(pairs)} کانفیگ ساخته شد", "redirect": "/subscriptions"}


@router.post("/subscriptions/{group_id}/delete")
async def subscription_delete(
    group_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    group = await session.get(Subscription, group_id)
    if group is None:
        return {"ok": False, "message": "گروه پیدا نشد"}
    name = group.name
    await session.delete(group)
    session.add(ActivityLog(actor=admin.username, kind="subscription", level="warn", message=f"گروه «{name}» حذف شد"))
    await session.commit()
    return {"ok": True, "message": "گروه حذف شد"}


@router.post("/subscriptions/{group_id}/toggle")
async def subscription_toggle(
    group_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    group = await session.get(Subscription, group_id)
    if group is None:
        return {"ok": False, "message": "گروه پیدا نشد"}
    group.is_active = not group.is_active
    session.add(group)
    await session.commit()
    return {"ok": True, "message": "وضعیت گروه تغییر کرد"}


@router.post("/subscriptions/{group_id}/rotate")
async def subscription_rotate(
    group_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)
):
    group = await session.get(Subscription, group_id)
    if group is None:
        return {"ok": False, "message": "گروه پیدا نشد"}
    group.token = new_token(24)
    session.add(group)
    await session.commit()
    return {"ok": True, "message": "لینک اشتراک بازتولید شد"}


# ── public endpoints ─────────────────────────────────────────────────────────
async def _group_payload(session: AsyncSession, token: str) -> tuple[Subscription | None, list[dict]]:
    group = (
        await session.execute(
            select(Subscription)
            .where(Subscription.token == token)
            .options(
                selectinload(Subscription.items).selectinload(SubscriptionItem.inbound).selectinload(Inbound.node),
                selectinload(Subscription.items).selectinload(SubscriptionItem.user),
            )
        )
    ).scalars().first()
    if group is None or not group.is_active:
        return None, []

    rows: list[dict] = []
    index = 0
    for item in group.items:
        user, inbound = item.user, item.inbound
        if user is None or inbound is None or not inbound.is_active or not inbound.node:
            continue
        if user.status in (UserStatus.DISABLED, UserStatus.EXPIRED, UserStatus.LIMITED):
            continue
        rows.append(
            {
                "user": user,
                "inbound": inbound,
                "node": inbound.node,
                "link": link_service.build_link(inbound.node, inbound, user),
                "color": _COLORS[index % len(_COLORS)],
            }
        )
        index += 1
    return group, rows


@public_router.get("/sub/{token}")
async def raw_subscription(token: str, request: Request, session: AsyncSession = Depends(get_db)):
    """Base64 subscription body that client apps consume."""
    group, rows = await _group_payload(session, token)
    if group is None:
        return PlainTextResponse("not found", status_code=404)

    if group.password_hash:
        supplied = request.query_params.get("pw") or ""
        if not supplied or not verify_password(group.password_hash, supplied):
            return PlainTextResponse("unauthorized", status_code=401)

    group.hits += 1
    group.last_hit_at = utcnow()
    session.add(group)
    await session.commit()

    links = [row["link"] for row in rows if row["link"]]
    body = link_service.base64_subscription(links, title=group.name)

    primary = rows[0]["user"] if rows else None
    headers = {
        "profile-title": quote(f"TiTaN · {group.name}"),
        "profile-update-interval": "12",
        "support-url": "https://t.me/Code_Watch",
    }
    if primary:
        total = primary.data_limit or 0
        headers["subscription-userinfo"] = (
            f"upload={primary.used_up}; download={primary.used_down}; total={total}; "
            f"expire={int(primary.expire_at.timestamp()) if primary.expire_at else 0}"
        )
    return PlainTextResponse(body, media_type="text/plain; charset=utf-8", headers=headers)


@public_router.get("/s/{token}", response_class=HTMLResponse)
async def public_subscription_page(
    token: str, request: Request, pw: str = "", session: AsyncSession = Depends(get_db)
):
    """Human-friendly landing page with per-config QR codes and usage."""
    group, rows = await _group_payload(session, token)
    if group is None:
        return HTMLResponse(
            '<!doctype html><html lang="fa" dir="rtl"><body style="background:#050a12;color:#f3f6fb;'
            'font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0">'
            "<div style='text-align:center'><h2>اشتراک پیدا نشد</h2><p style='color:#7f8da4'>"
            "لینک نامعتبر است یا غیرفعال شده.</p></div></body></html>",
            status_code=404,
        )

    if group.password_hash and not verify_password(group.password_hash, pw):
        return render(
            request,
            "sub_password.html",
            group=group,
            token=token,
            error="رمز نادرست است" if pw else None,
        )

    group.hits += 1
    group.last_hit_at = utcnow()
    session.add(group)
    await session.commit()

    total_up = sum(row["user"].used_up for row in rows)
    total_down = sum(row["user"].used_down for row in rows)
    unique_users = {row["user"].id for row in rows}
    announce = (await session.get(Setting, "sub_announcement")).value if await session.get(Setting, "sub_announcement") else ""

    cards = []
    for row in rows:
        cards.append(
            {
                **row,
                "qr": _qr_svg(row["link"]) if row["link"] else "",
            }
        )

    return render(
        request,
        "sub_page.html",
        group=group,
        token=token,
        cards=cards,
        sub_url=f"/sub/{group.token}" + (f"?pw={pw}" if pw else ""),
        totals={"up": total_up, "down": total_down, "usage": total_up + total_down, "users": len(unique_users)},
        announcement=announce,
        links=DEFAULT_LINKS,
    )


@public_router.get("/qr.svg")
async def inline_qr(data: str = ""):
    """Inline SVG QR for any payload (links, subscription URLs)."""
    if not data:
        return Response(content="<!-- empty -->", media_type="image/svg+xml")
    return Response(content=_qr_svg(data), media_type="image/svg+xml")


@public_router.get("/qr/{token}.svg")
async def subscription_qr(token: str, session: AsyncSession = Depends(get_db)):
    """QR of the raw subscription URL (used inside the public page)."""
    url = f"/sub/{token}"
    svg = _qr_svg(url, size=260)
    return Response(content=svg, media_type="image/svg+xml")


@public_router.get("/sub/{token}/json")
async def subscription_json(token: str, request: Request, session: AsyncSession = Depends(get_db)):
    group, rows = await _group_payload(session, token)
    if group is None:
        return JSONResponse({"ok": False, "message": "not found"}, status_code=404)
    return JSONResponse(
        {
            "ok": True,
            "name": group.name,
            "count": len(rows),
            "links": [row["link"] for row in rows],
            "items": [
                {
                    "user": row["user"].username,
                    "node": row["node"].name,
                    "protocol": row["inbound"].protocol.value,
                    "transport": row["inbound"].transport.value,
                }
                for row in rows
            ],
        }
    )


@public_router.get("/sub/{token}/clash.yaml")
async def subscription_clash(token: str, session: AsyncSession = Depends(get_db)):
    group, rows = await _group_payload(session, token)
    if group is None:
        return PlainTextResponse("not found", status_code=404)
    body = link_service.clash_subscription([(row["node"], row["inbound"], row["user"]) for row in rows])
    return PlainTextResponse(
        body,
        media_type="text/yaml; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="titan-{group.token}.yaml"'},
    )
