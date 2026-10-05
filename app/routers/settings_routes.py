"""Panel settings + admin (staff) management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import ActivityLog, Admin, AdminRole, Notification, Setting, utcnow
from ..services import provisioner, xray_config as xc
from ..services.security import current_admin, hash_password
from ..settings import settings
from ..web import base_context, render

router = APIRouter(tags=["settings"])

DEFAULT_SETTINGS: dict[str, str] = {
    "sub_title": "TiTaN",
    "sub_announcement": "",
    "decoy_url": "",
    "default_flow": "xtls-rprx-vision",
    "auto_deploy": "1",
    "ip_limit_strict": "0",
    "agent_port": str(settings.agent_port),
    "first_internal_port": str(settings.first_internal_port),
}


async def load_settings(session: AsyncSession) -> dict[str, str]:
    rows = (await session.execute(select(Setting))).scalars().all()
    values = dict(DEFAULT_SETTINGS)
    values.update({row.key: row.value for row in rows})
    return values


async def save_setting(session: AsyncSession, key: str, value: str) -> None:
    row = await session.get(Setting, key)
    if row is None:
        session.add(Setting(key=key, value=value))
    else:
        row.value = value
        session.add(row)


@router.get("/settings")
async def settings_page(
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "settings", request)
    values = await load_settings(session)
    context.update(
        {
            "panel_settings": values,
            "env": {
                "panel_domain": settings.panel_domain or context["panel_domain"],
                "data_dir": str(settings.data_path),
                "metrics_mode": settings.metrics_mode,
                "agent_port": settings.agent_port,
                "api_port": settings.xray_api_port,
                "telegram_configured": bool(settings.telegram_bot_token),
                "allowed_ips": settings.allowed_ips,
            },
        }
    )
    return render(request, "settings.html", **context)


@router.post("/settings/save")
async def settings_save(request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    form = await request.form()
    for key in DEFAULT_SETTINGS:
        if key in form:
            await save_setting(session, key, str(form.get(key) or ""))
    session.add(ActivityLog(actor=admin.username, kind="settings", level="info", message="تنظیمات پنل بروزرسانی شد"))
    await session.commit()
    return {"ok": True, "message": "تنظیمات ذخیره شد"}


@router.post("/settings/notify-check")
async def notify_check(session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    """Create a test notification (verifies the notification pipeline)."""
    session.add(Notification(title="اعلان آزمایشی", body="اگر این پیام را می‌بینید، سیستم اعلان‌ها سالم است.", level="info"))
    await session.commit()
    return {"ok": True, "message": "اعلان آزمایشی ساخته شد"}


@router.post("/settings/mark-read")
async def mark_read(session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    rows = (await session.execute(select(Notification).where(Notification.is_read == False))).scalars().all()  # noqa: E712
    for row in rows:
        row.is_read = True
        session.add(row)
    await session.commit()
    return {"ok": True, "message": "همه اعلان‌ها خوانده شد"}


@router.get("/api/config-preview")
async def config_preview(session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    """The exact Xray config the panel would push — useful for audits."""
    from ..models import Node

    nodes = (await session.execute(select(Node))).scalars().all()
    previews = {}
    for node in nodes:
        try:
            _, inbounds = await provisioner.load_node_bundle(session, node.id)
            previews[node.name] = xc.build_xray_config(node, inbounds, {i.id: list(i.clients) for i in inbounds})
        except Exception as exc:
            previews[node.name] = {"error": str(exc)}
    return JSONResponse({"ok": True, "nodes": previews})


# ── staff (admins) ───────────────────────────────────────────────────────────
@router.get("/admins")
async def admins_page(
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "admins", request)
    staff = (await session.execute(select(Admin).order_by(Admin.id))).scalars().all()
    context.update({"staff": staff, "roles": [role.value for role in AdminRole]})
    return render(request, "admins.html", **context)


@router.post("/admins/create")
async def admin_create(request: Request, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    if admin.role is not AdminRole.OWNER:
        return {"ok": False, "message": "فقط مدیر کل می‌تواند ادمین بسازد"}
    form = await request.form()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    if not username or len(password) < 6:
        return {"ok": False, "message": "نام کاربری و رمز (حداقل ۶ کاراکتر) الزامی است"}
    existing = (await session.execute(select(Admin).where(Admin.username == username))).scalar_one_or_none()
    if existing:
        return {"ok": False, "message": "این نام کاربری وجود دارد"}
    try:
        role = AdminRole(str(form.get("role") or "admin"))
    except ValueError:
        role = AdminRole.ADMIN
    session.add(
        Admin(
            username=username,
            password_hash=hash_password(password),
            full_name=str(form.get("full_name") or "").strip(),
            role=role,
            telegram_id=str(form.get("telegram_id") or "") or None,
            note=str(form.get("note") or ""),
            is_active=True,
        )
    )
    session.add(ActivityLog(actor=admin.username, kind="admin", level="ok", message=f"ادمین «{username}» ساخته شد"))
    await session.commit()
    return {"ok": True, "message": f"ادمین {username} ساخته شد"}


@router.post("/admins/{admin_id}/toggle")
async def admin_toggle(admin_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    if admin.role is not AdminRole.OWNER:
        return {"ok": False, "message": "دسترسی کافی ندارید"}
    target = await session.get(Admin, admin_id)
    if target is None:
        return {"ok": False, "message": "ادمین پیدا نشد"}
    if target.id == admin.id:
        return {"ok": False, "message": "نمی‌توانید حساب خودتان را غیرفعال کنید"}
    target.is_active = not target.is_active
    session.add(target)
    await session.commit()
    return {"ok": True, "message": "وضعیت ادمین تغییر کرد"}


@router.post("/admins/{admin_id}/delete")
async def admin_delete(admin_id: int, session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    if admin.role is not AdminRole.OWNER:
        return {"ok": False, "message": "دسترسی کافی ندارید"}
    target = await session.get(Admin, admin_id)
    if target is None:
        return {"ok": False, "message": "ادمین پیدا نشد"}
    if target.id == admin.id:
        return {"ok": False, "message": "حساب خودتان را نمی‌توانید حذف کنید"}
    await session.delete(target)
    session.add(ActivityLog(actor=admin.username, kind="admin", level="warn", message=f"ادمین «{target.username}» حذف شد"))
    await session.commit()
    return {"ok": True, "message": "ادمین حذف شد"}
