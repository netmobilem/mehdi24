"""Sign-in / sign-out and first-run password setup."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import ActivityLog, Admin, AdminRole
from ..services.security import (
    SESSION_COOKIE,
    client_ip,
    create_session,
    destroy_session,
    hash_password,
    ip_allowed,
    verify_password,
)
from ..settings import settings
from ..web import render

router = APIRouter(tags=["auth"])


@router.get("/login")
async def login_page(request: Request, session: AsyncSession = Depends(get_db)):
    count = len((await session.execute(select(Admin.id))).scalars().all())
    return render(request, "login.html", error=None, setup=count == 0)


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    session: AsyncSession = Depends(get_db),
):
    ip = client_ip(request)
    if not ip_allowed(ip):
        return render(request, "login.html", error="دسترسی از این آی‌پی مجاز نیست", setup=False)

    result = await session.execute(select(Admin).where(Admin.username == username.strip()))
    admin = result.scalar_one_or_none()

    # first-run: create the owner account straight from the environment
    if admin is None and (await session.execute(select(Admin.id))).first() is None:
        admin = Admin(
            username=username.strip() or settings.admin_username,
            password_hash=hash_password(password or settings.admin_password),
            full_name="مدیر کل",
            role=AdminRole.OWNER,
            is_active=True,
        )
        session.add(admin)
        await session.commit()

    if admin is None or not verify_password(admin.password_hash, password):
        session.add(ActivityLog(actor=username or "?", kind="login", level="warn", message="تلاش ناموفق برای ورود", ip=ip))
        await session.commit()
        return render(request, "login.html", error="نام کاربری یا رمز عبور نادرست است", setup=False)

    if not admin.is_active:
        return render(request, "login.html", error="این حساب غیرفعال شده است", setup=False)

    record = await create_session(session, admin, request)
    session.add(ActivityLog(actor=admin.username, kind="login", level="ok", message="ورود به پنل", ip=ip))
    await session.commit()

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        record.token,
        max_age=settings.session_ttl,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@router.get("/logout")
@router.post("/logout")
async def logout(request: Request, session: AsyncSession = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(session, token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.post("/change-password")
async def change_password(
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    token = request.cookies.get(SESSION_COOKIE)
    from ..services.security import current_admin  # local import keeps dependency graph simple

    admin = await current_admin(request, session)
    form = await request.form()
    current = str(form.get("current_password") or "")
    new_password = str(form.get("new_password") or "")
    if not verify_password(admin.password_hash, current):
        return RedirectResponse("/settings?notice=رمز فعلی نادرست است", status_code=303)
    if len(new_password) < 6:
        return RedirectResponse("/settings?notice=رمز جدید باید حداقل ۶ کاراکتر باشد", status_code=303)
    admin.password_hash = hash_password(new_password)
    session.add(admin)
    session.add(ActivityLog(actor=admin.username, kind="security", level="warn", message="تغییر رمز عبور"))
    await session.commit()
    return RedirectResponse("/settings?notice=رمز عبور بروزرسانی شد", status_code=303)
