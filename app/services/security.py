"""TiTaN Panel — authentication, sessions and access control."""

from __future__ import annotations

import ipaddress
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Admin, AdminRole, AdminSession, utcnow
from ..settings import settings

SESSION_COOKIE = "titan_session"
_hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)


# ── passwords ────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:
        return False


# ── IP allow-list ────────────────────────────────────────────────────────────
def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "0.0.0.0"


def ip_allowed(ip: str) -> bool:
    if not settings.allowed_ips:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in settings.allowed_ips:
        try:
            if "/" in entry:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            elif address == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


# ── sessions ─────────────────────────────────────────────────────────────────
async def create_session(session: AsyncSession, admin: Admin, request: Request) -> AdminSession:
    token = secrets.token_urlsafe(40)
    record = AdminSession(
        token=token,
        admin_id=admin.id,
        ip=client_ip(request)[:64],
        user_agent=(request.headers.get("user-agent") or "")[:255],
        expires_at=utcnow() + timedelta(seconds=settings.session_ttl),
    )
    admin.last_login_at = utcnow()
    admin.last_login_ip = client_ip(request)[:64]
    session.add(record)
    session.add(admin)
    await session.commit()
    return record


async def destroy_session(session: AsyncSession, token: str | None) -> None:
    if not token:
        return
    await session.execute(delete(AdminSession).where(AdminSession.token == token))
    await session.commit()


async def purge_expired_sessions(session: AsyncSession) -> int:
    result = await session.execute(delete(AdminSession).where(AdminSession.expires_at < utcnow()))
    await session.commit()
    return result.rowcount or 0


async def current_admin(request: Request, session: AsyncSession = Depends(get_db)) -> Admin:
    """FastAPI dependency: resolves the signed-in admin or raises 401."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="وارد نشده‌اید")

    result = await session.execute(
        select(AdminSession).where(AdminSession.token == token, AdminSession.expires_at > utcnow())
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="نشست منقضی شده است")

    admin = await session.get(Admin, record.admin_id)
    if admin is None or not admin.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="حساب غیرفعال است")
    return admin


async def optional_admin(request: Request, session: AsyncSession = Depends(get_db)) -> Admin | None:
    try:
        return await current_admin(request, session)
    except HTTPException:
        return None


def require_role(*roles: AdminRole):
    """Dependency factory for role-gated endpoints."""

    async def _guard(admin: Admin = Depends(current_admin)) -> Admin:
        if admin.role is AdminRole.OWNER:
            return admin
        if roles and admin.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="دسترسی کافی ندارید")
        return admin

    return _guard


ACCESS_MATRIX: dict[AdminRole, set[str]] = {
    AdminRole.OWNER: {"*"},
    AdminRole.ADMIN: {"dashboard", "users", "configs", "nodes", "subscriptions", "reports", "settings", "stats"},
    AdminRole.RESELLER: {"dashboard", "users", "configs", "subscriptions", "stats"},
    AdminRole.VIEWER: {"dashboard", "reports", "stats"},
}


def can(admin: Admin, area: str) -> bool:
    allowed = ACCESS_MATRIX.get(admin.role, set())
    return "*" in allowed or area in allowed
