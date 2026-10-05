"""Shared web helpers: template engine, common context, flash messages."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import workers
from .models import (
    Admin,
    Inbound,
    Node,
    NodeStatus,
    Notification,
    Subscription,
    User,
    UserStatus,
    human_bytes,
    utcnow,
)
from .services import geo
from .settings import settings

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
STATIC_DIR = PROJECT_ROOT / "static"
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ── template globals / filters ───────────────────────────────────────────────
DEFAULT_LINKS = {
    "github": "https://github.com/",
    "support": "https://t.me/Code_Watch",
    "support_label": "t.me/Code_Watch",
    "bot": "https://t.me/Code_Shield",
}

templates.env.globals.update(
    links=DEFAULT_LINKS,
    now=utcnow(),
    app_name=settings.app_name,
    app_subtitle=settings.app_subtitle,
    version=settings.version,
    human_bytes=human_bytes,
    flag_for=geo.flag_for,
    countries=geo.COUNTRIES,
    country_cities=geo.CITY_PRESETS,
)


def time_ago(value, *, persian: bool = True) -> str:
    """'۲ دقیقه پیش' style relative time."""
    if not value:
        return "—"
    from .models import utcnow

    delta = utcnow() - value
    seconds = int(delta.total_seconds())
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return "چند لحظه پیش"
    if seconds < 3600:
        return f"{seconds // 60} دقیقه پیش"
    if seconds < 86400:
        return f"{seconds // 3600} ساعت پیش"
    if seconds < 2592000:
        return f"{seconds // 86400} روز پیش"
    return value.strftime("%Y-%m-%d")


def fa_digits(value: Any) -> str:
    """Convert latin digits to Persian digits for display."""
    mapping = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
    return str(value).translate(mapping)


def short_date(value, fmt: str = "%Y-%m-%d") -> str:
    return value.strftime(fmt) if value else "—"


templates.env.filters.update(
    time_ago=time_ago,
    fa=fa_digits,
    short_date=short_date,
    human_bytes=human_bytes,
    flag=geo.flag_for,
)


def _json_default(value):
    """Fallback encoder so dataclasses/enums/datetimes survive `| tojson`."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    return str(value)


templates.env.policies["json.dumps_kwargs"] = {"default": _json_default}

NAV_ITEMS: list[dict[str, str]] = [
    {"key": "dashboard", "label": "داشبورد", "href": "/", "icon": "home"},
    {"key": "users", "label": "کاربران", "href": "/users", "icon": "users"},
    {"key": "inbounds", "label": "کانفیگ‌ها", "href": "/inbounds", "icon": "grid"},
    {"key": "nodes", "label": "سرورها (Node ها)", "href": "/nodes", "icon": "server"},
    {"key": "subscriptions", "label": "اشتراک‌ها", "href": "/subscriptions", "icon": "layers"},
    {"key": "reports", "label": "گزارش‌ها", "href": "/reports", "icon": "chart"},
    {"key": "settings", "label": "تنظیمات", "href": "/settings", "icon": "gear"},
    {"key": "admins", "label": "مدیریت ادمین", "href": "/admins", "icon": "shield"},
    {"key": "stats", "label": "آمارها", "href": "/stats", "icon": "bars"},
]


async def base_context(session: AsyncSession, admin: Admin | None, active: str, request: Request | None = None) -> dict:
    """Context every page needs (sidebar badges, worker state, counters)."""
    users_total = (await session.execute(select(func.count(User.id)))).scalar_one()
    users_online = (
        await session.execute(
            select(func.count(User.id)).where(User.last_online_at >= utcnow() - timedelta(minutes=3))
        )
    ).scalar_one()
    inbounds_total = (await session.execute(select(func.count(Inbound.id)))).scalar_one()
    nodes_total = (await session.execute(select(func.count(Node.id)))).scalar_one()
    nodes_online = (
        await session.execute(select(func.count(Node.id)).where(Node.status == NodeStatus.ONLINE))
    ).scalar_one()
    subs_total = (await session.execute(select(func.count(Subscription.id)))).scalar_one()

    notifications = (
        await session.execute(select(Notification).order_by(Notification.created_at.desc()).limit(8))
    ).scalars().all()
    unread = (
        await session.execute(select(func.count(Notification.id)).where(Notification.is_read == False))  # noqa: E712
    ).scalar_one()

    panel_domain = settings.panel_domain or (request.url.hostname if request else "panel.local")

    return {
        "admin": admin,
        "active": active,
        "nav_items": NAV_ITEMS,
        "notifications": notifications,
        "unread_notifications": unread,
        "links": {
            "github": "https://github.com/",
            "support": "https://t.me/Code_Watch",
            "support_label": "t.me/Code_Watch",
            "bot": "https://t.me/Code_Shield",
        },
        "panel_domain": panel_domain,
        # surfaced by the app when DATA_DIR was not writable (see settings.py)
        "data_warning": settings.data_warning,
        "counters": {
            "users": users_total,
            "users_online": users_online,
            "inbounds": inbounds_total,
            "nodes": nodes_total,
            "nodes_online": nodes_online,
            "subscriptions": subs_total,
        },
        "workers": workers.worker_state(),
        "notice": request.query_params.get("notice") if request else None,
    }


def render(request: Request, template: str, **context) -> HTMLResponse:
    return templates.TemplateResponse(request, template, context)


def redirect(url: str, *, status_code: int = 303) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=status_code)
