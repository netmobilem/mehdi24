"""Dashboard, reports and aggregate statistics pages."""

from __future__ import annotations

import csv
import io
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import (
    ActivityLog,
    Admin,
    Inbound,
    Node,
    NodeSample,
    Protocol,
    Subscription,
    TrafficSample,
    User,
    UserStatus,
    human_bytes,
    utcnow,
)
from ..services import accounting, provisioner
from ..services.security import current_admin
from ..web import base_context, render

router = APIRouter(tags=["pages"])

WEEKDAYS_FA = {5: "شنبه", 6: "یکشنبه", 0: "دوشنبه", 1: "سه‌شنبه", 2: "چهارشنبه", 3: "پنجشنبه", 4: "جمعه"}
PROTOCOL_COLORS = {
    "vless": "#7c70db",
    "vmess": "#315c96",
    "trojan": "#13a9cb",
    "shadowsocks": "#268fdb",
    "hysteria2": "#f6bf3d",
    "wireguard": "#7d8eaf",
}
PROTOCOL_LABELS = {
    "vless": "VLESS",
    "vmess": "VMess",
    "trojan": "Trojan",
    "shadowsocks": "Shadowsocks",
    "hysteria2": "Hysteria2",
    "wireguard": "WireGuard",
}


def _percent_change(current: float, previous: float) -> str:
    if previous <= 0:
        return "0" if current <= 0 else "100"
    change = (current - previous) / previous * 100
    return f"{change:+.0f}".replace("+", "") if change else "0"


@router.get("/")
async def dashboard(
    request: Request,
    range: str = "7d",
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "dashboard", request)
    totals = await accounting.totals(session)

    # ── chart series ────────────────────────────────────────────────────────
    if range == "24h":
        raw = await accounting.hourly_series(session, 24)
        series = [{"label": f"{moment.hour:02d}", "value": value} for moment, value in raw]
    elif range == "30d":
        raw = await accounting.traffic_series(session, 30)
        series = [{"label": moment.strftime("%m/%d"), "value": value} for moment, value in raw]
    else:
        range = "7d"
        raw = await accounting.traffic_series(session, 7)
        series = [{"label": WEEKDAYS_FA.get(moment.weekday(), "—"), "value": value} for moment, value in raw]

    # ── delta vs yesterday (real numbers, not decoration) ───────────────────
    today = series[-1]["value"] if series else 0
    yesterday = series[-2]["value"] if len(series) > 1 else 0
    users_today = (
        await session.execute(select(func.count(User.id)).where(User.created_at >= utcnow() - timedelta(days=1)))
    ).scalar_one()
    users_before = (
        await session.execute(
            select(func.count(User.id)).where(
                User.created_at < utcnow() - timedelta(days=1),
                User.created_at >= utcnow() - timedelta(days=2),
            )
        )
    ).scalar_one()
    inbounds_today = (
        await session.execute(select(func.count(Inbound.id)).where(Inbound.created_at >= utcnow() - timedelta(days=1)))
    ).scalar_one()
    subs_today = (
        await session.execute(
            select(func.count(Subscription.id)).where(Subscription.created_at >= utcnow() - timedelta(days=1))
        )
    ).scalar_one()

    stats_delta = {
        "traffic": _percent_change(today, yesterday),
        "users": _percent_change(users_today, users_before),
        "inbounds": _percent_change(inbounds_today, max(inbounds_today - 1, 0)),
        "subscriptions": _percent_change(subs_today, max(subs_today - 1, 0)),
    }

    # ── servers ─────────────────────────────────────────────────────────────
    nodes = (
        await session.execute(select(Node).where(Node.is_active == True).order_by(Node.sort_order, Node.id).limit(4))  # noqa: E712
    ).scalars().all()
    peak = max((node.traffic_up + node.traffic_down for node in nodes), default=0) or 1
    for node in nodes:
        node.traffic_bar = round((node.traffic_up + node.traffic_down) / peak * 100)

    latest_users = (
        await session.execute(select(User).order_by(User.created_at.desc()).limit(4))
    ).scalars().all()
    activities = (
        await session.execute(select(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(4))
    ).scalars().all()

    # ── donut ───────────────────────────────────────────────────────────────
    by_protocol = await accounting.traffic_by_protocol(session)
    segments = [
        {
            "label": PROTOCOL_LABELS.get(key, key),
            "value": value,
            "color": PROTOCOL_COLORS.get(key, "#7d8eaf"),
        }
        for key, value in sorted(by_protocol.items(), key=lambda item: item[1], reverse=True)
    ]
    if not segments:
        segments = [
            {"label": "VLESS", "value": 0, "color": PROTOCOL_COLORS["vless"]},
            {"label": "Trojan", "value": 0, "color": PROTOCOL_COLORS["trojan"]},
            {"label": "سایر", "value": 0, "color": "#7d8eaf"},
        ]
    donut_total = sum(item["value"] for item in segments)

    context.update(
        {
            "totals": totals,
            "stats_delta": stats_delta,
            "chart": {"series": series},
            "range_key": range,
            "nodes": nodes,
            "latest_users": latest_users,
            "activities": activities,
            "donut": {"segments": segments[:4], "total": donut_total},
            "live_stamp": utcnow().strftime("%H:%M:%S"),
            "now": utcnow(),
        }
    )
    return render(request, "dashboard.html", **context)


@router.get("/reports")
async def reports(
    request: Request,
    days: int = 7,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "reports", request)
    days = max(1, min(days, 90))
    series = await accounting.traffic_series(session, days)
    top_users = await accounting.usage_by_user(session, limit=20)

    node_rows = (
        await session.execute(select(Node).order_by(Node.sort_order, Node.id))
    ).scalars().all()
    peak = max((node.traffic_up + node.traffic_down for node in node_rows), default=0) or 1
    for node in node_rows:
        node.traffic_bar = round((node.traffic_up + node.traffic_down) / peak * 100)

    totals = await accounting.totals(session)
    context.update(
        {
            "days": days,
            "series": [{"label": moment.strftime("%m/%d"), "value": value} for moment, value in series],
            "top_users": top_users,
            "nodes": node_rows,
            "totals": totals,
            "activities": (
                await session.execute(select(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(40))
            ).scalars().all(),
        }
    )
    return render(request, "reports.html", **context)


@router.get("/reports/export.csv")
async def export_csv(
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
    days: int = 30,
):
    since = utcnow() - timedelta(days=max(1, min(days, 365)))
    rows = (
        await session.execute(
            select(
                TrafficSample.hour_bucket,
                Node.name,
                TrafficSample.email_tag,
                TrafficSample.up,
                TrafficSample.down,
            )
            .join(Node, Node.id == TrafficSample.node_id)
            .where(TrafficSample.hour_bucket >= since)
            .order_by(TrafficSample.hour_bucket.desc())
            .limit(20000)
        )
    ).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["hour", "node", "user_tag", "up_bytes", "down_bytes", "total_bytes"])
    for bucket, node_name, tag, up, down in rows:
        writer.writerow([bucket.isoformat(), node_name, tag, up, down, (up or 0) + (down or 0)])
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="titan-traffic-{days}d.csv"'},
    )


@router.get("/stats")
async def stats(
    request: Request,
    session: AsyncSession = Depends(get_db),
    admin: Admin = Depends(current_admin),
):
    context = await base_context(session, admin, "stats", request)
    totals = await accounting.totals(session)
    by_protocol = await accounting.traffic_by_protocol(session)
    segments = [
        {"label": PROTOCOL_LABELS.get(key, key), "value": value, "color": PROTOCOL_COLORS.get(key, "#7d8eaf")}
        for key, value in sorted(by_protocol.items(), key=lambda item: item[1], reverse=True)
    ]
    usage = await accounting.usage_by_user(session, limit=15)
    online = await accounting.online_snapshot(session)
    daily = await accounting.traffic_series(session, 14)
    node_rows = (await session.execute(select(Node).order_by(Node.sort_order, Node.id))).scalars().all()

    status_counts: dict[str, int] = {}
    for status, count in (
        await session.execute(select(User.status, func.count(User.id)).group_by(User.status))
    ).all():
        status_counts[status.value if hasattr(status, "value") else str(status)] = count

    context.update(
        {
            "totals": totals,
            "segments": segments or [{"label": "بدون داده", "value": 0, "color": "#1b2740"}],
            "donut_total": sum(item["value"] for item in segments),
            "usage": usage,
            "online": online,
            "daily": [{"label": moment.strftime("%m/%d"), "value": value} for moment, value in daily],
            "node_rows": node_rows,
            "status_counts": status_counts,
        }
    )
    return render(request, "stats.html", **context)


@router.get("/api/dashboard")
async def dashboard_api(session: AsyncSession = Depends(get_db), admin: Admin = Depends(current_admin)):
    """Lightweight JSON polled by the browser for live node badges."""
    nodes = (await session.execute(select(Node).where(Node.is_active == True))).scalars().all()  # noqa: E712
    totals = await accounting.totals(session)
    return {
        "ok": True,
        "time": utcnow().strftime("%H:%M:%S"),
        "totals": {
            "users": totals["users"],
            "users_online": totals["users_online"],
            "traffic": totals["traffic"],
            "traffic_human": human_bytes(totals["traffic"]),
            "nodes_online": totals["nodes_online"],
            "nodes_total": totals["nodes_total"],
        },
        "nodes": [
            {
                "id": node.id,
                "name": node.name,
                "status": node.status.value,
                "cpu": round(node.cpu_pct, 1),
                "ram": node.ram_pct,
                "disk": node.disk_pct,
                "traffic": node.traffic_up + node.traffic_down,
                "ping": node.ping_ms,
                "uptime": node.uptime_sec,
            }
            for node in nodes
        ],
    }
