"""TiTaN Panel — traffic accounting, quota / expiry / IP-limit enforcement.

The collector pulls cumulative counters from every node's Xray stats API, keeps
the last value per ``(node, email)`` and stores the *delta*:

* per-user hourly buckets  → the traffic chart and reports
* per-node hourly buckets  → node traffic counters on the dashboard
* user totals              → quota enforcement

Everything runs on one async loop, so a 5-second interval costs almost nothing
even with thousands of users.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models import (
    ActivityLog,
    Client,
    Inbound,
    Node,
    NodeSample,
    NodeStatus,
    ResetStrategy,
    TrafficSample,
    User,
    UserStatus,
    utcnow,
)
from . import provisioner

logger = logging.getLogger("titan.accounting")


def hour_bucket(moment: datetime | None = None) -> datetime:
    moment = moment or utcnow()
    return moment.replace(minute=0, second=0, microsecond=0)


# ── counter bookkeeping ──────────────────────────────────────────────────────
class CounterStore:
    """Keeps the previous cumulative values so we can store hourly deltas."""

    def __init__(self) -> None:
        self._values: dict[tuple[int, str], tuple[int, int]] = {}
        self._baseline_hour: datetime | None = None

    def delta(self, node_id: int, email: str, up: int, down: int) -> tuple[int, int]:
        key = (node_id, email)
        previous = self._values.get(key)
        self._values[key] = (up, down)
        if previous is None:
            return 0, 0
        prev_up, prev_down = previous
        # a counter that went backwards means xray restarted — treat as fresh
        d_up = up - prev_up if up >= prev_up else up
        d_down = down - prev_down if down >= prev_down else down
        return max(d_up, 0), max(d_down, 0)

    def forget(self, node_id: int) -> None:
        for key in [k for k in self._values if k[0] == node_id]:
            self._values.pop(key, None)


counters = CounterStore()


async def collect_node(session: AsyncSession, node: Node) -> dict:
    """Fetch + persist traffic for one node. Returns a small summary."""
    stats = await provisioner.collect_stats(session, node)
    if not stats.get("ok"):
        return {"ok": False, "error": stats.get("error", "no data")}

    bucket = hour_bucket()
    users_payload: dict[str, dict] = stats.get("users") or {}
    node_up = node_down = 0
    samples: dict[str, tuple[int, int]] = {}

    # map email → user via clients (email tags are unique per client)
    emails = list(users_payload.keys())
    user_by_email: dict[str, User] = {}
    if emails:
        result = await session.execute(
            select(Client.email_tag, User)
            .join(User, Client.user_id == User.id)
            .where(Client.email_tag.in_(emails))
        )
        for email_tag, user in result.all():
            user_by_email[email_tag] = user

    for email, payload in users_payload.items():
        up = int(payload.get("up") or 0)
        down = int(payload.get("down") or 0)
        node_up += up
        node_down += down
        d_up, d_down = counters.delta(node.id, email, up, down)
        if d_up or d_down:
            samples[email] = (d_up, d_down)
            user = user_by_email.get(email)
            if user is not None:
                user.used_up += d_up
                user.used_down += d_down
                session.add(user)
                await _write_user_sample(session, bucket, node.id, user.id, email, d_up, d_down)

    node.traffic_up = node_up
    node.traffic_down = node_down
    session.add(node)

    await _write_node_sample(session, bucket, node.id, node_up, node_down)

    # online state + IP tracking
    online = set((stats.get("online") or {}).get("users") or [])
    ip_map: dict[str, list[str]] = stats.get("ips") or {}
    for email, user in user_by_email.items():
        ips = [ip for ip, emails in ip_map.items() if email in emails]
        if ips:
            user.last_ip = ips[0]
            user.online_ips = ips[:32]
        if email in online or ips:
            user.last_online_at = utcnow()
        session.add(user)

    await session.commit()
    return {
        "ok": True,
        "node": node.name,
        "users": len(users_payload),
        "online": len(online),
        "delta_users": len(samples),
        "up": node_up,
        "down": node_down,
    }


async def _write_user_sample(
    session: AsyncSession, bucket: datetime, node_id: int, user_id: int, email: str, up: int, down: int
) -> None:
    result = await session.execute(
        select(TrafficSample).where(
            TrafficSample.hour_bucket == bucket,
            TrafficSample.node_id == node_id,
            TrafficSample.email_tag == email,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        session.add(
            TrafficSample(hour_bucket=bucket, node_id=node_id, user_id=user_id, email_tag=email, up=up, down=down)
        )
    else:
        row.up += up
        row.down += down
        row.user_id = user_id
        session.add(row)


async def _write_node_sample(session: AsyncSession, bucket: datetime, node_id: int, up: int, down: int) -> None:
    result = await session.execute(
        select(NodeSample).where(NodeSample.hour_bucket == bucket, NodeSample.node_id == node_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        session.add(NodeSample(hour_bucket=bucket, node_id=node_id, up=up, down=down))
    else:
        row.up = up        # node totals are absolute counters, not deltas
        row.down = down


# ── enforcement ──────────────────────────────────────────────────────────────
async def enforce_quotas(session: AsyncSession) -> dict:
    """Expire users, cut them off when the quota is gone, apply resets."""
    result = await session.execute(
        select(User).where(User.status != UserStatus.DISABLED).options(selectinload(User.clients))
    )
    users = list(result.scalars().all())
    changed = expired = limited = reset = 0

    for user in users:
        previous = user.status
        user.refresh_status()
        if user.status is not previous:
            changed += 1
            if user.status is UserStatus.EXPIRED:
                expired += 1
            elif user.status is UserStatus.LIMITED:
                limited += 1
            session.add(
                ActivityLog(
                    actor="system",
                    kind="quota",
                    level="warn",
                    message=f"کاربر {user.username}: وضعیت به {user.status.value} تغییر کرد",
                )
            )
        session.add(user)

    # scheduled resets
    reset = await _apply_resets(session, users)

    if changed or reset:
        await session.commit()
        await _flag_dirty_nodes(session, users)
    return {"ok": True, "changed": changed, "expired": expired, "limited": limited, "reset": reset}


async def _apply_resets(session: AsyncSession, users: list[User]) -> int:
    now = utcnow()
    count = 0
    for user in users:
        if user.reset_strategy is ResetStrategy.NEVER or not user.activated_at:
            continue
        period = {ResetStrategy.MONTHLY: 30, ResetStrategy.WEEKLY: 7, ResetStrategy.DAILY: 1}.get(user.reset_strategy)
        if not period:
            continue
        if now - user.activated_at >= timedelta(days=period):
            user.used_up = 0
            user.used_down = 0
            user.activated_at = now
            user.refresh_status()
            session.add(user)
            session.add(
                ActivityLog(
                    actor="system",
                    kind="quota",
                    level="info",
                    message=f"مصرف کاربر {user.username} بر اساس چرخه‌ی {user.reset_strategy.value} صفر شد",
                )
            )
            count += 1
    return count


async def enforce_ip_limits(session: AsyncSession, *, strict: bool = False) -> dict:
    """IP-limit accounting.

    In ``strict`` mode a user who exceeds the allowed concurrent IP count is
    disabled (and automatically re-enabled once they drop below the limit) —
    the behaviour most panels call "IP limit".
    """
    result = await session.execute(select(User).where(User.ip_limit > 0, User.status == UserStatus.ACTIVE))
    users = list(result.scalars().all())
    violations = 0
    for user in users:
        active_ips = [ip for ip in (user.online_ips or []) if ip and ip not in ("127.0.0.1", "::1")]
        if len(active_ips) > user.ip_limit:
            violations += 1
            session.add(
                ActivityLog(
                    actor="system",
                    kind="ip-limit",
                    level="warn",
                    message=f"کاربر {user.username} از محدودیت IP عبور کرد ({len(active_ips)}/{user.ip_limit})",
                )
            )
            if strict:
                user.status = UserStatus.DISABLED
                user.note = f"غیرفعال خودکار: عبور از محدودیت {user.ip_limit} آی‌پی"
                session.add(user)
    if violations:
        await session.commit()
        if strict:
            await _flag_dirty_nodes(session, users)
    return {"ok": True, "violations": violations, "checked": len(users)}


async def _flag_dirty_nodes(session: AsyncSession, users: list[User]) -> None:
    """Mark every node that serves one of these users as 'needs redeploy'."""
    user_ids = [user.id for user in users if user.id]
    if not user_ids:
        return
    rows = await session.execute(
        select(Inbound.node_id)
        .join(Client, Client.inbound_id == Inbound.id)
        .where(Client.user_id.in_(user_ids))
        .distinct()
    )
    node_ids = {row[0] for row in rows.all()}
    if node_ids:
        result = await session.execute(select(Node).where(Node.id.in_(node_ids)))
        for node in result.scalars().all():
            node.config_dirty = True
            session.add(node)
        await session.commit()


# ── reporting helpers used by the dashboard ──────────────────────────────────
async def traffic_series(session: AsyncSession, days: int = 7) -> list[tuple[datetime, int]]:
    """Daily traffic totals for the chart (oldest → newest, always filled)."""
    end = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days - 1)
    result = await session.execute(
        select(
            func.strftime("%Y-%m-%d", TrafficSample.hour_bucket).label("day"),
            func.sum(TrafficSample.up + TrafficSample.down).label("total"),
        )
        .where(TrafficSample.hour_bucket >= start)
        .group_by("day")
    )
    buckets = {row.day: int(row.total or 0) for row in result.all()}
    series: list[tuple[datetime, int]] = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        series.append((day, buckets.get(day.strftime("%Y-%m-%d"), 0)))
    return series


async def hourly_series(session: AsyncSession, hours: int = 24) -> list[tuple[datetime, int]]:
    end = hour_bucket()
    start = end - timedelta(hours=hours - 1)
    result = await session.execute(
        select(TrafficSample.hour_bucket, func.sum(TrafficSample.up + TrafficSample.down))
        .where(TrafficSample.hour_bucket >= start)
        .group_by(TrafficSample.hour_bucket)
    )
    buckets = {row[0]: int(row[1] or 0) for row in result.all()}
    series: list[tuple[datetime, int]] = []
    for offset in range(hours):
        moment = start + timedelta(hours=offset)
        series.append((moment, buckets.get(moment, 0)))
    return series


async def usage_by_user(session: AsyncSession, limit: int = 10) -> list[tuple[User, int]]:
    result = await session.execute(
        select(TrafficSample.user_id, func.sum(TrafficSample.up + TrafficSample.down))
        .where(TrafficSample.hour_bucket >= utcnow() - timedelta(days=30), TrafficSample.user_id.is_not(None))
        .group_by(TrafficSample.user_id)
        .order_by(func.sum(TrafficSample.up + TrafficSample.down).desc())
        .limit(limit)
    )
    rows = result.all()
    if not rows:
        return []
    ids = [row[0] for row in rows]
    users = (await session.execute(select(User).where(User.id.in_(ids)))).scalars().all()
    index = {user.id: user for user in users}
    return [(index[row[0]], int(row[1] or 0)) for row in rows if row[0] in index]


async def traffic_by_node(session: AsyncSession) -> dict[int, int]:
    result = await session.execute(select(Node.id, Node.traffic_up + Node.traffic_down))
    return {row[0]: int(row[1] or 0) for row in result.all()}


async def totals(session: AsyncSession) -> dict:
    user_count = (await session.execute(select(func.count(User.id)))).scalar_one()
    active_users = (
        await session.execute(select(func.count(User.id)).where(User.status == UserStatus.ACTIVE))
    ).scalar_one()
    nodes_online = (
        await session.execute(select(func.count(Node.id)).where(Node.status == NodeStatus.ONLINE))
    ).scalar_one()
    nodes_total = (await session.execute(select(func.count(Node.id)))).scalar_one()
    traffic = (
        await session.execute(select(func.coalesce(func.sum(Node.traffic_up + Node.traffic_down), 0)))
    ).scalar_one()
    inbounds_active = (
        await session.execute(select(func.count(Inbound.id)).where(Inbound.is_active == True))  # noqa: E712
    ).scalar_one()
    inbounds_total = (await session.execute(select(func.count(Inbound.id)))).scalar_one()
    online_now = (
        await session.execute(
            select(func.count(User.id)).where(User.last_online_at >= utcnow() - timedelta(minutes=3))
        )
    ).scalar_one()
    return {
        "users": user_count,
        "users_active": active_users,
        "users_online": online_now,
        "nodes_online": nodes_online,
        "nodes_total": nodes_total,
        "traffic": int(traffic or 0),
        "inbounds": inbounds_total,
        "inbounds_active": inbounds_active,
    }


async def traffic_by_protocol(session: AsyncSession) -> dict[str, int]:
    """Traffic split per protocol (VLESS / VMess / Trojan / …) for the donut."""
    result = await session.execute(
        select(Inbound.protocol, func.sum(TrafficSample.up + TrafficSample.down))
        .select_from(TrafficSample)
        .join(Client, Client.email_tag == TrafficSample.email_tag)
        .join(Inbound, Inbound.id == Client.inbound_id)
        .where(TrafficSample.hour_bucket >= utcnow() - timedelta(days=30))
        .group_by(Inbound.protocol)
    )
    output: dict[str, int] = {}
    for protocol, total in result.all():
        key = protocol.value if hasattr(protocol, "value") else str(protocol)
        output[key] = output.get(key, 0) + int(total or 0)
    return output


async def online_snapshot(session: AsyncSession) -> list[tuple[str, str, str | None]]:
    """(username, last_ip, last_online_at) for recently active users."""
    result = await session.execute(
        select(User.username, User.last_ip, User.last_online_at)
        .where(User.last_online_at >= utcnow() - timedelta(minutes=5))
        .order_by(User.last_online_at.desc())
    )
    return [(row[0], row[1] or "—", row[2]) for row in result.all()]
