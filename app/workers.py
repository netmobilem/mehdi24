"""TiTaN Panel — background workers.

Four independent loops share one event loop:

``health``       every 20s  → probe every node agent, refresh CPU/RAM/ping
``stats``        every 15s  → pull Xray stats, update traffic + online users
``enforce``      every 60s  → quotas, expiry, resets, IP limits
``deploy``       every 30s  → push pending config changes to nodes that need it
``maintenance``  every 1h   → prune old samples, purge sessions, cert warnings
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import delete, select

from .database import session_scope
from .models import ActivityLog, Node, NodeStatus, Notification, Setting, TrafficSample, utcnow
from .services import accounting, provisioner
from .services.security import purge_expired_sessions

logger = logging.getLogger("titan.workers")

TASKS: list[asyncio.Task] = []
STATE: dict[str, str] = {"health": "—", "stats": "—", "enforce": "—", "deploy": "—", "maintenance": "—"}


def _stamp() -> str:
    return utcnow().isoformat(timespec="seconds")


async def health_loop(interval: int = 20) -> None:
    while True:
        try:
            async with session_scope() as session:
                nodes = (await session.execute(select(Node).where(Node.is_active == True))).scalars().all()  # noqa: E712
                results = await asyncio.gather(*(provisioner.probe_node(node, persist=False) for node in nodes), return_exceptions=True)
                for node, result in zip(nodes, results):
                    if isinstance(result, Exception):
                        node.status = NodeStatus.OFFLINE
                        node.status_message = str(result)[:180]
                    session.add(node)
                await session.commit()
            STATE["health"] = _stamp()
        except Exception as exc:  # pragma: no cover
            logger.warning("health loop error: %s", exc)
        await asyncio.sleep(interval)


async def stats_loop(interval: int = 15) -> None:
    while True:
        try:
            async with session_scope() as session:
                nodes = (
                    await session.execute(select(Node).where(Node.is_active == True))  # noqa: E712
                ).scalars().all()
                for node in nodes:
                    if node.status is NodeStatus.OFFLINE:
                        continue
                    try:
                        await accounting.collect_node(session, node)
                    except Exception as exc:
                        logger.debug("collect failed on %s: %s", node.name, exc)
            STATE["stats"] = _stamp()
        except Exception as exc:  # pragma: no cover
            logger.warning("stats loop error: %s", exc)
        await asyncio.sleep(interval)


async def enforce_loop(interval: int = 60) -> None:
    while True:
        try:
            async with session_scope() as session:
                await accounting.enforce_quotas(session)
                await accounting.enforce_ip_limits(session, strict=False)
            STATE["enforce"] = _stamp()
        except Exception as exc:  # pragma: no cover
            logger.warning("enforce loop error: %s", exc)
        await asyncio.sleep(interval)


async def deploy_loop(interval: int = 30) -> None:
    """Push configuration to nodes flagged as dirty (user/quota/config changes)."""
    while True:
        try:
            async with session_scope() as session:
                nodes = (
                    await session.execute(
                        select(Node).where(Node.config_dirty == True, Node.is_active == True)  # noqa: E712
                    )
                ).scalars().all()
                for node in nodes:
                    if node.status is NodeStatus.OFFLINE:
                        continue
                    result = await provisioner.push_state(session, node.id, actor="auto-deploy")
                    if result.get("ok"):
                        node.config_dirty = False
                        session.add(node)
                        await session.commit()
                        await asyncio.sleep(0.5)
            STATE["deploy"] = _stamp()
        except Exception as exc:  # pragma: no cover
            logger.warning("deploy loop error: %s", exc)
        await asyncio.sleep(interval)


async def maintenance_loop(interval: int = 3600) -> None:
    while True:
        try:
            async with session_scope() as session:
                cutoff = utcnow() - timedelta(days=90)
                await session.execute(delete(TrafficSample).where(TrafficSample.hour_bucket < cutoff))
                await session.execute(delete(ActivityLog).where(ActivityLog.created_at < utcnow() - timedelta(days=30)))

                # TLS expiry warnings
                nodes = (await session.execute(select(Node))).scalars().all()
                for node in nodes:
                    if node.cert_expires_at and (node.cert_expires_at - utcnow()).days <= 10:
                        exists = (
                            await session.execute(
                                select(Notification).where(
                                    Notification.title.like(f"%{node.name}%"),
                                    Notification.created_at > utcnow() - timedelta(days=1),
                                )
                            )
                        ).scalars().first()
                        if not exists:
                            session.add(
                                Notification(
                                    title=f"انقضای گواهی TLS روی {node.name}",
                                    body=f"گواهی {node.address} تا {(node.cert_expires_at - utcnow()).days} روز دیگر منقضی می‌شود.",
                                    level="warn",
                                )
                            )
                await purge_expired_sessions(session)

                record = await session.get(Setting, "maintenance_last_run")
                if record is None:
                    session.add(Setting(key="maintenance_last_run", value=_stamp()))
                else:
                    record.value = _stamp()
            STATE["maintenance"] = _stamp()
        except Exception as exc:  # pragma: no cover
            logger.warning("maintenance loop error: %s", exc)
        await asyncio.sleep(interval)


def start_workers() -> None:
    stop_workers()
    TASKS.extend(
        [
            asyncio.create_task(health_loop(), name="titan-health"),
            asyncio.create_task(stats_loop(), name="titan-stats"),
            asyncio.create_task(enforce_loop(), name="titan-enforce"),
            asyncio.create_task(deploy_loop(), name="titan-deploy"),
            asyncio.create_task(maintenance_loop(), name="titan-maintenance"),
        ]
    )
    logger.info("background workers started (%d loops)", len(TASKS))


def stop_workers() -> None:
    for task in TASKS:
        task.cancel()
    TASKS.clear()


def worker_state() -> dict[str, str]:
    return dict(STATE)
