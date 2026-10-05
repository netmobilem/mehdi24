"""TiTaN Panel — async database bootstrap.

Uses SQLAlchemy 2.x async engine with aiosqlite. WAL journal mode is enabled so
panel reads never block the background traffic/accounting writers.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .models import Base
from .settings import settings

logger = logging.getLogger("titan.db")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings.ensure_dirs()
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            future=True,
            pool_pre_ping=True,
            connect_args={"timeout": 30, "check_same_thread": False},
        )

        @event.listens_for(_engine.sync_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=15000")
            cursor.close()

    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional scope used by background workers and services."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create the schema (idempotent) and run light migrations."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # light-weight migrations for pre-existing databases
        await _apply_migrations(conn)
    logger.info("database ready at %s", settings.db_path)


async def _apply_migrations(conn) -> None:
    """Additive migrations — keeps old installs working without Alembic."""
    result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
    tables = {row[0] for row in result.fetchall()}
    if "nodes" not in tables:
        return

    result = await conn.execute(text("PRAGMA table_info(nodes)"))
    columns = {row[1] for row in result.fetchall()}
    additive = {
        "reality_enabled": "BOOLEAN DEFAULT 0",
        "hysteria2_enabled": "BOOLEAN DEFAULT 0",
        "wireguard_enabled": "BOOLEAN DEFAULT 0",
        "cert_expires_at": "DATETIME",
        "cert_issuer": "VARCHAR(64)",
        "ssh_key_path": "VARCHAR(255)",
        "xray_version": "VARCHAR(32)",
        "nginx_version": "VARCHAR(32)",
        "agent_version": "VARCHAR(32)",
        "traffic_reset_day": "INTEGER DEFAULT 1",
    }
    for column, ddl in additive.items():
        if column not in columns:
            try:
                await conn.execute(text(f"ALTER TABLE nodes ADD COLUMN {column} {ddl}"))
                logger.info("migration: nodes.%s added", column)
            except Exception as exc:  # pragma: no cover
                logger.warning("migration skipped nodes.%s: %s", column, exc)


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
