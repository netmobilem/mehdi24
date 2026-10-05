"""TiTaN Panel — application entrypoint.

Run locally:      python -m app.main         (or: uvicorn app.main:app)
On Railway:       the Dockerfile starts ``python -m app.main``.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import workers
from .database import dispose_engine, init_db, session_scope
from .models import Admin, AdminRole, Node, NodeStatus, Setting, User, UserStatus, utcnow
from .routers import inbounds, nodes, pages, subscriptions, users
from .routers import auth as auth_router
from .routers import settings_routes
from .services.security import hash_password
from .settings import settings
from .web import STATIC_DIR

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("titan")

DESCRIPTION = """
**TiTaN Panel** — management panel for Xray + Nginx nodes.

* combined core: Nginx owns TLS/ALPN/decoy site, Xray owns the protocols
* protocols: VLESS · VMess · Trojan · Shadowsocks (+ Hysteria2 / WireGuard)
* transports: WS · XHTTP (packet-up / stream-up / stream-one) · gRPC · TCP · HTTPUpgrade
* security: TLS (Let's Encrypt) or REALITY, per-inbound fingerprint + ALPN
* real accounting, quota / expiry / IP-limit enforcement, subscriptions & QR
"""


LISTEN_STATE: dict[str, object] = {"addresses": [], "ports": []}


def _bind_port(host: str, port: int) -> list:
    """Bind one port, returning the sockets (IPv4 wildcard + IPv6 sibling)."""
    import socket

    def make(family: int, address: str, v6only: int | None = None):
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6 and v6only is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only)
            except OSError:
                pass
        sock.bind((address, port))
        sock.listen(2048)
        sock.setblocking(False)
        return sock

    if ":" in host:  # explicit IPv6 host (HOST=::) — leave the stack flag to the OS
        return [make(socket.AF_INET6, host)]

    socks = [make(socket.AF_INET, host)]
    if host in ("0.0.0.0", ""):
        # V6ONLY=1 keeps this socket IPv6-only, so it never conflicts with the
        # IPv4 wildcard above while still accepting Railway's internal IPv6 hop.
        try:
            socks.append(make(socket.AF_INET6, "::", v6only=1))
        except OSError:
            pass  # no IPv6 on this platform — IPv4 is enough
    return socks


async def seed_first_run() -> None:
    """Create the owner account and defaults on an empty database."""
    async with session_scope() as session:
        admins = (await session.execute(__import__("sqlalchemy").select(Admin))).scalars().all()
        if not admins:
            session.add(
                Admin(
                    username=settings.admin_username,
                    password_hash=hash_password(settings.admin_password),
                    full_name="مدیر کل",
                    role=AdminRole.OWNER,
                    is_active=True,
                )
            )
            logger.info("created default owner '%s' (change the password after login)", settings.admin_username)

        defaults = {
            "sub_title": settings.app_name,
            "sub_announcement": "برای دریافت پشتیبانی به تلگرام ما پیام دهید.",
            "auto_deploy": "1",
            "ip_limit_strict": "0",
        }
        for key, value in defaults.items():
            if await session.get(Setting, key) is None:
                session.add(Setting(key=key, value=value))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    settings.resolve_secret()
    await init_db()
    await seed_first_run()
    workers.start_workers()
    logger.info("%s v%s ready on %s:%s", settings.app_name, settings.version, settings.host, settings.port)
    try:
        yield
    finally:
        workers.stop_workers()
        await dispose_engine()
        logger.info("shutdown complete")


app = FastAPI(
    title="TiTaN Panel",
    description=DESCRIPTION,
    version=settings.version,
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(auth_router.router)
app.include_router(pages.router)
app.include_router(users.router)
app.include_router(inbounds.router)
app.include_router(nodes.router)
app.include_router(subscriptions.router)
app.include_router(subscriptions.public_router)
app.include_router(settings_routes.router)


@app.get("/healthz", include_in_schema=False)
async def healthz():
    """Liveness probe used by Railway / Docker / uptime monitors."""
    return {
        "ok": True,
        "app": settings.app_name,
        "version": settings.version,
        "time": utcnow().isoformat(),
        "listen": LISTEN_STATE["addresses"],
        "workers": workers.worker_state(),
    }


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith(("/api", "/sub", "/s/", "/qr")):
        return JSONResponse({"ok": False, "message": "not found"}, status_code=404)
    from fastapi.responses import RedirectResponse

    return RedirectResponse("/", status_code=303)


def main() -> None:
    """Start the panel.

    The panel binds *every* port from :meth:`Settings.listen_ports` (``PORT``
    plus ``EXTRA_PORTS``) so a Railway "target port" that differs from the
    injected ``PORT`` variable can no longer produce
    ``Application failed to respond``. Each port additionally gets an IPv6
    socket (``[::]``) because Railway's internal edge can reach the container
    over IPv6; if the platform has no IPv6 the socket is simply skipped.
    """
    import asyncio
    import errno
    import socket

    import uvicorn

    host = settings.host or "0.0.0.0"
    ports = settings.listen_ports() or [8000]
    sockets: list[socket.socket] = []
    bound: list[str] = []
    failures: list[str] = []

    for port in ports:
        try:
            sockets.extend(_bind_port(host, port))
        except OSError as exc:
            detail = errno.errorcode.get(exc.errno or 0, str(exc))
            failures.append(f"{host}:{port} ({detail})")
            logger.error("cannot listen on %s:%s — %s", host, port, detail)

    for sock in sockets:
        addr = sock.getsockname()
        bound.append(f"[{addr[0]}]:{addr[1]}" if sock.family == socket.AF_INET6 else f"{addr[0]}:{addr[1]}")

    if not sockets:
        raise SystemExit(f"no port could be bound ({'; '.join(failures) or 'unknown error'})")

    LISTEN_STATE["addresses"] = bound
    LISTEN_STATE["ports"] = sorted({sock.getsockname()[1] for sock in sockets})

    logger.info("=" * 68)
    logger.info("TiTaN is listening on: %s", "  ".join(bound))
    logger.info("Railway/Fly: set the public domain target port to %s", " or ".join(str(p) for p in LISTEN_STATE["ports"]))
    if failures:
        logger.warning("ports that failed to bind: %s", ", ".join(failures))
    logger.info("=" * 68)

    config = uvicorn.Config(
        app,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips="*",
        access_log=False,
    )
    server = uvicorn.Server(config)
    asyncio.run(server.serve(sockets=sockets))


if __name__ == "__main__":
    main()
