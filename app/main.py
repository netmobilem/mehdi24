"""TiTaN Panel — application entrypoint.

Run locally:      python -m app.main         (or: uvicorn app.main:app)
On Railway:       the Dockerfile starts ``python -m app.main``.

Robustness notes (learned from real Railway deployments):

* A failure while the app is starting up (unwritable volume, DB file that
  cannot be opened, …) used to make uvicorn print "Application startup
  failed. Exiting." and leave the process with **exit code 0**. Railway reads
  exit code 0 as *"the job finished"* → deployment status **Completed** (green)
  and, with ``restartPolicyType: ON_FAILURE``, it never restarts — the public
  domain then answers "Application failed to respond".
  Now the runtime setup happens *before* uvicorn starts, the data directory
  falls back to a writable location, and a truly fatal setup exits with a
  non-zero code so Railway shows *Crashed* + the real traceback and restarts.
* The panel listens on ``PORT`` **and** ``EXTRA_PORTS`` (default 8080/8000/3000)
  over both IPv4 and IPv6, because Railway's public-domain "target port" is a
  separate setting that does not change the injected ``PORT`` value.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import workers
from .database import dispose_engine, init_db, session_scope
from .models import Admin, AdminRole, Setting, utcnow
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

# Runtime state exposed through /healthz and the boot logs.
BOOT_STATE: dict[str, object] = {
    "addresses": [],
    "ports": [],
    "ports_seen": [],
    "requests": 0,
    "fatal": None,
    "warning": None,
    "restarts": 0,
}


# ── socket helpers ────────────────────────────────────────────────────────────
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


def _bind_all() -> tuple[list, list[str], list[str]]:
    """Bind every configured port; returns (sockets, addresses, failures)."""
    import errno
    import socket

    host = settings.host or "0.0.0.0"
    sockets: list[socket.socket] = []
    failures: list[str] = []

    for port in settings.listen_ports() or [8000]:
        try:
            sockets.extend(_bind_port(host, port))
        except OSError as exc:
            detail = errno.errorcode.get(exc.errno or 0, str(exc))
            failures.append(f"{host}:{port} ({detail})")
            logger.error("cannot listen on %s:%s — %s", host, port, detail)

    addresses = []
    for sock in sockets:
        addr = sock.getsockname()
        addresses.append(f"[{addr[0]}]:{addr[1]}" if sock.family == socket.AF_INET6 else f"{addr[0]}:{addr[1]}")
    return sockets, addresses, failures


# ── runtime setup (runs BEFORE uvicorn, so failures are loud) ─────────────────
async def _setup_runtime() -> None:
    settings.ensure_writable_data_dir()
    settings.resolve_secret()
    try:
        await init_db()
    except Exception as exc:  # noqa: BLE001 - volume/db problem, try the fallback
        if settings.data_dir == settings.data_dir_fallback:
            raise
        await dispose_engine()
        settings.secret_key = ""
        settings.use_fallback_data_dir(f"database could not be opened ({type(exc).__name__}: {exc})")
        settings.resolve_secret()
        await init_db()
    await seed_first_run()
    # The pre-flight engine lives in this (throwaway) event loop — dispose it so
    # the server event loop builds fresh aiosqlite connections.
    await dispose_engine()


def _preflight() -> None:
    """Prepare dirs, signing key and database schema before serving traffic."""
    import asyncio

    asyncio.run(_setup_runtime())
    BOOT_STATE["warning"] = settings.data_warning or None
    BOOT_STATE["data_dir"] = str(settings.data_dir)


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


async def _self_probe() -> None:
    """Ask ourselves for /healthz on every bound port — proves we really serve."""
    import asyncio

    import httpx

    await asyncio.sleep(1.5)
    for port in BOOT_STATE["ports"]:  # type: ignore[union-attr]
        for host in ("127.0.0.1", "[::1]"):
            url = f"http://{host}:{port}/healthz"
            try:
                async with httpx.AsyncClient(timeout=4, trust_env=False) as client:
                    response = await client.get(url)
                logger.info("self-check %s → HTTP %s ✔", url, response.status_code)
            except Exception as exc:  # noqa: BLE001 - diagnostics only
                logger.warning("self-check %s failed: %s", url, exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    try:
        # Pre-flight already did this once; repeated here so that restarts and
        # bare ``uvicorn app.main:app`` runs work exactly the same way.
        settings.ensure_writable_data_dir()
        settings.resolve_secret()
        await init_db()
        await seed_first_run()
    except Exception as exc:  # noqa: BLE001 - must never exit silently
        BOOT_STATE["fatal"] = f"{type(exc).__name__}: {exc}"
        logger.exception("FATAL: application startup failed")
        raise

    workers.start_workers()
    logger.info("%s v%s ready (DATA_DIR=%s)", settings.app_name, settings.version, settings.data_dir)
    probe = asyncio.create_task(_self_probe(), name="titan-self-probe")
    try:
        yield
    finally:
        probe.cancel()
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


@app.middleware("http")
async def trace_requests(request: Request, call_next):
    """Log the first requests and remember which local port they hit.

    That port is the ground truth for Railway's *target port*, which is the
    single most common cause of "Application failed to respond".
    """
    response = await call_next(request)

    server = request.scope.get("server") or ("", 0)
    port = server[1]
    BOOT_STATE["requests"] = int(BOOT_STATE["requests"]) + 1  # type: ignore[arg-type]
    seen = BOOT_STATE.setdefault("ports_seen", [])
    if isinstance(seen, list) and port not in seen:
        seen.append(port)

    count = int(BOOT_STATE["requests"])  # type: ignore[arg-type]
    if count <= 5 or count % 200 == 0:
        logger.info(
            "request #%d %s %s → %s (arrived on port %s, host=%s, proto=%s)",
            count,
            request.method,
            request.url.path,
            response.status_code,
            port,
            request.headers.get("host", "-"),
            request.headers.get("x-forwarded-proto", "-"),
        )
    return response


@app.get("/healthz", include_in_schema=False)
async def healthz():
    """Liveness probe used by Railway / Docker / uptime monitors."""
    return {
        "ok": BOOT_STATE["fatal"] is None,
        "app": settings.app_name,
        "version": settings.version,
        "time": utcnow().isoformat(),
        "listen": BOOT_STATE["addresses"],
        "ports_used_by_proxy": BOOT_STATE["ports_seen"],
        "requests": BOOT_STATE["requests"],
        "data_dir": str(settings.data_dir),
        "warning": BOOT_STATE["warning"],
        "fatal": BOOT_STATE["fatal"],
        "workers": workers.worker_state(),
    }


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith(("/api", "/sub", "/s/", "/qr")):
        return JSONResponse({"ok": False, "message": "not found"}, status_code=404)
    from fastapi.responses import RedirectResponse

    return RedirectResponse("/", status_code=303)


# ── process entrypoint ────────────────────────────────────────────────────────
RAILWAY_KEYS = (
    "RAILWAY_PUBLIC_DOMAIN",
    "RAILWAY_PRIVATE_DOMAIN",
    "RAILWAY_TCP_PROXY_PORT",
    "RAILWAY_TCP_APPLICATION_PORT",
    "RAILWAY_SERVICE_NAME",
    "RAILWAY_ENVIRONMENT_NAME",
    "RAILWAY_PROJECT_NAME",
    "RAILWAY_REPLICA_ID",
)


def _log_boot_banner() -> None:
    logger.info("=" * 72)
    logger.info("TiTaN Panel v%s · python %s", settings.version, __import__("sys").version.split()[0])
    logger.info("PORT=%s  EXTRA_PORTS=%s  HOST=%s  DATA_DIR=%s", os.environ.get("PORT", "(unset)"), os.environ.get("EXTRA_PORTS", "(unset)"), settings.host, settings.data_dir)
    for key in RAILWAY_KEYS:
        value = os.environ.get(key)
        if value:
            logger.info("%s=%s", key, value)
    logger.info("=" * 72)


def _log_listen_banner(addresses: list[str], failures: list[str]) -> None:
    logger.info("=" * 72)
    logger.info("TiTaN is listening on: %s", "  ".join(addresses))
    logger.info("Set the Railway/Fly public-domain target port to one of: %s", " or ".join(str(p) for p in BOOT_STATE["ports"]))
    if failures:
        logger.warning("ports that failed to bind: %s", ", ".join(failures))
    logger.info("=" * 72)


def main() -> None:
    """Start the panel (with a watchdog so a silent exit can never happen)."""
    import asyncio
    import sys
    import time

    import uvicorn

    _log_boot_banner()

    try:
        _preflight()
    except Exception:
        logger.exception("FATAL: could not prepare runtime (data dir / database) — see traceback above")
        sys.exit(1)

    if not settings.data_dir.exists():
        logger.error("FATAL: data directory %s does not exist", settings.data_dir)
        sys.exit(1)

    sockets, addresses, failures = _bind_all()
    if not sockets:
        logger.error("FATAL: no port could be bound (%s)", "; ".join(failures) or "unknown error")
        sys.exit(2)

    BOOT_STATE["addresses"] = addresses
    BOOT_STATE["ports"] = sorted({sock.getsockname()[1] for sock in sockets})
    _log_listen_banner(addresses, failures)

    attempt = 0
    while True:
        attempt += 1
        BOOT_STATE["restarts"] = attempt - 1
        config = uvicorn.Config(
            app,
            log_level="info",
            proxy_headers=True,
            forwarded_allow_ips="*",
            access_log=False,
            timeout_graceful_shutdown=10,
        )
        server = uvicorn.Server(config)
        try:
            asyncio.run(server.serve(sockets=sockets))
        except KeyboardInterrupt:
            logger.info("interrupted by user — shutting down")
            break

        if BOOT_STATE["fatal"]:
            # uvicorn swallowed the startup failure and returned "successfully";
            # exit non-zero so Railway marks the deploy Crashed and restarts it.
            logger.error("startup failed (%s) — exiting with code 1", BOOT_STATE["fatal"])
            sys.exit(1)

        if server.should_exit:
            logger.info("shutdown requested — exiting cleanly")
            break

        if attempt >= 5:
            logger.error("server loop exited unexpectedly %d times — giving up", attempt)
            sys.exit(3)

        logger.error("server loop returned unexpectedly (attempt %d) — restarting in 2s", attempt)
        time.sleep(2)
        BOOT_STATE["fatal"] = None
        for sock in sockets:  # sockets are closed by uvicorn on shutdown; rebind
            try:
                sock.close()
            except OSError:
                pass
        sockets, addresses, failures = _bind_all()
        BOOT_STATE["addresses"] = addresses
        BOOT_STATE["ports"] = sorted({sock.getsockname()[1] for sock in sockets})
        _log_listen_banner(addresses, failures)
        if not sockets:
            logger.error("FATAL: no port could be bound after restart")
            sys.exit(2)


if __name__ == "__main__":
    main()
