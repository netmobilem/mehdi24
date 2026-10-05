"""Smoke test: boots the panel in-process, seeds demo data and hits every route.

    python3 scripts/smoke.py

Exits non-zero on the first unexpected status code, prints a compact report.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile

DATA_DIR = os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="titan-smoke-"))
os.environ.setdefault("ADMIN_PASSWORD", "admin")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402

from app.main import app, seed_first_run  # noqa: E402
from app.database import dispose_engine, init_db  # noqa: E402

PUBLIC = ["/login", "/healthz", "/sub/does-not-exist", "/s/does-not-exist"]
PROTECTED = [
    "/",
    "/?range=24h",
    "/?range=30d",
    "/users",
    "/users?q=ali&status=active",
    "/inbounds",
    "/nodes",
    "/subscriptions",
    "/reports",
    "/reports?days=30",
    "/reports/export.csv?days=7",
    "/stats",
    "/settings",
    "/admins",
    "/api/dashboard",
    "/api/docs",
]

FAILED: list[str] = []


async def main() -> int:
    await init_db()
    await seed_first_run()

    # demo data
    sys.argv = ["seed", "--reset"]
    from app.seed import seed

    await seed(reset=True, force=True)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://titan.test", follow_redirects=False) as client:
        print("── public routes ─────────────────────────────────────────────")
        for path in PUBLIC:
            response = await client.get(path)
            ok = response.status_code in (200, 404, 401)
            print(f"{'✔' if ok else '✘'} {path:<32} {response.status_code}")
            if not ok:
                FAILED.append(f"{path} → {response.status_code}")

        print("── login ────────────────────────────────────────────────────")
        login = await client.post("/login", data={"username": "admin", "password": "admin"})
        print(f"{'✔' if login.status_code in (200, 303) else '✘'} POST /login {login.status_code}")
        if login.status_code not in (200, 303):
            FAILED.append(f"login → {login.status_code}")

        print("── protected pages ──────────────────────────────────────────")
        for path in PROTECTED:
            response = await client.get(path)
            ok = response.status_code == 200
            note = ""
            if not ok:
                note = (response.text or "")[:120].replace("\n", " ")
            print(f"{'✔' if ok else '✘'} {path:<32} {response.status_code} {note}")
            if not ok:
                FAILED.append(f"{path} → {response.status_code} {note}")

        # detail pages need real ids from the seeded database
        print("── detail pages ─────────────────────────────────────────────")
        from sqlalchemy import select

        from app.database import session_scope
        from app.models import Inbound, Node, Subscription, User

        async with session_scope() as session:
            user_id = (await session.execute(select(User.id).order_by(User.id))).scalars().first()
            node_id = (await session.execute(select(Node.id).order_by(Node.id))).scalars().first()
            inbound_id = (await session.execute(select(Inbound.id).order_by(Inbound.id))).scalars().first()
            sub_token = (await session.execute(select(Subscription.token))).scalars().first()

        for path in (
            f"/users/{user_id}/links",
            f"/nodes/{node_id}",
            f"/nodes/{node_id}/script",
            f"/inbounds/{inbound_id}/links",
            f"/inbounds/{inbound_id}/preview",
            f"/sub/{sub_token}",
            f"/s/{sub_token}",
            f"/sub/{sub_token}/clash.yaml",
            f"/sub/{sub_token}/json",
        ):
            response = await client.get(path)
            ok = response.status_code == 200
            note = "" if ok else (response.text or "")[:120].replace("\n", " ")
            print(f"{'✔' if ok else '✘'} {path:<32} {response.status_code} {note}")
            if not ok:
                FAILED.append(f"{path} → {response.status_code}")

        print("── write endpoints (validation paths) ───────────────────────")
        checks = [
            ("POST /users/create", "post", "/users/create", {"username": "", "limit_value": "0", "limit_unit": "GB"}),
            ("POST /inbounds/create", "post", "/inbounds/create", {"node_id": "999", "protocol": "vless"}),
            ("POST /nodes/create", "post", "/nodes/create", {"name": "", "address": ""}),
            ("POST /subscriptions/create", "post", "/subscriptions/create", {"name": "test", "auto_all": "1"}),
            ("POST /users/1/toggle", "post", f"/users/{user_id}/toggle", {}),
            ("POST /inbounds/{id}/toggle", "post", f"/inbounds/{inbound_id}/toggle", {}),
        ]
        for label, _method, path, payload in checks:
            response = await client.post(path, data=payload)
            body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            ok = response.status_code == 200 and ("ok" in body)
            print(f"{'✔' if ok else '✘'} {label:<32} {response.status_code} {str(body.get('message'))[:60]}")
            if not ok:
                FAILED.append(f"{label} → {response.status_code} {response.text[:100]}")

    await dispose_engine()

    print()
    if FAILED:
        print(f"✘ {len(FAILED)} failure(s):")
        for item in FAILED:
            print("   -", item)
        return 1
    print("✔ all routes healthy")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
