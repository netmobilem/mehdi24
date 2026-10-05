"""Render a standalone, offline-viewable HTML snapshot of the dashboard.

    python3 scripts/render_static.py [output.html]

Boots the panel in-process against a throw-away database, seeds demo data,
signs in as admin, fetches `/` and inlines the stylesheet so the file can be
opened anywhere (no server, no network).
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="titan-preview-"))
os.environ.setdefault("ADMIN_PASSWORD", "admin")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import httpx  # noqa: E402

from app.main import app, seed_first_run  # noqa: E402
from app.database import dispose_engine, init_db  # noqa: E402


async def main() -> int:
    output = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs", "dashboard-preview.html")

    await init_db()
    await seed_first_run()

    from app.seed import seed

    await seed(reset=True, force=True)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://panel.local") as client:
        await client.post("/login", data={"username": "admin", "password": "admin"})
        page = await client.get("/")
        css = await client.get("/static/css/titan.css")
        js = await client.get("/static/js/titan.js")

    html = page.text
    html = html.replace('<link rel="stylesheet" href="/static/css/titan.css" />', f"<style>\n{css.text}\n</style>")
    html = html.replace('<script src="/static/js/titan.js"></script>', f"<script>\n{js.text}\n</script>")
    html = html.replace("</head>", (
        "<!-- Offline snapshot rendered by scripts/render_static.py — assets inlined. -->\n</head>"
    ))

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        handle.write(html)

    await dispose_engine()
    print(f"✔ snapshot written to {output} ({len(html) / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
