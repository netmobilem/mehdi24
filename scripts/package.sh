#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  TiTaN Panel · packaging script
#
#  Builds a clean archive you can drop straight into a GitHub repo
#  (no caches, no local database, no secrets).
#
#      bash scripts/package.sh          → dist/titan-panel-<version>.zip
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(python3 -c "import re,pathlib;print(re.search(r'__version__ = \"([^\"]+)\"', pathlib.Path('app/__init__.py').read_text()).group(1))")"
NAME="titan-panel-${VERSION}"
OUT="dist"
STAGE="${OUT}/${NAME}"

echo "› packaging ${NAME}"

rm -rf "$STAGE"
mkdir -p "$STAGE"

# everything a deployment needs — nothing else
cp -R app agent static scripts deploy "$STAGE"/
cp requirements.txt Dockerfile docker-compose.yml railway.json \
   README.md LICENSE Makefile pytest.ini .env.example .gitignore .dockerignore "$STAGE"/
mkdir -p "$STAGE/.github/workflows"
cp .github/workflows/ci.yml "$STAGE/.github/workflows/" 2>/dev/null || true
mkdir -p "$STAGE/docs"
cp docs/ARCHITECTURE.md docs/START-HERE.md "$STAGE/docs/" 2>/dev/null || true
cp docs/dashboard-preview.html "$STAGE/docs/" 2>/dev/null || true

# strip anything local/generated that slipped in
find "$STAGE" -type d \( -name '__pycache__' -o -name '.pytest_cache' -o -name 'var' -o -name '.venv' \) -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -type f \( -name '*.pyc' -o -name '*.db' -o -name '*.db-wal' -o -name '*.key' -o -name '.env' \) -delete 2>/dev/null || true

mkdir -p "$OUT"
( cd "$OUT" && zip -qr "${NAME}.zip" "${NAME}" )
rm -rf "$STAGE"

echo "✔ dist/${NAME}.zip  ($(du -h "dist/${NAME}.zip" | cut -f1))"
echo
echo "  آپلود روی گیت‌هاب:"
echo "    unzip dist/${NAME}.zip && cd ${NAME}"
echo "    git init && git add . && git commit -m 'TiTaN Panel v${VERSION}'"
echo "    git branch -M main && git remote add origin git@github.com:<user>/<repo>.git && git push -u origin main"
