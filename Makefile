# ── TiTaN Panel · developer shortcuts ────────────────────────────────────────
PY ?= python3
DATA ?= ./var
PORT ?= 8000

.PHONY: help install dev seed test smoke preview docker zip clean

help:
	@echo "make install   نصب وابستگی‌ها"
	@echo "make dev       اجرای پنل روی پورت $(PORT) با داده‌های $(DATA)"
	@echo "make seed      ساخت داده‌ی نمونه (نود/کاربر/ترافیک)"
	@echo "make test      تست‌های واحد"
	@echo "make smoke     تست دود همه‌ی مسیرها"
	@echo "make preview   ساخت اسنپ‌شات آفلاین داشبورد"
	@echo "make docker    ساخت و اجرای ایمیج با Docker Compose"
	@echo "make zip       ساخت آرشیو برای آپلود روی گیت‌هاب"

install:
	$(PY) -m pip install -r requirements.txt

seed:
	DATA_DIR=$(DATA) $(PY) -m app.seed --reset

dev:
	DATA_DIR=$(DATA) PORT=$(PORT) $(PY) -m app.main

test:
	DATA_DIR=/tmp/titan-tests $(PY) -m pytest tests -q

smoke:
	DATA_DIR=/tmp/titan-smoke $(PY) scripts/smoke.py

preview:
	$(PY) scripts/render_static.py docs/dashboard-preview.html

docker:
	docker compose up -d --build

zip:
	bash scripts/package.sh

clean:
	rm -rf $(DATA) .pytest_cache **/__pycache__ dist/*.zip
