#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  TiTaN Panel · VPS installer
#
#      curl -fsSL https://raw.githubusercontent.com/<you>/titan-panel/main/deploy/install-panel.sh | sudo bash
#
#  Installs the panel as a systemd service behind nginx, with an optional
#  Let's Encrypt certificate. Idempotent: safe to re-run for updates.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PANEL_DIR="${PANEL_DIR:-/opt/titan-panel}"
PANEL_USER="${PANEL_USER:-titan}"
PANEL_PORT="${PANEL_PORT:-8000}"
DOMAIN="${DOMAIN:-}"
LE_EMAIL="${LE_EMAIL:-}"
REPO_URL="${REPO_URL:-}"

log() { printf '\033[1;35m›\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m✖\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "این اسکریپت باید با root اجرا شود"

log "نصب پیش‌نیازها"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx curl ca-certificates git ufw >/dev/null

log "ساخت کاربر سرویس ($PANEL_USER)"
id -u "$PANEL_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$PANEL_USER"

if [[ -n "$REPO_URL" ]]; then
  log "دریافت کد از $REPO_URL"
  if [[ -d "$PANEL_DIR/.git" ]]; then
    git -C "$PANEL_DIR" pull --ff-only
  else
    git clone --depth 1 "$REPO_URL" "$PANEL_DIR"
  fi
elif [[ ! -f "$PANEL_DIR/app/main.py" ]]; then
  die "کد پنل در $PANEL_DIR پیدا نشد — REPO_URL را تنظیم کنید یا فایل‌ها را دستی کپی کنید"
fi

cd "$PANEL_DIR"

log "ساخت محیط مجازی و نصب وابستگی‌ها"
python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt

log "آماده‌سازی داده‌ها و متغیرهای محیطی"
mkdir -p /var/lib/titan-panel
chown -R "$PANEL_USER:$PANEL_USER" /var/lib/titan-panel "$PANEL_DIR"

if [[ ! -f /etc/titan-panel.env ]]; then
  ADMIN_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 16)"
  cat > /etc/titan-panel.env <<EOF
DATA_DIR=/var/lib/titan-panel
PORT=$PANEL_PORT
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PASSWORD
PANEL_DOMAIN=${DOMAIN:-}
EOF
  chmod 600 /etc/titan-panel.env
  log "رمز ادمین ساخته شد: $ADMIN_PASSWORD  (در /etc/titan-panel.env)"
fi

log "ساخت سرویس systemd"
cat > /etc/systemd/system/titan-panel.service <<UNIT
[Unit]
Description=TiTaN Panel (Xray + Nginx control plane)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$PANEL_USER
WorkingDirectory=$PANEL_DIR
EnvironmentFile=/etc/titan-panel.env
ExecStart=$PANEL_DIR/.venv/bin/python -m app.main
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable titan-panel >/dev/null 2>&1
systemctl restart titan-panel

log "پیکربندی Nginx به‌عنوان reverse proxy"
cat > /etc/nginx/sites-available/titan-panel <<NGINX
server {
    listen 80;
    server_name ${DOMAIN:-_};

    client_max_body_size 64m;
    location / {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/titan-panel /etc/nginx/sites-enabled/titan-panel
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

if [[ -n "$DOMAIN" && -n "$LE_EMAIL" ]]; then
  log "صدور گواهی TLS با certbot"
  apt-get install -y -qq certbot python3-certbot-nginx >/dev/null
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$LE_EMAIL" --redirect || \
    log "certbot ناموفق بود — بعداً دستی اجرا کنید: certbot --nginx -d $DOMAIN"
fi

log "تنظیم فایروال"
ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
echo "y" | ufw enable >/dev/null 2>&1 || true

IP="$(curl -fsS -m 5 https://api.ipify.org || echo '<server-ip>')"
cat <<EOF

✔ TiTaN Panel نصب شد
   آدرس      : http://${DOMAIN:-$IP}$([[ -n "$DOMAIN" ]] && echo "" || echo ":$PANEL_PORT")
   سرویس     : systemctl status titan-panel
   لاگ       : journalctl -u titan-panel -f
   داده‌ها    : /var/lib/titan-panel
   رمز ادمین : در /etc/titan-panel.env

   گام بعدی: وارد پنل شوید → سرورها → افزودن سرور → نصب خودکار روی نود.
EOF
