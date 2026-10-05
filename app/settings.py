"""Central runtime configuration for TiTaN Panel.

Every value can be overridden through environment variables so the very same
image can run on Railway, inside Docker Compose or on a bare VPS.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


def _env_int(key: str, default: int) -> int:
    raw = _env(key)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_list(key: str) -> list[str]:
    raw = _env(key)
    if not raw:
        return []
    return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]


def _env_int_list(key: str, default: str = "") -> list[int]:
    """Parse ``1,2,3`` style env values into ints.

    Unlike :func:`_env`, an env var that is *present and empty* disables the
    feature (``EXTRA_PORTS=`` → no extra ports), while a missing var falls back
    to ``default``.
    """
    raw = os.environ.get(key)
    if raw is None:
        raw = default
    out: list[int] = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            value = int(part)
        except ValueError:
            continue
        if 0 < value <= 65535 and value not in out:
            out.append(value)
    return out


@dataclass(slots=True)
class Settings:
    """Immutable-ish settings container resolved at import time."""

    app_name: str = "TiTaN"
    app_subtitle: str = "Management Panel"
    version: str = "1.0.1"

    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "/data")))
    port: int = field(default_factory=lambda: _env_int("PORT", 8000))
    host: str = field(default_factory=lambda: _env("HOST", "0.0.0.0"))
    # Extra ports the panel also listens on. Railway routes the public domain to
    # a "target port" which is NOT always the same as the injected PORT var, and
    # a mismatch is the #1 cause of the "Application failed to respond" error.
    # Listening on both makes the panel reachable either way; set EXTRA_PORTS=
    # (empty) to disable, or EXTRA_PORTS=8080,3000 to add more.
    extra_ports: list[int] = field(default_factory=lambda: _env_int_list("EXTRA_PORTS", "8080"))

    panel_domain: str = field(default_factory=lambda: _env("PANEL_DOMAIN") or _env("RAILWAY_PUBLIC_DOMAIN"))
    admin_username: str = field(default_factory=lambda: _env("ADMIN_USERNAME", "admin"))
    admin_password: str = field(default_factory=lambda: _env("ADMIN_PASSWORD", "admin"))

    secret_key: str = ""
    session_ttl: int = field(default_factory=lambda: _env_int("SESSION_TTL", 60 * 60 * 24 * 30))
    allowed_ips: list[str] = field(default_factory=lambda: _env_list("PANEL_ALLOWED_IPS"))

    telegram_bot_token: str = field(default_factory=lambda: _env("TELEGRAM_BOT_TOKEN"))
    telegram_admin_ids: list[str] = field(default_factory=lambda: _env_list("TELEGRAM_ADMIN_IDS"))

    # how node health is collected: agent | ssh | mock
    metrics_mode: str = field(default_factory=lambda: _env("NODE_METRICS_MODE", "agent"))

    # agent defaults used when a node is bootstrapped
    agent_port: int = field(default_factory=lambda: _env_int("AGENT_PORT", 62050))
    agent_scheme: str = field(default_factory=lambda: _env("AGENT_SCHEME", "http"))

    # proxy defaults
    default_tls_port: int = 443
    first_internal_port: int = 10000           # xray inbounds live on 127.0.0.1:10000+
    xray_api_port: int = 10085                  # local stats/api inbound
    xray_api_prefix: str = "/titan-api"         # api inbound path
    decoy_root: str = "/var/www/titan-decoy"

    db_file_name: str = "titan.db"
    secret_file_name: str = "titan.key"

    @property
    def data_path(self) -> Path:
        return self.data_dir

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_file_name

    @property
    def database_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "backups").mkdir(parents=True, exist_ok=True)

    def listen_ports(self) -> list[int]:
        """Ordered, de-duplicated list of TCP ports the panel binds."""
        ports: list[int] = []
        for candidate in [self.port, *self.extra_ports]:
            if 0 < candidate <= 65535 and candidate not in ports:
                ports.append(candidate)
        return ports

    def resolve_secret(self) -> str:
        """Load (or create) a stable signing key so sessions survive restarts."""
        if self.secret_key:
            return self.secret_key

        env_secret = _env("SECRET_KEY")
        if env_secret:
            self.secret_key = env_secret
            return self.secret_key

        self.ensure_dirs()
        secret_file = self.data_dir / self.secret_file_name
        try:
            if secret_file.exists():
                stored = secret_file.read_text(encoding="utf-8").strip()
                if stored:
                    self.secret_key = stored
                    return self.secret_key
            generated = secrets.token_urlsafe(48)
            secret_file.write_text(generated, encoding="utf-8")
            os.chmod(secret_file, 0o600)
            self.secret_key = generated
        except OSError:
            # read-only filesystem — fall back to an ephemeral key
            self.secret_key = secrets.token_urlsafe(48)
        return self.secret_key


settings = Settings()
