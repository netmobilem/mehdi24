"""TiTaN Panel — data model.

Design notes
------------
* A **Node** is a remote server running the combined *Xray + Nginx* core stack.
* An **Inbound** is one protocol service on a node (VLESS/VMess/Trojan/SS/…)
  bound to a public port, fronted by Nginx for TLS where needed.
* A **User** is an account with quota / expiry / ip-limit / speed-limit.
* A **Subscription** groups several users+inbounds behind one shareable link.
* **TrafficSample** keeps per-user hourly deltas so charts stay cheap.
"""

from __future__ import annotations

import enum
import secrets
import uuid as uuid_lib
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)[:length]


def new_uuid() -> str:
    return str(uuid_lib.uuid4())


class Base(DeclarativeBase):
    pass


# ── enums ────────────────────────────────────────────────────────────────────
class NodeStatus(str, enum.Enum):
    ONLINE = "online"
    CONNECTING = "connecting"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    INSTALLING = "installing"
    ERROR = "error"


class AdminRole(str, enum.Enum):
    OWNER = "owner"        # مدیر کل
    ADMIN = "admin"        # ادمین
    RESELLER = "reseller"  # نماینده
    VIEWER = "viewer"      # فقط‌خواندنی


class Protocol(str, enum.Enum):
    VLESS = "vless"
    VMESS = "vmess"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    HYSTERIA2 = "hysteria2"
    WIREGUARD = "wireguard"


class Transport(str, enum.Enum):
    WS = "ws"
    XHTTP = "xhttp"
    GRPC = "grpc"
    TCP = "tcp"
    HTTPUPGRADE = "httpupgrade"
    QUIC = "quic"


class Security(str, enum.Enum):
    TLS = "tls"
    REALITY = "reality"
    NONE = "none"


class XhttpMode(str, enum.Enum):
    PACKET_UP = "packet-up"
    STREAM_UP = "stream-up"
    STREAM_ONE = "stream-one"
    AUTO = "auto"


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    EXPIRED = "expired"
    LIMITED = "limited"      # traffic exhausted
    ONHOLD = "onhold"        # not started yet


class ResetStrategy(str, enum.Enum):
    NEVER = "never"
    MONTHLY = "monthly"
    WEEKLY = "weekly"
    DAILY = "daily"


# ── admin & sessions ─────────────────────────────────────────────────────────
class Admin(Base):
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(128), default="")
    role: Mapped[AdminRole] = mapped_column(Enum(AdminRole), default=AdminRole.ADMIN)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    telegram_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    sessions: Mapped[list["AdminSession"]] = relationship(back_populates="admin", cascade="all, delete-orphan")

    @property
    def role_label(self) -> str:
        return {
            AdminRole.OWNER: "مدیر کل",
            AdminRole.ADMIN: "ادمین",
            AdminRole.RESELLER: "نماینده",
            AdminRole.VIEWER: "مشاهده‌گر",
        }.get(self.role, "ادمین")


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="CASCADE"))
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)

    admin: Mapped[Admin] = relationship(back_populates="sessions")


# ── nodes ────────────────────────────────────────────────────────────────────
class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    address: Mapped[str] = mapped_column(String(255), comment="دامنه‌ی عمومی نود")
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int] = mapped_column(Integer, default=443, comment="پورت عمومی TLS/nginx")
    country_code: Mapped[str] = mapped_column(String(4), default="")
    country_name: Mapped[str] = mapped_column(String(64), default="")
    city: Mapped[str] = mapped_column(String(64), default="")
    flag: Mapped[str] = mapped_column(String(8), default="🌐")

    # agent
    agent_port: Mapped[int] = mapped_column(Integer, default=62050)
    agent_token: Mapped[str] = mapped_column(String(128), default=new_token)
    agent_scheme: Mapped[str] = mapped_column(String(8), default="http")
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # ssh bootstrap
    ssh_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_user: Mapped[str] = mapped_column(String(64), default="root")
    ssh_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssh_key_path: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # health & metrics
    status: Mapped[NodeStatus] = mapped_column(Enum(NodeStatus), default=NodeStatus.CONNECTING)
    status_message: Mapped[str] = mapped_column(String(255), default="")
    xray_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    nginx_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    os_info: Mapped[str] = mapped_column(String(128), default="")
    cpu_cores: Mapped[int] = mapped_column(Integer, default=1)
    cpu_pct: Mapped[float] = mapped_column(Float, default=0.0)
    ram_total: Mapped[int] = mapped_column(BigInteger, default=0)
    ram_used: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_total: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_used: Mapped[int] = mapped_column(BigInteger, default=0)
    traffic_up: Mapped[int] = mapped_column(BigInteger, default=0)
    traffic_down: Mapped[int] = mapped_column(BigInteger, default=0)
    uptime_sec: Mapped[int] = mapped_column(BigInteger, default=0)
    ping_ms: Mapped[int] = mapped_column(Integer, default=0, comment="پینگ پنل تا نود")
    load_avg: Mapped[str] = mapped_column(String(32), default="")

    # feature flags
    reality_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hysteria2_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    wireguard_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cert_issuer: Mapped[str | None] = mapped_column(String(64), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    config_dirty: Mapped[bool] = mapped_column(Boolean, default=True, comment="نیازمند استقرار مجدد")
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    inbounds: Mapped[list["Inbound"]] = relationship(back_populates="node", cascade="all, delete-orphan")

    @property
    def ram_pct(self) -> float:
        return round(self.ram_used / self.ram_total * 100, 1) if self.ram_total else 0.0

    @property
    def disk_pct(self) -> float:
        return round(self.disk_used / self.disk_total * 100, 1) if self.disk_total else 0.0

    @property
    def ram_total_human(self) -> str:
        return human_bytes(self.ram_total)

    @property
    def disk_total_human(self) -> str:
        return human_bytes(self.disk_total)


# ── inbounds (protocol services) ─────────────────────────────────────────────
class Inbound(Base):
    __tablename__ = "inbounds"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    note: Mapped[str] = mapped_column(Text, default="")

    protocol: Mapped[Protocol] = mapped_column(Enum(Protocol), default=Protocol.VLESS)
    transport: Mapped[Transport] = mapped_column(Enum(Transport), default=Transport.WS)
    security: Mapped[Security] = mapped_column(Enum(Security), default=Security.TLS)

    port: Mapped[int] = mapped_column(Integer, default=443, comment="پورت عمومی")
    internal_port: Mapped[int] = mapped_column(Integer, default=10000, comment="پورت داخلی روی 127.0.0.1")
    path: Mapped[str] = mapped_column(String(128), default="/titan")
    host_header: Mapped[str] = mapped_column(String(255), default="")
    sni: Mapped[str] = mapped_column(String(255), default="")
    alpn: Mapped[str] = mapped_column(String(64), default="http/1.1")
    fingerprint: Mapped[str] = mapped_column(String(32), default="chrome")
    service_name: Mapped[str] = mapped_column(String(64), default="titan-grpc")
    xhttp_mode: Mapped[XhttpMode] = mapped_column(Enum(XhttpMode), default=XhttpMode.AUTO)
    flow: Mapped[str] = mapped_column(String(32), default="")
    allow_insecure: Mapped[bool] = mapped_column(Boolean, default=False)

    # reality
    reality_dest: Mapped[str] = mapped_column(String(255), default="www.cloudflare.com:443")
    reality_server_names: Mapped[str] = mapped_column(String(255), default="www.cloudflare.com")
    reality_private_key: Mapped[str] = mapped_column(String(128), default="")
    reality_public_key: Mapped[str] = mapped_column(String(128), default="")
    reality_short_id: Mapped[str] = mapped_column(String(32), default="")

    # shadowsocks / trojan
    cipher: Mapped[str] = mapped_column(String(32), default="2022-blake3-aes-128-gcm")
    password: Mapped[str] = mapped_column(String(128), default="")
    # wireguard / hysteria2 extras
    extra: Mapped[dict] = mapped_column(JSON, default=dict)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    tag: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    node: Mapped[Node] = relationship(back_populates="inbounds")
    clients: Mapped[list["Client"]] = relationship(back_populates="inbound", cascade="all, delete-orphan")

    @property
    def protocol_label(self) -> str:
        return self.protocol.value.upper()

    @property
    def transport_label(self) -> str:
        return self.transport.value.upper()


# ── users & clients ──────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(128), default="", comment="tag مصرف در Xray stats")
    uuid: Mapped[str] = mapped_column(String(64), default=new_uuid)
    password: Mapped[str] = mapped_column(String(128), default=new_token(16))

    note: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[UserStatus] = mapped_column(Enum(UserStatus), default=UserStatus.ACTIVE)

    data_limit: Mapped[int] = mapped_column(BigInteger, default=0, comment="بایت — 0 یعنی نامحدود")
    used_up: Mapped[int] = mapped_column(BigInteger, default=0)
    used_down: Mapped[int] = mapped_column(BigInteger, default=0)
    ip_limit: Mapped[int] = mapped_column(Integer, default=0, comment="0 = نامحدود")
    speed_limit: Mapped[int] = mapped_column(Integer, default=0, comment="Mbps — 0 = نامحدود")
    reset_strategy: Mapped[ResetStrategy] = mapped_column(Enum(ResetStrategy), default=ResetStrategy.MONTHLY)

    expire_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    sub_token: Mapped[str] = mapped_column(String(64), unique=True, default=lambda: new_token(28))
    telegram_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    last_online_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    online_ips: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(64), default="system")

    clients: Mapped[list["Client"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    subscriptions: Mapped[list["Subscription"]] = relationship(back_populates="owner")

    # ── derived helpers used by templates/API ────────────────────────────────
    @property
    def used(self) -> int:
        return self.used_up + self.used_down

    @property
    def remaining(self) -> int:
        if not self.data_limit:
            return -1
        return max(self.data_limit - self.used, 0)

    @property
    def usage_percent(self) -> float:
        if not self.data_limit:
            return 0.0
        return min(round(self.used / self.data_limit * 100, 1), 100.0)

    @property
    def days_left(self) -> int | None:
        if not self.expire_at:
            return None
        delta = self.expire_at - utcnow()
        return max(delta.days, 0)

    def refresh_status(self) -> UserStatus:
        """Recompute the effective status from quota + expiry."""
        if self.status in (UserStatus.DISABLED,):
            return self.status
        if self.expire_at and self.expire_at <= utcnow():
            self.status = UserStatus.EXPIRED
            return self.status
        if self.data_limit and self.used >= self.data_limit:
            self.status = UserStatus.LIMITED
            return self.status
        if self.status in (UserStatus.EXPIRED, UserStatus.LIMITED, UserStatus.ONHOLD):
            self.status = UserStatus.ACTIVE
        return self.status


class Client(Base):
    """Binds a User to a specific Inbound (the thing Xray actually serves)."""

    __tablename__ = "clients"
    __table_args__ = (UniqueConstraint("user_id", "inbound_id", name="uq_client_user_inbound"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    inbound_id: Mapped[int] = mapped_column(ForeignKey("inbounds.id", ondelete="CASCADE"), index=True)

    uuid: Mapped[str] = mapped_column(String(64), default=new_uuid)
    email_tag: Mapped[str] = mapped_column(String(160), index=True, comment="tag در آمار Xray")
    flow: Mapped[str] = mapped_column(String(32), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped[User] = relationship(back_populates="clients")
    inbound: Mapped[Inbound] = relationship(back_populates="clients")


# ── subscriptions ────────────────────────────────────────────────────────────
class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=lambda: new_token(24))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    owner: Mapped[User | None] = relationship(back_populates="subscriptions")
    items: Mapped[list["SubscriptionItem"]] = relationship(back_populates="subscription", cascade="all, delete-orphan")


class SubscriptionItem(Base):
    __tablename__ = "subscription_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id", ondelete="CASCADE"), index=True)
    inbound_id: Mapped[int] = mapped_column(ForeignKey("inbounds.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    subscription: Mapped[Subscription] = relationship(back_populates="items")
    inbound: Mapped[Inbound] = relationship()
    user: Mapped[User] = relationship()


# ── telemetry ────────────────────────────────────────────────────────────────
class TrafficSample(Base):
    """Hourly per-user delta. Powers the traffic chart and per-user reports."""

    __tablename__ = "traffic_samples"
    __table_args__ = (UniqueConstraint("hour_bucket", "node_id", "email_tag", name="uq_sample_hour_node_tag"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    hour_bucket: Mapped[datetime] = mapped_column(DateTime, index=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    email_tag: Mapped[str] = mapped_column(String(160), index=True)
    up: Mapped[int] = mapped_column(BigInteger, default=0)
    down: Mapped[int] = mapped_column(BigInteger, default=0)


class NodeSample(Base):
    """Hourly per-node traffic totals (independent of users)."""

    __tablename__ = "node_samples"
    __table_args__ = (UniqueConstraint("hour_bucket", "node_id", name="uq_sample_hour_node"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    hour_bucket: Mapped[datetime] = mapped_column(DateTime, index=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    up: Mapped[int] = mapped_column(BigInteger, default=0)
    down: Mapped[int] = mapped_column(BigInteger, default=0)


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    kind: Mapped[str] = mapped_column(String(48), default="info")
    level: Mapped[str] = mapped_column(String(16), default="info")   # info | ok | warn | error
    message: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class NodeTask(Base):
    """Queued/reported command for a node agent (deploy, restart, cert, …)."""

    __tablename__ = "node_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="pending")  # pending|running|done|failed
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(160))
    body: Mapped[str] = mapped_column(Text, default="")
    level: Mapped[str] = mapped_column(String(16), default="info")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ── formatting helpers shared by templates ───────────────────────────────────
_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(value: float | int | None, precision: int = 1) -> str:
    if value is None:
        return "0 B"
    value = float(value)
    if value <= 0:
        return "0 B"
    index = 0
    while value >= 1024 and index < len(_UNITS) - 1:
        value /= 1024.0
        index += 1
    if index == 0:
        return f"{int(value)} B"
    text = f"{value:.{precision}f}".rstrip("0").rstrip(".")
    return f"{text} {_UNITS[index]}"


def parse_bytes(value: float, unit: str) -> int:
    factor = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(unit.upper(), 1)
    return int(value * factor)
