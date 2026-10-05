"""Demo data seeder — makes the dashboard and every page look alive locally.

    python -m app.seed            # add demo nodes/users/traffic
    python -m app.seed --reset    # wipe demo data first

It never touches a panel that already has real nodes unless ``--force`` is given.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import secrets
from datetime import timedelta

from sqlalchemy import delete, select

from .database import dispose_engine, init_db, session_scope
from .models import (
    ActivityLog,
    Client,
    Inbound,
    Node,
    NodeSample,
    NodeStatus,
    Protocol,
    Security,
    Subscription,
    SubscriptionItem,
    TrafficSample,
    Transport,
    User,
    UserStatus,
    XhttpMode,
    new_uuid,
    utcnow,
)
from .services.reality import generate_reality_keypair, generate_short_id, generate_ss_password

DEMO_NODES = [
    ("سرور اصلی", "amsterdam.titan.example", "NL", "Amsterdam", 7, 37, 50),
    ("Singapore", "singapore.titan.example", "SG", "Singapore", 198, 22, 41),
    ("US - Virginia", "virginia.titan.example", "US", "Virginia", 134, 61, 33),
    ("DE - Frankfurt", "frankfurt.titan.example", "DE", "Frankfurt", 15, 12, 28),
]

DEMO_USERS = [
    ("admin", "مدیر کل", 0, 0, 0),
    ("ali", "علی رضایی", 100, 0, 2),
    ("sara", "سارا محمدی", 50, 30, 1),
    ("reza", "رضا کریمی", 200, 7, 3),
    ("maryam", "مریم احمدی", 0, 0, 0),
    ("test", "کاربر تست", 10, 1, 1),
]

PROTO_PLAN = [
    (Protocol.VLESS, Transport.WS, Security.TLS),
    (Protocol.VLESS, Transport.XHTTP, Security.TLS),
    (Protocol.TROJAN, Transport.WS, Security.TLS),
    (Protocol.VMESS, Transport.WS, Security.TLS),
    (Protocol.SHADOWSOCKS, Transport.TCP, Security.NONE),
    (Protocol.VLESS, Transport.GRPC, Security.TLS),
]


async def seed(reset: bool = False, force: bool = False) -> None:
    await init_db()
    async with session_scope() as session:
        existing = (await session.execute(select(Node))).scalars().all()
        if existing and not (reset or force):
            print(f"• {len(existing)} node(s) already exist — use --reset to reseed")
            return

        if reset:
            for model in (TrafficSample, NodeSample, SubscriptionItem, Subscription, Client, Inbound, User, Node, ActivityLog):
                await session.execute(delete(model))
            await session.commit()
            print("• previous demo data cleared")

        # ── nodes ───────────────────────────────────────────────────────────
        nodes: list[Node] = []
        for index, (name, address, code, city, ping, cpu, ram) in enumerate(DEMO_NODES):
            from .services.geo import country_name, flag_for

            node = Node(
                name=name,
                address=address,
                ip=f"10.20.30.{index + 10}",
                port=443,
                country_code=code,
                country_name=country_name(code),
                city=city,
                flag=flag_for(code),
                agent_port=62050,
                status=NodeStatus.ONLINE if index != 3 else NodeStatus.CONNECTING,
                status_message="" if index != 3 else "در حال راه‌اندازی",
                cpu_pct=cpu,
                cpu_cores=random.choice([2, 4, 8]),
                ram_total=random.choice([1024, 2048, 4096]) * 1024 * 1024,
                ram_used=int(random.choice([1024, 2048, 4096]) * 1024 * 1024 * ram / 100),
                disk_total=40 * 1024**3,
                disk_used=int(40 * 1024**3 * random.uniform(0.18, 0.62)),
                uptime_sec=random.randint(86_400, 3_000_000),
                ping_ms=ping,
                load_avg=f"{random.uniform(0.1, 1.8):.2f} {random.uniform(0.1, 1.8):.2f} {random.uniform(0.1, 1.8):.2f}",
                xray_version="Xray 25.4.30 (Xray, Penetrates Everything.)",
                nginx_version="nginx/1.26.2",
                agent_version="1.0.0",
                os_info="Linux Ubuntu 24.04",
                cert_expires_at=utcnow() + timedelta(days=random.randint(20, 80)),
                cert_issuer="Let's Encrypt R11",
                last_seen=utcnow(),
                sort_order=index,
            )
            session.add(node)
            nodes.append(node)
        await session.flush()

        # ── inbounds ────────────────────────────────────────────────────────
        inbounds: list[Inbound] = []
        port = 10000
        direct_pool = [8443, 2053, 2083, 2087, 2096, 2095, 8880, 9443]
        for node_index, node in enumerate(nodes):
            for plan_index, (protocol, transport, security) in enumerate(PROTO_PLAN):
                if node_index == 3 and plan_index > 1:
                    continue
                port += 1
                # raw-TCP / UDP inbounds own a dedicated public port; http-ish ones
                # ride on nginx (443) through their local path.
                public_port = direct_pool.pop(0) if transport in (Transport.TCP, Transport.QUIC) and direct_pool else node.port
                private, public = (generate_reality_keypair() if security is Security.REALITY else ("", ""))
                inbound = Inbound(
                    node_id=node.id,
                    name=f"{protocol.value.upper()}-{transport.value.upper()}",
                    protocol=protocol,
                    transport=transport,
                    security=security,
                    port=public_port,
                    internal_port=port,
                    path=f"/titan/{transport.value}",
                    host_header=node.address,
                    sni=node.address,
                    alpn="http/1.1" if transport is Transport.WS else "h2,http/1.1",
                    fingerprint=random.choice(["chrome", "firefox", "safari", "ios", "randomized"]),
                    xhttp_mode=XhttpMode.AUTO,
                    cipher="2022-blake3-aes-128-gcm",
                    password=generate_ss_password() if protocol is Protocol.SHADOWSOCKS else "",
                    reality_private_key=private,
                    reality_public_key=public,
                    reality_short_id=generate_short_id() if security is Security.REALITY else "",
                    is_active=True,
                )
                session.add(inbound)
                inbounds.append(inbound)
        await session.flush()

        # ── users + clients ─────────────────────────────────────────────────
        users: list[User] = []
        for username, display, limit_gb, expire_days, ip_limit in DEMO_USERS:
            uuid_value = new_uuid()
            user = User(
                username=username,
                display_name=display,
                email=f"{username}@titan",
                uuid=uuid_value,
                password=secrets.token_urlsafe(12),
                status=UserStatus.ACTIVE,
                data_limit=limit_gb * 1024**3,
                ip_limit=ip_limit,
                speed_limit=random.choice([0, 0, 50, 100]),
                expire_at=utcnow() + timedelta(days=expire_days) if expire_days else None,
                activated_at=utcnow() - timedelta(days=random.randint(1, 20)),
                last_online_at=utcnow() - timedelta(minutes=random.randint(0, 90)),
                last_ip=f"5.238.{random.randint(1, 254)}.{random.randint(1, 254)}",
                online_ips=[f"5.238.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(random.randint(0, 3))],
                created_by="seed",
                created_at=utcnow() - timedelta(days=random.randint(1, 40)),
            )
            session.add(user)
            users.append(user)
        await session.flush()

        for user in users:
            for inbound in random.sample(inbounds, k=min(len(inbounds), random.randint(2, 4))):
                session.add(
                    Client(
                        user_id=user.id,
                        inbound_id=inbound.id,
                        uuid=user.uuid,
                        email_tag=f"{user.username}-{inbound.id}",
                        is_active=True,
                    )
                )

        # ── traffic history (30 days hourly-ish) ────────────────────────────
        now = utcnow().replace(minute=0, second=0, microsecond=0)
        for node in nodes:
            base = random.randint(80 * 1024**2, 400 * 1024**2)
            for hours_ago in range(0, 24 * 30, 2):
                bucket = now - timedelta(hours=hours_ago)
                scale = 1 + (hours_ago / (24 * 30)) * 0.8
                up = int(base * random.uniform(0.25, 0.6) * scale)
                down = int(base * random.uniform(1.0, 2.4) * scale)
                session.add(NodeSample(hour_bucket=bucket, node_id=node.id, up=up, down=down))
                for user in random.sample(users, k=random.randint(1, 3)):
                    session.add(
                        TrafficSample(
                            hour_bucket=bucket,
                            node_id=node.id,
                            user_id=user.id,
                            email_tag=f"{user.username}-{random.choice([i.id for i in inbounds if i.node_id == node.id])}",
                            up=int(up * random.uniform(0.05, 0.3)),
                            down=int(down * random.uniform(0.05, 0.3)),
                        )
                    )

        # node totals
        for node in nodes:
            node.traffic_up = random.randint(2 * 1024**3, 9 * 1024**3)
            node.traffic_down = random.randint(8 * 1024**3, 40 * 1024**3)
            session.add(node)

        # ── subscription group ──────────────────────────────────────────────
        group = Subscription(name="پکیج ویژه TiTaN", note="گروه نمونه", is_active=True)
        session.add(group)
        await session.flush()
        for inbound in inbounds[:4]:
            session.add(SubscriptionItem(subscription_id=group.id, inbound_id=inbound.id, user_id=users[1].id))

        # ── activity log ────────────────────────────────────────────────────
        events = [
            ("login", "ok", "ورود به پنل توسط مدیر کل"),
            ("config", "ok", "ایجاد کانفیگ جدید"),
            ("subscription", "ok", "اشتراک جدید فعال شد"),
            ("create", "ok", "کاربر جدید ثبت شد"),
            ("node", "ok", "سرور آمستردام مستقر شد"),
        ]
        for index, (kind, level, message) in enumerate(events):
            session.add(
                ActivityLog(
                    actor="admin",
                    kind=kind,
                    level=level,
                    message=message,
                    created_at=utcnow() - timedelta(minutes=index * 13 + 2),
                )
            )

        await session.commit()
        print(f"✔ seeded {len(nodes)} nodes · {len(inbounds)} inbounds · {len(users)} users · 30 days of traffic")


async def _main() -> None:
    parser = argparse.ArgumentParser(description="TiTaN demo seeder")
    parser.add_argument("--reset", action="store_true", help="clear demo tables first")
    parser.add_argument("--force", action="store_true", help="seed even if nodes exist")
    args = parser.parse_args()
    await seed(reset=args.reset, force=args.force)
    await dispose_engine()


if __name__ == "__main__":
    asyncio.run(_main())
