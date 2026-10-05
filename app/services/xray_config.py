"""TiTaN Panel — Xray + Nginx core configuration generator.

The combined core works like this::

    client ──TLS──>  nginx (443, stream:ssl_preread)
                       ├─ SNI = reality/trojan/raw-tls host ──> xray inbound (raw TLS / REALITY)
                       └─ default ──> nginx http (8443, TLS term + decoy site)
                                        └─ /path (ws|xhttp|grpc|httpupgrade) ──> xray inbound

* Nginx owns certificates, ALPN, HTTP/2, the decoy website and anti-probing.
* Xray owns the proxy protocols and does the actual tunnelling.
* ``proxy_protocol`` is enabled on every hop so Xray/backend always sees the
  **real client IP** (required for IP-limits, per-IP accounting and fair usage).
* Every tunable below is performance oriented (BBR, TFO, epoll, keepalive,
  no buffering on proxied paths) so throughput and latency stay best-in-class.
"""

from __future__ import annotations

import json
from typing import Iterable

from ..models import Inbound, Node, Protocol, Security, Transport, XhttpMode
from ..settings import settings

# ── tunables ─────────────────────────────────────────────────────────────────
TLS_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)
TLS13_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

DEFAULT_DECOY_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Welcome to nginx!</title><style>body{font-family:system-ui;margin:8% auto;max-width:640px;color:#222}</style>
</head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is
successfully installed and working. Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p></body></html>"""


def _sockopt(*, accept_proxy_protocol: bool, tfo: bool = True) -> dict:
    return {
        "acceptProxyProtocol": accept_proxy_protocol,
        "tcpFastOpen": tfo,
        "tcpNoDelay": True,
        "tcpKeepAliveInterval": 15,
        "tcpKeepAliveIdle": 60,
        "tcpcongestion": "bbr",
        "domainStrategy": "UseIPv4v6",
        "mark": 255,
    }


def _client_entry(client, inbound: Inbound) -> dict:
    """Build the Xray client object for a bound panel Client."""
    user = client.user
    email = client.email_tag or f"{user.username}-{inbound.id}"
    base = {
        "id": client.uuid,
        "email": email,
        "level": 0,
    }
    if inbound.protocol is Protocol.VMESS:
        base = {
            "id": client.uuid,
            "alterId": 0,
            "email": email,
            "level": 0,
        }
        return base
    if inbound.protocol is Protocol.TROJAN:
        base = {
            "password": user.password,
            "email": email,
            "level": 0,
        }
        return base
    if inbound.protocol is Protocol.SHADOWSOCKS:
        base = {
            "password": inbound.password or user.password,
            "email": email,
            "level": 0,
        }
        return base
    # vless
    if inbound.flow:
        base["flow"] = inbound.flow
    return base


# Transports that travel inside an HTTP/2 or HTTP/1.1 request → nginx terminates TLS.
FRONTED_TRANSPORTS = (Transport.WS, Transport.XHTTP, Transport.GRPC, Transport.HTTPUPGRADE)
# Transports that are a raw byte stream / UDP → they own a public port themselves.
DIRECT_TRANSPORTS = (Transport.TCP, Transport.QUIC)


def routing_mode(inbound: Inbound) -> str:
    """Where this inbound lives in the combined core.

    ``fronted``      → nginx http terminates TLS, proxies the path to 127.0.0.1
    ``passthrough``  → nginx stream routes the SNI through untouched (REALITY)
    ``direct``       → xray owns a dedicated public port (raw TCP / QUIC)
    """
    if inbound.security is Security.REALITY:
        return "passthrough"
    if inbound.transport in DIRECT_TRANSPORTS:
        return "direct"
    if inbound.security is Security.TLS:
        return "fronted"
    return "direct"


def listen_port(inbound: Inbound) -> int:
    mode = routing_mode(inbound)
    return inbound.port if mode == "direct" else inbound.internal_port


def listen_address(inbound: Inbound) -> str:
    return "0.0.0.0" if routing_mode(inbound) == "direct" else "127.0.0.1"


def _stream_settings(inbound: Inbound, node: Node) -> dict:
    """Transport + security block for one inbound (all performance flags set)."""
    transport = inbound.transport
    network = {
        Transport.WS: "ws",
        Transport.XHTTP: "xhttp",
        Transport.GRPC: "grpc",
        Transport.TCP: "tcp",
        Transport.HTTPUPGRADE: "httpupgrade",
        Transport.QUIC: "quic",
    }.get(transport, "tcp")

    mode = routing_mode(inbound)
    # fronted inbounds reach xray as plain http(1.1) over loopback
    if mode == "fronted":
        security = "none"
    elif mode == "passthrough":
        security = "reality"
    else:
        security = {Security.TLS: "tls", Security.REALITY: "reality", Security.NONE: "none"}[inbound.security]

    stream: dict = {
        "network": network,
        "security": security,
        "sockopt": _sockopt(accept_proxy_protocol=True),
    }

    if stream["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": inbound.sni or node.address,
            "alpn": [a.strip() for a in (inbound.alpn or "http/1.1").split(",") if a.strip()],
            "certificates": [
                {
                    "certificateFile": f"/etc/titan/tls/fullchain.pem",
                    "keyFile": f"/etc/titan/tls/privkey.pem",
                    "ocspStapling": 3600,
                }
            ],
            "minVersion": "1.2",
            "cipherSuites": TLS_CIPHERS,
        }
    elif stream["security"] == "reality":
        stream["realitySettings"] = {
            "show": False,
            "dest": inbound.reality_dest or f"{node.address}:443",
            "xver": 1,
            "serverNames": [s.strip() for s in (inbound.reality_server_names or node.address).split(",") if s.strip()],
            "privateKey": inbound.reality_private_key,
            "shortIds": [inbound.reality_short_id] if inbound.reality_short_id else [""],
            "maxTimeDiff": 0,
        }

    if network == "ws":
        stream["wsSettings"] = {
            "path": inbound.path or "/titan",
            "host": inbound.host_header or inbound.sni or node.address,
            "heartbeatPeriod": 15,
            "acceptProxyProtocol": True,
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": inbound.path or "/titan",
            "host": inbound.host_header or node.address,
            "acceptProxyProtocol": True,
        }
    elif network == "xhttp":
        mode = {
            XhttpMode.PACKET_UP: "packet-up",
            XhttpMode.STREAM_UP: "stream-up",
            XhttpMode.STREAM_ONE: "stream-one",
            XhttpMode.AUTO: "auto",
        }.get(inbound.xhttp_mode, "auto")
        stream["xhttpSettings"] = {
            "path": inbound.path or "/titan",
            "host": inbound.host_header or node.address,
            "mode": mode,
            "extra": {"xPaddingBytes": "100-1000", "scMaxBufferedPosts": 30},
        }
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": inbound.service_name or "titan-grpc",
            "multiMode": False,
            "idle_timeout": 60,
            "health_check_timeout": 20,
            "permit_without_stream": False,
        }
    elif network == "tcp" and inbound.protocol is Protocol.VLESS and not inbound.flow:
        stream["tcpSettings"] = {"acceptProxyProtocol": True, "header": {"type": "none"}}
    elif network == "tcp":
        stream["tcpSettings"] = {"acceptProxyProtocol": True, "header": {"type": "none"}}
    elif network == "quic":
        stream["quicSettings"] = {
            "security": inbound.password or "none",
            "key": inbound.path or "/titan",
            "header": {"type": "none"},
        }

    return stream


def build_inbound(inbound: Inbound, node: Node, clients: Iterable) -> dict:
    """One Xray inbound object (with all clients bound to it)."""
    entries = [_client_entry(c, inbound) for c in clients if c.is_active]

    settings_block: dict
    if inbound.protocol in (Protocol.VLESS,):
        settings_block = {
            "clients": entries,
            "decryption": "none",
            "fallbacks": [],
        }
    elif inbound.protocol is Protocol.VMESS:
        settings_block = {"clients": entries}
    elif inbound.protocol is Protocol.TROJAN:
        settings_block = {"clients": entries, "fallbacks": []}
    elif inbound.protocol is Protocol.SHADOWSOCKS:
        settings_block = {
            "clients": entries,
            "network": "tcp,udp",
        }
    else:
        settings_block = {"clients": entries}

    if inbound.protocol is Protocol.SHADOWSOCKS:
        settings_block["method"] = inbound.cipher or "2022-blake3-aes-128-gcm"

    tag = inbound.tag or f"inbound-{inbound.id}"

    return {
        "tag": tag,
        "listen": listen_address(inbound),
        "port": listen_port(inbound),
        "protocol": inbound.protocol.value,
        "settings": settings_block,
        "streamSettings": _stream_settings(inbound, node),
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic", "fakedns"],
            "metadataOnly": False,
            "routeOnly": False,
        },
    }


def build_xray_config(node: Node, inbounds: list[Inbound], clients_by_inbound: dict[int, list]) -> dict:
    """Full /usr/local/etc/xray/config.json for a node."""
    api_tag = "titan-api"
    active = [i for i in inbounds if i.is_active and i.protocol not in (Protocol.HYSTERIA2, Protocol.WIREGUARD)]

    inbound_objects = [build_inbound(i, node, clients_by_inbound.get(i.id, [])) for i in active]
    inbound_tags = [i["tag"] for i in inbound_objects]

    # ── routing rules ───────────────────────────────────────────────────────
    rules: list[dict] = [
        # never proxy traffic aimed at the node itself (prevents loops / probing)
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
        {"type": "field", "domain": ["geosite:private"], "outboundTag": "blocked"},
        # block common abuse categories
        {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "blocked"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
    ]
    rules.append({"type": "field", "inboundTag": inbound_tags or ["none"], "outboundTag": "direct"})

    config: dict = {
        "log": {"loglevel": "warning", "access": "/var/log/titan/xray-access.log", "error": "/var/log/titan/xray-error.log", "dnsLog": False},
        "stats": {},
        "api": {
            "tag": api_tag,
            "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"],
        },
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "connIdle": 300,
                    "handshake": 4,
                    "uplinkOnly": 0,
                    "downlinkOnly": 0,
                    "bufferSize": 512,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [
            *inbound_objects,
            {
                "tag": api_tag,
                "listen": "127.0.0.1",
                "port": settings.xray_api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "streamSettings": {"network": "tcp"},
            },
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4v6"}, "streamSettings": {"sockopt": {"mark": 255, "tcpFastOpen": True, "tcpcongestion": "bbr"}}},
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "domainMatcher": "hybrid",
            "rules": rules,
        },
        "dns": {
            "hosts": {
                "dns.google": ["8.8.8.8", "8.8.4.4"],
                "one.one.one.one": ["1.1.1.1", "1.0.0.1"],
            },
            "servers": [
                {"address": "https://1.1.1.1/dns-query", "domains": ["geosite:geolocation-!cn"]},
                {"address": "8.8.8.8"},
            ],
            "tag": "dns-inbound",
            "queryStrategy": "UseIPv4v6",
        },
        "metrics": {"tag": "metrics-out"},
    }
    return config


# ── nginx ────────────────────────────────────────────────────────────────────
def build_nginx_main(node: Node, stream_routes: list[tuple[str, str]] | None = None) -> str:
    """nginx.conf with SNI routing on 443.

    ``stream_routes`` — list of ``(sni, upstream)`` pairs, e.g.
    ``("reality.example.com", "127.0.0.1:10003")``. Anything not matched falls
    through to the local https vhost (decoy + WS/XHTTP/GRPC paths).
    """
    lines = []
    for sni, upstream in stream_routes or []:
        if sni:
            lines.append(f"        {sni} {upstream};")
    lines.append("        default 127.0.0.1:8443;")
    stream_map = "\n".join(lines)

    return f"""# ── TiTaN Panel · /etc/nginx/nginx.conf (managed) ────────────────────────────
user  www-data;
worker_processes  auto;
worker_rlimit_nofile  65535;
pid  /run/nginx.pid;

events {{
    worker_connections  32768;
    multi_accept  on;
    use  epoll;
    accept_mutex  off;
}}

stream {{
    # SNI based routing on 443 so raw-TLS / REALITY inbounds bypass TLS
    # termination while everything else lands on the https vhost below.
    map $ssl_preread_server_name $titan_upstream {{
{stream_map}
    }}

    server {{
        listen 443 reuseport so_keepalive=on backlog=32768;
        listen [::]:443 reuseport so_keepalive=on backlog=32768;
        proxy_pass $titan_upstream;
        ssl_preread on;
        proxy_protocol on;
        proxy_timeout 3600s;
        proxy_connect_timeout 5s;
    }}
}}

http {{
    include  /etc/nginx/mime.types;
    default_type  application/octet-stream;
    server_tokens  off;

    log_format titan '$remote_addr - $remote_user [$time_local] "$request" '
                     '$status $body_bytes_sent "$http_referer" rt=$request_time';

    access_log /var/log/titan/nginx-access.log titan buffer=64k flush=5s;
    error_log  /var/log/titan/nginx-error.log warn;

    sendfile  on;
    tcp_nopush  on;
    tcp_nodelay  on;
    keepalive_timeout  300;
    keepalive_requests  10000;
    reset_timedout_connection  on;
    client_body_timeout  60s;
    client_header_timeout  60s;
    send_timeout  60s;
    large_client_header_buffers  4 16k;

    open_file_cache  max=20000 inactive=30s;
    open_file_cache_valid  60s;
    open_file_cache_min_uses 2;
    open_file_cache_errors  on;

    gzip  on;
    gzip_vary  on;
    gzip_comp_level  5;
    gzip_min_length  512;
    gzip_proxied  any;
    gzip_types  text/plain text/css application/json application/javascript text/xml application/xml;

    ssl_protocols  TLSv1.2 TLSv1.3;
    ssl_ciphers  {TLS_CIPHERS};
    ssl_conf_command  Ciphersuites {TLS13_CIPHERS};
    ssl_prefer_server_ciphers  off;
    ssl_session_cache  shared:TiTaN_TLS:100m;
    ssl_session_timeout  1d;
    ssl_session_tickets  on;
    ssl_early_data  on;
    ssl_stapling  on;
    ssl_stapling_verify  on;

    http2  on;
    http2_recv_buffer_size  1m;
    postpone_output  0;

    include /etc/nginx/conf.d/titan/*.conf;
}}
"""


def build_nginx_vhost(node: Node, inbounds: list[Inbound], *, cert_path: str = "/etc/titan/tls") -> str:
    """The https vhost: decoy site + one proxy location per nginx-backed inbound."""
    locations: list[str] = []
    for inbound in inbounds:
        if not inbound.is_active:
            continue
        if inbound.security is Security.REALITY or inbound.transport in (Transport.TCP, Transport.QUIC):
            continue
        if inbound.protocol in (Protocol.HYSTERIA2, Protocol.WIREGUARD):
            continue

        upgrade = ""
        extra_headers = ""
        if inbound.transport in (Transport.WS, Transport.HTTPUPGRADE):
            upgrade = "proxy_set_header Upgrade $http_upgrade;\n            proxy_set_header Connection $connection_upgrade;\n            "
        if inbound.transport is Transport.GRPC:
            extra_headers = "grpc_set_header X-Real-IP $remote_addr;\n            grpc_pass grpc://127.0.0.1:%d;\n" % inbound.internal_port
            locations.append(
                f"    location {inbound.path or '/titan'} {{\n"
                f"        {extra_headers}"
                f"        grpc_read_timeout 3600s;\n"
                f"        grpc_send_timeout 3600s;\n"
                f"        client_body_timeout 3600s;\n"
                f"    }}\n"
            )
            continue

        locations.append(
            f"    location {inbound.path or '/titan'} {{\n"
            f"        proxy_pass http://127.0.0.1:{inbound.internal_port};\n"
            f"        proxy_http_version 1.1;\n"
            f"        {upgrade}"
            f"        proxy_set_header Host $host;\n"
            f"        proxy_set_header X-Real-IP $proxy_protocol_addr;\n"
            f"        proxy_set_header X-Forwarded-For $proxy_protocol_addr;\n"
            f"        proxy_set_header X-Forwarded-Proto $scheme;\n"
            f"        proxy_protocol on;\n"
            f"        proxy_buffering off;\n"
            f"        proxy_request_buffering off;\n"
            f"        proxy_send_timeout 3600s;\n"
            f"        proxy_read_timeout 3600s;\n"
            f"        proxy_socket_keepalive on;\n"
            f"    }}\n"
        )

    locations_block = "\n".join(locations) if locations else "    # no nginx-fronted inbounds yet\n"
    decoy = node.decoy_url if getattr(node, "decoy_url", None) else None

    decoy_block = (
        f"    location / {{ proxy_pass {decoy}; proxy_set_header Host $host; proxy_ssl_server_name on; }}\n"
        if decoy
        else f"    root {settings.decoy_root};\n    index index.html;\n\n    location / {{ try_files $uri $uri/ /index.html; }}\n"
    )

    return f"""# ── TiTaN Panel · https vhost for {node.address} (managed) ──────────────────
map $http_upgrade $connection_upgrade {{
    default upgrade;
    ''      close;
}}

server {{
    listen 8443 ssl proxy_protocol reuseport so_keepalive=on;
    http2 on;
    server_name {node.address};

    ssl_certificate     {cert_path}/fullchain.pem;
    ssl_certificate_key {cert_path}/privkey.pem;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;

{decoy_block}
{locations_block}}}
"""


def build_nginx_http_redirect() -> str:
    """Port 80: ACME http-01 + redirect to https + tiny decoy."""
    return f"""# ── TiTaN Panel · port 80 vhost (managed) ────────────────────────────────────
server {{
    listen 80 default_server reuseport;
    listen [::]:80 default_server reuseport;
    server_name _;

    location ^~ /.well-known/acme-challenge/ {{
        root {settings.decoy_root}/acme;
        default_type "text/plain";
    }}

    location / {{ return 301 https://$host$request_uri; }}
}}
"""


def build_sysctl_conf() -> str:
    """Kernel tuning applied by the agent — big part of the 'fast' in fast panel."""
    return """# ── TiTaN Panel · /etc/sysctl.d/99-titan.conf (managed) ──────────────────────
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65000
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
fs.file-max = 1000000
net.ipv4.ping_group_range = 0 2147483647
"""


def build_ufw_rules(node: Node, inbounds: list[Inbound] | None = None) -> list[str]:
    """Firewall plan: ingress ports public, control ports protected.

    443/tcp   nginx stream (fronted paths + REALITY passthrough)
    80/tcp    ACME + redirect
    8443/tcp  the local https vhost — reachable only through the 443 stream,
              so it is explicitly *not* opened to the internet
    direct    every raw-TCP / UDP inbound gets its own rule
    """
    rules = [
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "ufw allow 22/tcp",
        "ufw allow 80/tcp",
        "ufw allow 443/tcp",
        f"ufw allow {node.agent_port}/tcp",
        "ufw deny 8443/tcp",
    ]
    seen: set[str] = set()
    for inbound in inbounds or []:
        if not inbound.is_active or routing_mode(inbound) != "direct":
            continue
        proto = "udp" if (inbound.transport is Transport.QUIC or inbound.protocol.value in ("hysteria2", "wireguard")) else "tcp"
        rule = f"ufw allow {inbound.port}/{proto}"
        if rule not in seen:
            rules.append(rule)
            seen.add(rule)
    return rules


# ── optional extra cores ─────────────────────────────────────────────────────
def build_hysteria2_config(node: Node, inbounds: list[Inbound], cert_path: str = "/etc/titan/tls") -> dict | None:
    """Hysteria2 (QUIC/UDP) — best-in-class on lossy / high-latency links."""
    hy2 = [i for i in inbounds if i.is_active and i.protocol is Protocol.HYSTERIA2]
    if not hy2:
        return None
    inbound = hy2[0]
    extra = inbound.extra or {}
    users: list[dict] = []
    for client in inbound.clients:
        if not client.is_active:
            continue
        user = client.user
        entry = {"password": user.password}
        if user.data_limit:
            entry["up_mbps"] = max(user.speed_limit, 0)
            entry["down_mbps"] = max(user.speed_limit, 0)
        users.append(entry)

    return {
        "listen": f":{inbound.port}",
        "tls": {"cert": f"{cert_path}/fullchain.pem", "key": f"{cert_path}/privkey.pem"},
        "obfs": {"type": "salamander", "salamander": {"password": extra.get("obfs_password", inbound.password)}},
        "masquerade": {"type": "proxy", "proxy": {"url": f"https://{node.address}/", "rewrite_host": True, "insecure": False}},
        "auth": {"type": "password", "password": entry_password(inbound)},
        "bandwidth": {
            "up": extra.get("bandwidth_up", "1 gbps"),
            "down": extra.get("bandwidth_down", "1 gbps"),
        },
        "ignoreClientBandwidth": False,
        "quic": {"initStreamReceiveWindow": 8388608, "maxStreamReceiveWindow": 8388608,
                 "initConnReceiveWindow": 20971520, "maxConnReceiveWindow": 20971520,
                 "maxIdleTimeout": "30s", "keepAlivePeriod": "10s"},
        "udp": True,
        "users": users,
    }


def entry_password(inbound: Inbound) -> str:
    return inbound.password or "titan"


def build_wireguard_config(node: Node, inbounds: list[Inbound]) -> str | None:
    wg = [i for i in inbounds if i.is_active and i.protocol is Protocol.WIREGUARD]
    if not wg:
        return None
    inbound = wg[0]
    extra = inbound.extra or {}
    peers = []
    for client in inbound.clients:
        if client.is_active:
            peers.append(
                f"# {client.user.username}\n[Peer]\nPublicKey = {extra.get('peer_keys', {}).get(str(client.user_id), '')}\n"
                f"AllowedIPs = {extra.get('peer_ips', {}).get(str(client.user_id), '10.66.66.2/32')}\n"
            )
    return f"""[Interface]
Address = {extra.get('address', '10.66.66.1/24,fd42:42:42::1/64')}
ListenPort = {inbound.port}
PrivateKey = {inbound.password}
MTU = {extra.get('mtu', 1420)}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
{' '.join(peers)}
"""


def dumps(config: dict) -> str:
    return json.dumps(config, indent=2, ensure_ascii=False)
