"""TiTaN Panel — share-link / client-config builders.

Turns panel entities (Node + Inbound + User) into everything a client app
needs: VLESS/VMess/Trojan/SS/Hysteria2 URIs, WireGuard confs, full Xray client
JSON, base64 subscription payloads and Clash/sing-box friendly output.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote, urlencode

from ..models import Inbound, Node, Protocol, Security, Transport, User, XhttpMode

TRANSPORT_MAP = {
    Transport.WS: "ws",
    Transport.XHTTP: "xhttp",
    Transport.GRPC: "grpc",
    Transport.TCP: "tcp",
    Transport.HTTPUPGRADE: "httpupgrade",
    Transport.QUIC: "quic",
}

XHTTP_MODE_MAP = {
    XhttpMode.PACKET_UP: "packet-up",
    XhttpMode.STREAM_UP: "stream-up",
    XhttpMode.STREAM_ONE: "stream-one",
    XhttpMode.AUTO: "auto",
}


def _b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def _host_for(node: Node, inbound: Inbound) -> str:
    return inbound.host_header or inbound.sni or node.address


def _port_for(node: Node, inbound: Inbound) -> int:
    return inbound.port or node.port or 443


def _query(params: dict) -> str:
    clean = {k: v for k, v in params.items() if v not in (None, "")}
    return urlencode(clean, quote_via=quote, safe=",")  # ALPN lists keep their comma


def _remark(node: Node, inbound: Inbound, user: User | None = None) -> str:
    parts = [node.flag or "", node.name, inbound.name]
    if user:
        parts.append(user.username)
    return " | ".join(p for p in parts if p)


def build_link(node: Node, inbound: Inbound, user: User, *, client_email: str | None = None) -> str:
    """Build a single share URI for the given user on the given inbound."""
    host = _host_for(node, inbound)
    port = _port_for(node, inbound)
    remark = _remark(node, inbound, user)
    transport = TRANSPORT_MAP.get(inbound.transport, "tcp")
    security = {Security.TLS: "tls", Security.REALITY: "reality", Security.NONE: "none"}[inbound.security]
    alpn = inbound.alpn or ("http/1.1" if transport == "ws" else "h2,http/1.1")

    common = {
        "type": transport,
        "security": security,
        "fp": inbound.fingerprint or "chrome",
        "alpn": alpn,
    }
    if security == "reality":
        common.update(
            {
                "pbk": inbound.reality_public_key,
                "sid": inbound.reality_short_id,
                "sni": inbound.reality_server_names.split(",")[0].strip() if inbound.reality_server_names else host,
                "spx": "/",
                "flow": inbound.flow or "xtls-rprx-vision",
            }
        )
    else:
        common["sni"] = inbound.sni or host
        common["host"] = inbound.host_header or host
        if inbound.allow_insecure:
            common["allowInsecure"] = "1"

    if transport in ("ws", "httpupgrade", "xhttp"):
        common["path"] = inbound.path or "/titan"
    if transport == "xhttp":
        common["mode"] = XHTTP_MODE_MAP.get(inbound.xhttp_mode, "auto")
    if transport == "grpc":
        common["serviceName"] = inbound.service_name or "titan-grpc"
        common["mode"] = "gun"
    if transport == "tcp" and security != "reality":
        common["headerType"] = "none"

    if inbound.protocol is Protocol.VLESS:
        query = {"encryption": "none", **common}
        return f"vless://{user.uuid}@{host}:{port}?{_query(query)}#{quote(remark)}"

    if inbound.protocol is Protocol.VMESS:
        payload = {
            "v": "2",
            "ps": remark,
            "add": host,
            "port": str(port),
            "id": user.uuid,
            "aid": "0",
            "scy": "auto",
            "net": transport,
            "type": "none",
            "host": common.get("host", host),
            "path": common.get("path", ""),
            "tls": "" if security == "none" else security,
            "sni": common.get("sni", host),
            "alpn": alpn,
            "fp": common.get("fp", ""),
        }
        return "vmess://" + base64.b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode()

    if inbound.protocol is Protocol.TROJAN:
        query = {"security": security, **{k: v for k, v in common.items() if k != "security"}}
        return f"trojan://{quote(user.password)}@{host}:{port}?{_query(query)}#{quote(remark)}"

    if inbound.protocol is Protocol.SHADOWSOCKS:
        method = inbound.cipher or "2022-blake3-aes-128-gcm"
        password = inbound.password or user.password
        userinfo = _b64(f"{method}:{password}")
        plugin = ""
        if inbound.transport in (Transport.WS, Transport.HTTPUPGRADE):
            plugin = "?plugin=" + quote(f"v2ray-plugin;mode=websocket;host={host};path={inbound.path or '/titan'};tls")
        return f"ss://{userinfo}@{host}:{port}{plugin}#{quote(remark)}"

    if inbound.protocol is Protocol.HYSTERIA2:
        extra = inbound.extra or {}
        query = {
            "sni": inbound.sni or host,
            "insecure": "1" if inbound.allow_insecure else "0",
            "obfs": "salamander",
            "obfs-password": extra.get("obfs_password", inbound.password),
        }
        return f"hysteria2://{quote(user.password)}@{host}:{port}?{_query(query)}#{quote(remark)}"

    return ""


def build_wireguard_conf(node: Node, inbound: Inbound, user: User, client_index: int = 0) -> str:
    """A ready to import WireGuard configuration (client side)."""
    extra = inbound.extra or {}
    address = extra.get("client_addresses", {}).get(str(user.id), f"10.66.66.{client_index + 2}/32")
    peer_key = extra.get("server_public_key", "")
    return f"""[Interface]
PrivateKey = {user.password}
Address = {address}
DNS = 1.1.1.1, 8.8.8.8
MTU = {extra.get('mtu', 1420)}

[Peer]
PublicKey = {peer_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {node.address}:{inbound.port}
PersistentKeepalive = 25
"""


def build_client_json(node: Node, inbound: Inbound, user: User) -> dict:
    """Full Xray client-side config.json (for desktop/CLI users)."""
    link = build_link(node, inbound, user)
    link = link.replace("vless://", "").replace("trojan://", "") if link else ""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
            {
                "tag": "http-in",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": inbound.protocol.value,
                "settings": _client_outbound_settings(inbound, user),
                "streamSettings": _client_stream_settings(node, inbound),
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
            ],
        },
    }


def _client_outbound_settings(inbound: Inbound, user: User) -> dict:
    if inbound.protocol is Protocol.VLESS:
        entry: dict = {"id": user.uuid, "encryption": "none"}
        if inbound.flow:
            entry["flow"] = inbound.flow
        return {"vnext": [{"address": "", "port": 443, "users": [entry]}]}
    if inbound.protocol is Protocol.VMESS:
        return {"vnext": [{"address": "", "port": 443, "users": [{"id": user.uuid, "alterId": 0, "security": "auto"}]}]}
    if inbound.protocol is Protocol.TROJAN:
        return {"servers": [{"address": "", "port": 443, "password": user.password}]}
    if inbound.protocol is Protocol.SHADOWSOCKS:
        return {"servers": [{"address": "", "port": 443, "method": inbound.cipher, "password": inbound.password or user.password}]}
    return {}


def _client_stream_settings(node: Node, inbound: Inbound) -> dict:
    transport = TRANSPORT_MAP.get(inbound.transport, "tcp")
    security = {Security.TLS: "tls", Security.REALITY: "reality", Security.NONE: "none"}[inbound.security]
    stream: dict = {"network": transport, "security": security, "sockopt": {"tcpFastOpen": True, "domainStrategy": "UseIPv4v6"}}
    if security == "tls":
        stream["tlsSettings"] = {
            "serverName": inbound.sni or node.address,
            "alpn": [a.strip() for a in (inbound.alpn or "http/1.1").split(",") if a.strip()],
            "allowInsecure": inbound.allow_insecure,
            "fingerprint": inbound.fingerprint,
        }
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": (inbound.reality_server_names or node.address).split(",")[0].strip(),
            "publicKey": inbound.reality_public_key,
            "shortId": inbound.reality_short_id,
            "fingerprint": inbound.fingerprint,
            "spiderX": "/",
        }
    if transport == "ws":
        stream["wsSettings"] = {"path": inbound.path or "/titan", "host": _host_for(node, inbound)}
    elif transport == "xhttp":
        stream["xhttpSettings"] = {"path": inbound.path or "/titan", "host": _host_for(node, inbound), "mode": XHTTP_MODE_MAP.get(inbound.xhttp_mode, "auto")}
    elif transport == "grpc":
        stream["grpcSettings"] = {"serviceName": inbound.service_name, "multiMode": False}
    elif transport == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": inbound.path or "/titan", "host": _host_for(node, inbound)}
    return stream


# ── subscription payloads ────────────────────────────────────────────────────
def base64_subscription(links: list[str], *, title: str = "TiTaN") -> str:
    body = "\n".join(link for link in links if link)
    payload = f"# {title}\n{body}\n".encode()
    return base64.b64encode(payload).decode()


def json_subscription(links: list[str]) -> str:
    return json.dumps({"links": [l for l in links if l]}, ensure_ascii=False)


def clash_subscription(node_inbounds: list[tuple[Node, Inbound, User]]) -> str:
    """Minimal but valid Clash Meta config for the given (node, inbound, user) set."""
    proxies: list[str] = []
    names: list[str] = []
    for node, inbound, user in node_inbounds:
        name = f"{node.name}-{inbound.name}"
        names.append(name)
        host = _host_for(node, inbound)
        port = _port_for(node, inbound)
        net = TRANSPORT_MAP.get(inbound.transport, "tcp")
        if inbound.protocol is Protocol.VLESS:
            proxies.append(
                "\n".join(
                    [
                        f"  - name: \"{name}\"",
                        "    type: vless",
                        f"    server: {host}",
                        f"    port: {port}",
                        f"    uuid: {user.uuid}",
                        "    udp: true",
                        f"    tls: {'false' if inbound.security is Security.NONE else 'true'}",
                        f"    servername: {inbound.sni or host}",
                        f"    network: {net}",
                        f"    client-fingerprint: {inbound.fingerprint or 'chrome'}",
                        ("    reality-opts:\n"
                         f"      public-key: {inbound.reality_public_key}\n"
                         f"      short-id: \"{inbound.reality_short_id}\"") if inbound.security is Security.REALITY else "",
                        (f"    ws-opts:\n      path: {inbound.path or '/titan'}\n      headers:\n        Host: {host}") if net == "ws" else "",
                    ]
                )
            )
        elif inbound.protocol is Protocol.TROJAN:
            proxies.append(
                "\n".join(
                    [
                        f"  - name: \"{name}\"",
                        "    type: trojan",
                        f"    server: {host}",
                        f"    port: {port}",
                        f"    password: {user.password}",
                        "    udp: true",
                        f"    sni: {inbound.sni or host}",
                        f"    network: {net}",
                    ]
                )
            )
    proxy_names = "\n".join(f"      - \"{n}\"" for n in names)
    return (
        "port: 7890\nsocks-port: 7891\nallow-lan: false\nmode: rule\nlog-level: warning\n\n"
        "proxies:\n" + ("\n".join(proxies) if proxies else "  []") + "\n\n"
        "proxy-groups:\n  - name: TiTaN\n    type: select\n    proxies:\n"
        f"{proxy_names}\n      - DIRECT\n\nrules:\n  - MATCH,TiTaN\n"
    )
