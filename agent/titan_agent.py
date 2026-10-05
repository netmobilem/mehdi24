#!/usr/bin/env python3
"""TiTaN Node Agent — the server-side half of the combined Xray + Nginx core.

Runs on every node with **zero third-party dependencies** (Python 3.9+ stdlib
only) so bootstrapping never fails because of pip/network issues.

Responsibilities
----------------
* Apply the desired-state pushed by the panel: Xray config, Nginx (main +
  vhosts + port 80), sysctl tuning, decoy site, optional Hysteria2/WireGuard.
* Validate before reload (``xray -test``, ``nginx -t``) and roll back on error —
  a bad push can never take the node offline.
* Report real health: CPU / RAM / disk / load / uptime / ping plus
  Xray versions and TLS certificate status.
* Collect traffic + online users straight from the Xray stats API.
* Issue/renew Let's Encrypt certificates through the ACME http-01 challenge.
* Optional per-user bandwidth shaping (Linux ``tc``/HTB) for speed limits.

Security: every request needs the shared token (``X-Titan-Token``) that the
panel generated for this node. Bind the agent to a private interface or
firewall it to the panel IP only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

AGENT_VERSION = "1.0.0"

# ── paths ────────────────────────────────────────────────────────────────────
def _path(env_key: str, default: str) -> Path:
    """Every path is overridable so the agent can run in containers/CI too."""
    return Path(os.environ.get(env_key, default))


STATE_DIR = _path("TITAN_STATE_DIR", "/etc/titan")
TLS_DIR = STATE_DIR / "tls"
DECOY_DIR = _path("TITAN_DECOY_DIR", "/var/www/titan-decoy")
LOG_DIR = _path("TITAN_LOG_DIR", "/var/log/titan")
XRAY_BIN = os.environ.get("TITAN_XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG = _path("TITAN_XRAY_CONFIG", "/usr/local/etc/xray/config.json")
NGINX_MAIN = _path("TITAN_NGINX_MAIN", "/etc/nginx/nginx.conf")
NGINX_VHOST_DIR = _path("TITAN_NGINX_VHOST_DIR", "/etc/nginx/conf.d/titan")
SYSCTL_FILE = _path("TITAN_SYSCTL_FILE", "/etc/sysctl.d/99-titan.conf")
HY2_CONFIG = _path("TITAN_HY2_CONFIG", "/etc/hysteria/config.yaml")
WG_CONFIG = _path("TITAN_WG_CONFIG", "/etc/wireguard/titan0.conf")
XRAY_API = os.environ.get("TITAN_XRAY_API", "127.0.0.1:10085")

_STARTED_AT = time.time()
_LOCK = threading.Lock()


# ── shell helpers ────────────────────────────────────────────────────────────
def run(cmd, timeout: int = 60, check: bool = False, env: dict | None = None):
    """Run a command, never raise unless ``check`` is set."""
    if isinstance(cmd, str):
        cmd = ["/bin/sh", "-c", cmd]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            env={**os.environ, **(env or {})},
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or b"").decode(errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or ""), "timeout"
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except Exception as exc:  # pragma: no cover
        return 1, "", str(exc)


def write_file(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".titan-new")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


def backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = path.with_suffix(path.suffix + f".bak-{stamp}")
    try:
        shutil.copy2(path, target)
        return target
    except OSError:
        return None


# ── system metrics ───────────────────────────────────────────────────────────
def cpu_times() -> tuple[int, int]:
    with open("/proc/stat") as fh:
        parts = fh.readline().split()[1:]
    values = [int(v) for v in parts]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    return idle, total


_cpu_last: tuple[int, int] | None = None


def cpu_percent() -> float:
    global _cpu_last
    idle, total = cpu_times()
    if _cpu_last is None:
        _cpu_last = (idle, total)
        time.sleep(0.15)
        idle, total = cpu_times()
    prev_idle, prev_total = _cpu_last
    _cpu_last = (idle, total)
    d_idle, d_total = idle - prev_idle, total - prev_total
    if d_total <= 0:
        return 0.0
    return round(100.0 * (1 - d_idle / d_total), 1)


def memory_info() -> dict:
    info = {"total": 0, "available": 0, "used": 0}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    info["total"] = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    info["available"] = int(line.split()[1]) * 1024
        info["used"] = max(info["total"] - info["available"], 0)
    except OSError:
        pass
    return info


def disk_info(path: str = "/") -> dict:
    try:
        usage = shutil.disk_usage(path)
        return {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        return {"total": 0, "used": 0, "free": 0}


def uptime_seconds() -> int:
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        return int(time.time() - _STARTED_AT)


def load_avg() -> list[float]:
    try:
        return [round(float(v), 2) for v in Path("/proc/loadavg").read_text().split()[:3]]
    except Exception:
        return [0.0, 0.0, 0.0]


def service_active(name: str) -> bool:
    code, out, _ = run(["systemctl", "is-active", name], timeout=10)
    return out.strip() == "active"


def binary_version(binary: str, args: list[str] | None = None) -> str:
    if not shutil.which(binary) and not Path(binary).exists():
        return ""
    code, out, err = run([binary, *(args or ["version"])], timeout=15)
    text = (out or err).splitlines()
    return text[0][:64] if text else ""


def ping_ms(host: str = "1.1.1.1") -> int:
    """Latency probe used for the dashboard 'پینگ' badge."""
    code, out, _ = run(["ping", "-c", "1", "-W", "2", host], timeout=6)
    if code != 0:
        return 0
    match = re.search(r"time=([\d.]+)", out)
    return int(float(match.group(1))) if match else 0


def cert_info() -> dict:
    cert = TLS_DIR / "fullchain.pem"
    if not cert.exists():
        return {"present": False, "expires_at": None, "issuer": None, "days_left": None}
    code, out, _ = run(
        [
            "openssl", "x509", "-in", str(cert), "-noout",
            "-enddate", "-issuer", "-subject",
        ],
        timeout=15,
    )
    if code != 0:
        return {"present": True, "expires_at": None, "issuer": None, "days_left": None}
    expires_at, issuer, days_left = None, None, None
    for line in out.splitlines():
        if line.startswith("notAfter="):
            try:
                dt = datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                expires_at = dt.replace(tzinfo=timezone.utc).isoformat()
                days_left = (dt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            except ValueError:
                pass
        elif line.startswith("issuer="):
            issuer = line.split("=", 1)[1].strip()[:120]
    return {"present": True, "expires_at": expires_at, "issuer": issuer, "days_left": days_left}


# ── xray stats ───────────────────────────────────────────────────────────────
def xray_stats() -> dict:
    """Query the local Xray stats API and normalise the answer.

    Returns ``{"users": {email: {"up": int, "down": int}}, "inbounds": {...}}``.
    """
    payload = {"pattern": "", "reset": False}
    code, out, err = run(
        [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}", "-json"],
        timeout=20,
    )
    if code != 0 or not out:
        # fall back to plain output parsing
        code, out, err = run([XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}"], timeout=20)
        if code != 0:
            return {"ok": False, "error": (err or "stats unavailable")[:200], "users": {}, "inbounds": {}}
        users: dict[str, dict] = {}
        for line in out.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 2:
                continue
            key, value = parts[0].strip(), parts[1].strip()
            if not key.startswith("user>>>"):
                continue
            chunks = key.split(">>>")
            if len(chunks) < 4:
                continue
            email, direction = chunks[1], chunks[3]
            entry = users.setdefault(email, {"up": 0, "down": 0})
            try:
                entry["up" if direction == "uplink" else "down"] = int(value)
            except ValueError:
                continue
        return {"ok": True, "users": users, "inbounds": {}}

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"ok": False, "error": "bad stats payload", "users": {}, "inbounds": {}}

    users: dict[str, dict] = {}
    inbounds: dict[str, dict] = {}
    for stat in data.get("stat", []):
        name = stat.get("name", "")
        value = int(stat.get("value", 0) or 0)
        if name.startswith("user>>>"):
            chunks = name.split(">>>")
            if len(chunks) < 4:
                continue
            email, direction = chunks[1], chunks[3]
            entry = users.setdefault(email, {"up": 0, "down": 0})
            entry["up" if direction == "uplink" else "down"] = value
        elif name.startswith("inbound>>>"):
            chunks = name.split(">>>")
            if len(chunks) < 4:
                continue
            tag, direction = chunks[1], chunks[3]
            entry = inbounds.setdefault(tag, {"up": 0, "down": 0})
            entry["up" if direction == "uplink" else "down"] = value
    return {"ok": True, "users": users, "inbounds": inbounds}


def online_users() -> dict:
    """Best-effort online list: Xray's online-users API, else access-log tail."""
    code, out, _ = run([XRAY_BIN, "api", "stats", "getallonlineusers", f"--server={XRAY_API}"], timeout=15)
    if code == 0 and out:
        emails = re.findall(r"email:\s*\"?([^\"\s]+)\"?", out)
        if emails:
            return {"ok": True, "source": "api", "users": sorted(set(emails))}

    # fallback — parse the access log for recent activity
    log_file = LOG_DIR / "xray-access.log"
    if not log_file.exists():
        return {"ok": True, "source": "none", "users": []}
    cutoff = time.time() - 120
    seen: dict[str, str] = {}
    try:
        with log_file.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(size - 512 * 1024, 0))
            for raw in fh.read().decode(errors="ignore").splitlines():
                match = re.search(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?email:?\s*([\w.\-@]+)", raw)
                if not match:
                    continue
                try:
                    stamp = datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                except ValueError:
                    continue
                if stamp >= cutoff:
                    seen[match.group(2)] = ""
    except OSError:
        pass
    return {"ok": True, "source": "log", "users": sorted(seen)}


def client_ips(sample_lines: int = 4000) -> dict:
    """Map recent client IPs → user emails (drives IP-limit accounting)."""
    log_file = LOG_DIR / "xray-access.log"
    if not log_file.exists():
        return {}
    mapping: dict[str, set[str]] = {}
    try:
        with log_file.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(size - 1024 * 1024, 0))
            lines = fh.read().decode(errors="ignore").splitlines()[-sample_lines:]
    except OSError:
        return {}
    for line in lines:
        ip_match = re.search(r"from (?:tcp:)?(\d+\.\d+\.\d+\.\d+|\ [[0-9a-fA-F:]+)", line)
        mail_match = re.search(r"email:?\s*([\w.\-@]+)", line)
        if ip_match and mail_match:
            mapping.setdefault(ip_match.group(1).strip("["), set()).add(mail_match.group(1))
    return {ip: sorted(emails) for ip, emails in mapping.items()}


# ── apply desired state ──────────────────────────────────────────────────────
def validate_xray(config_text: str) -> tuple[bool, str]:
    tmp = Path("/tmp/titan-xray-check.json")
    tmp.write_text(config_text, encoding="utf-8")
    code, out, err = run([XRAY_BIN, "-test", "-config", str(tmp)], timeout=30)
    return code == 0, (out or err)[:400]


def validate_nginx() -> tuple[bool, str]:
    if not shutil.which("nginx"):
        return True, "nginx not installed"
    code, out, err = run(["nginx", "-t"], timeout=30)
    return code == 0, (err or out)[:400]


def apply_state(state: dict) -> dict:
    """Write the panel's desired state to disk and reload services safely."""
    results: list[dict] = []
    actions: list[str] = []
    rolled_back = False

    with _LOCK:
        # 1 ── Xray ───────────────────────────────────────────────────────────
        if state.get("xray_config"):
            text = json.dumps(state["xray_config"], indent=2, ensure_ascii=False)
            ok, message = validate_xray(text)
            if not ok:
                results.append({"target": "xray", "ok": False, "message": message})
                return {"ok": False, "results": results, "rolled_back": False}
            backup(XRAY_CONFIG)
            write_file(XRAY_CONFIG, text)
            results.append({"target": "xray", "ok": True, "message": "config written"})
            actions.append("xray")

        # 2 ── Nginx ──────────────────────────────────────────────────────────
        if state.get("nginx_main") or state.get("nginx_vhost") or state.get("nginx_redirect"):
            backups: dict[Path, Path | None] = {}
            if state.get("nginx_main"):
                backups[NGINX_MAIN] = backup(NGINX_MAIN)
                write_file(NGINX_MAIN, state["nginx_main"])
            if state.get("nginx_vhost"):
                target = NGINX_VHOST_DIR / "vhost.conf"
                backups[target] = backup(target)
                write_file(target, state["nginx_vhost"])
            if state.get("nginx_redirect"):
                target = NGINX_VHOST_DIR / "redirect.conf"
                backups[target] = backup(target)
                write_file(target, state["nginx_redirect"])

            ok, message = validate_nginx()
            if not ok:
                for path, previous in backups.items():
                    if previous and previous.exists():
                        shutil.copy2(previous, path)
                rolled_back = True
                results.append({"target": "nginx", "ok": False, "message": message})
            else:
                results.append({"target": "nginx", "ok": True, "message": "config written"})
                actions.append("nginx")

        # 3 ── decoy site + acme webroot ──────────────────────────────────────
        if state.get("decoy_html") is not None:
            write_file(DECOY_DIR / "index.html", state["decoy_html"])
            (DECOY_DIR / "acme" / ".well-known" / "acme-challenge").mkdir(parents=True, exist_ok=True)

        # 4 ── kernel tuning ─────────────────────────────────────────────────
        if state.get("sysctl"):
            write_file(SYSCTL_FILE, state["sysctl"])
            run(["sysctl", "-p", str(SYSCTL_FILE)], timeout=30)
            results.append({"target": "sysctl", "ok": True, "message": "kernel tuned (bbr/tfo)"})

        # 5 ── optional cores ────────────────────────────────────────────────
        if state.get("hysteria2_yaml"):
            write_file(HY2_CONFIG, state["hysteria2_yaml"])
            run(["systemctl", "restart", "hysteria-server"], timeout=30)
            results.append({"target": "hysteria2", "ok": True, "message": "restarted"})

        if state.get("wireguard_conf"):
            write_file(WG_CONFIG, state["wireguard_conf"], mode=0o600)
            run(["systemctl", "restart", "wg-quick@titan0"], timeout=30)
            results.append({"target": "wireguard", "ok": True, "message": "restarted"})

        # 6 ── firewall plan ─────────────────────────────────────────────────
        if state.get("firewall_rules"):
            for rule in state["firewall_rules"]:
                run(rule, timeout=20)
            run("ufw --force enable", timeout=20)
            results.append({"target": "firewall", "ok": True, "message": "rules applied"})

        # 7 ── reload services ───────────────────────────────────────────────
        for service in ("xray", "nginx"):
            if service in actions:
                run(["systemctl", "restart", service], timeout=60)
                time.sleep(0.6)
                healthy = service_active(service)
                results.append(
                    {
                        "target": f"{service}-restart",
                        "ok": healthy,
                        "message": "active" if healthy else "service failed to start",
                    }
                )

    return {"ok": all(r.get("ok", True) for r in results), "results": results, "rolled_back": rolled_back}


# ── ACME ─────────────────────────────────────────────────────────────────────
def issue_certificate(domain: str, email: str = "admin@" + "example.com", *, staging: bool = False) -> dict:
    """Obtain/renew a Let's Encrypt certificate through acme.sh + nginx webroot."""
    acme = shutil.which("acme.sh") or "/root/.acme.sh/acme.sh"
    webroot = str(DECOY_DIR / "acme")

    if not Path(acme).exists():
        code, out, err = run(
            "curl -s https://get.acme.sh | sh -s email=" + email,
            timeout=300,
        )
        if code != 0:
            return {"ok": False, "message": f"acme.sh install failed: {err[:200]}"}

    if staging:
        run([acme, "--set-default-ca", "--server", "letsencrypt_test"], timeout=60)
    else:
        run([acme, "--set-default-ca", "--server", "letsencrypt"], timeout=60)

    # http-01 through the nginx webroot: the panel's port-80 vhost serves
    # /\.well-known/acme-challenge/ straight from the decoy directory.
    code, out, err = run(
        [
            acme, "--issue", "-d", domain, "-w", webroot,
            "--keylength", "ec-256", "--force",
        ],
        timeout=300,
    )
    if code != 0:
        return {"ok": False, "message": (err or out)[:400]}

    TLS_DIR.mkdir(parents=True, exist_ok=True)
    install = run(
        [
            acme, "--install-cert", "-d", domain,
            "--key-file", str(TLS_DIR / "privkey.pem"),
            "--fullchain-file", str(TLS_DIR / "fullchain.pem"),
            "--reloadcmd", "systemctl reload nginx || true",
        ],
        timeout=120,
    )
    if install[0] != 0:
        return {"ok": False, "message": install[2][:400]}

    info = cert_info()
    return {"ok": True, "message": "certificate installed", "cert": info}


# ── bandwidth shaping (per client IP) ───────────────────────────────────────
SHAPE_CHAIN = "TITAN_SHAPE"


def apply_shaping(rules: list[dict]) -> dict:
    """Per-IP HTB shaper. ``rules`` = [{"ip": str, "mbps": int}, …].

    Xray has no native per-user rate limit, so limits are enforced at the
    kernel level against the *client IPs currently bound to that user* — which
    is exactly how the panel tracks concurrent IPs anyway.
    """
    if not shutil.which("tc"):
        return {"ok": False, "message": "tc (iproute2) missing"}

    interface = "eth0"
    code, out, _ = run("ip route get 1.1.1.1 | head -1 | sed -E 's/.*dev ([^ ]+).*/\\1/'", timeout=10)
    if code == 0 and out:
        interface = out.strip()

    run(f"tc qdisc del dev {interface} root", timeout=15)
    run(f"tc qdisc add dev {interface} root handle 1: htb default 9999", timeout=15)

    applied = 0
    for index, rule in enumerate(rules[:400], start=1):
        ip, mbps = rule.get("ip"), int(rule.get("mbps") or 0)
        if not ip or mbps <= 0:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        rate = f"{mbps}mbit"
        run(f"tc class add dev {interface} parent 1: classid 1:{index} htb rate {rate} ceil {rate} burst 64k", timeout=10)
        run(
            f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 "
            f"match ip dst {ip}/32 flowid 1:{index}",
            timeout=10,
        )
        applied += 1

    return {"ok": True, "message": f"shaped {applied} clients on {interface}", "interface": interface}


def shaping_plan(user_map: dict[str, list[str]], limits: dict[str, int]) -> list[dict]:
    """Build shaper rules: {email: [ips]} + {email: mbps} → per-IP rules."""
    plan: list[dict] = []
    for email, ips in (user_map or {}).items():
        mbps = int((limits or {}).get(email, 0) or 0)
        if mbps <= 0:
            continue
        for ip in ips:
            if ip not in ("127.0.0.1", "::1"):
                plan.append({"ip": ip, "mbps": mbps})
    return plan


# ── HTTP API ─────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = f"TiTaNAgent/{AGENT_VERSION}"
    token: str = ""

    # silence default logging noise; keep a compact line
    def log_message(self, fmt, *args):  # noqa: D401
        sys.stderr.write(f"[agent] {self.address_string()} {fmt % args}\n")

    # ── helpers ─────────────────────────────────────────────────────────────
    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-Titan-Token") or ""
        if not self.token:
            return True
        return supplied == self.token

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except json.JSONDecodeError:
            return {}

    # ── routes ──────────────────────────────────────────────────────────────
    def do_GET(self):  # noqa: N802
        if not self._authorized():
            return self._json({"ok": False, "error": "unauthorized"}, 401)

        path = self.path.split("?")[0]
        if path in ("/", "/health", "/api/health"):
            mem, disk = memory_info(), disk_info()
            return self._json(
                {
                    "ok": True,
                    "agent_version": AGENT_VERSION,
                    "hostname": socket.gethostname(),
                    "os": f"{platform.system()} {platform.release()}",
                    "uptime": uptime_seconds(),
                    "cpu_cores": os.cpu_count() or 1,
                    "cpu_pct": cpu_percent(),
                    "ram_total": mem["total"],
                    "ram_used": mem["used"],
                    "disk_total": disk["total"],
                    "disk_used": disk["used"],
                    "load_avg": load_avg(),
                    "ping_ms": ping_ms(),
                    "xray_version": binary_version(XRAY_BIN, ["version"]),
                    "nginx_version": binary_version("nginx", ["-v"]),
                    "services": {"xray": service_active("xray"), "nginx": service_active("nginx")},
                    "cert": cert_info(),
                }
            )

        if path == "/stats":
            stats = xray_stats()
            stats["online"] = online_users()
            stats["ips"] = client_ips()
            return self._json(stats)

        if path == "/ips":
            return self._json({"ok": True, "ips": client_ips()})

        if path == "/logs":
            tail = int((self.path.split("tail=")[1].split("&")[0]) if "tail=" in self.path else 200)
            payload = {}
            for name in ("xray-error.log", "xray-access.log", "nginx-error.log"):
                code, out, _ = run(["tail", "-n", str(min(tail, 1000)), str(LOG_DIR / name)], timeout=15)
                payload[name] = out.splitlines()
            return self._json({"ok": True, "logs": payload})

        return self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):  # noqa: N802
        if not self._authorized():
            return self._json({"ok": False, "error": "unauthorized"}, 401)

        path = self.path.split("?")[0]
        body = self._body()

        if path in ("/apply", "/api/apply"):
            return self._json(apply_state(body))

        if path == "/cert":
            return self._json(
                issue_certificate(
                    body.get("domain", ""),
                    body.get("email", "admin@example.com"),
                    staging=bool(body.get("staging")),
                )
            )

        if path == "/shaping":
            rules = body.get("rules") or shaping_plan(body.get("user_map", {}), body.get("limits", {}))
            return self._json(apply_shaping(rules))

        if path == "/exec":
            allowed = {
                "restart-xray": ["systemctl", "restart", "xray"],
                "restart-nginx": ["systemctl", "restart", "nginx"],
                "reload-nginx": ["systemctl", "reload", "nginx"],
                "stop-xray": ["systemctl", "stop", "xray"],
                "start-xray": ["systemctl", "start", "xray"],
                "xray-restart": ["systemctl", "restart", "xray"],
                "upgrade-xray": ["bash", "-c", "bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install"],
                "upgrade-nginx": ["bash", "-c", "apt-get update -qq && apt-get install -y --only-upgrade nginx"],
                "geo-update": ["bash", "-c", f"{XRAY_BIN} geoupdate -all"],
                "reboot": ["systemctl", "reboot"],
            }
            action = body.get("action", "")
            if action not in allowed:
                return self._json({"ok": False, "error": "action not allowed"}, 400)
            code, out, err = run(allowed[action], timeout=600)
            return self._json({"ok": code == 0, "action": action, "stdout": out[-4000:], "stderr": err[-2000:]})

        return self._json({"ok": False, "error": "not found"}, 404)


def main() -> None:
    parser = argparse.ArgumentParser(description="TiTaN node agent")
    parser.add_argument("--host", default=os.environ.get("TITAN_AGENT_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TITAN_AGENT_PORT", "62050")))
    parser.add_argument("--token", default=os.environ.get("TITAN_AGENT_TOKEN", ""))
    parser.add_argument("--print-token", action="store_true")
    args = parser.parse_args()

    token = args.token
    token_file = STATE_DIR / "agent.token"
    if not token and token_file.exists():
        token = token_file.read_text(encoding="utf-8").strip()
    if args.print_token:
        print(token or "(no token configured)")
        return
    if token:
        write_file(token_file, token, mode=0o600)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    Handler.token = token
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    sys.stderr.write(f"[agent] TiTaN agent {AGENT_VERSION} listening on {args.host}:{args.port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
