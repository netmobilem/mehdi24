"""TiTaN Panel — one-click node bootstrap over SSH.

Installs everything a node needs and leaves it *ready to receive state*:

* nginx (front / TLS / decoy site) + the ``stream`` module
* Xray-core via the official XTLS install script
* directory layout, sysctl tuning (BBR/TFO/epoll), firewall rules
* the zero-dependency TiTaN agent as a systemd service with its own token

If paramiko is unavailable the same steps are returned as a copy-pasteable
bash script, so nothing is hidden behind the integration.
"""

from __future__ import annotations

import asyncio
import logging
import textwrap
from pathlib import Path

from ..models import Node
from ..settings import settings

logger = logging.getLogger("titan.bootstrap")

AGENT_SOURCE = Path(__file__).resolve().parents[2] / "agent" / "titan_agent.py"

SYSTEMD_UNIT = """[Unit]
Description=TiTaN Node Agent (Xray + Nginx control plane)
After=network-online.target xray.service nginx.service
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=TITAN_AGENT_TOKEN={token}
Environment=TITAN_AGENT_PORT={port}
Environment=TITAN_AGENT_HOST=0.0.0.0
ExecStart=/usr/bin/python3 /usr/local/bin/titan_agent.py --host 0.0.0.0 --port {port}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""


def generate_bootstrap_script(node: Node) -> str:
    """The full installer as a standalone bash script (idempotent)."""
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        # ── TiTaN Panel · node bootstrap for {node.name} ({node.address}) ────────
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive

        echo "[1/8] base packages"
        apt-get update -qq
        apt-get install -y -qq curl wget unzip tar socat cron ufw openssl ca-certificates \\
            python3 python3-venv nginx-full jq iproute2 lsb-release gnupg >/dev/null

        echo "[2/8] directories"
        mkdir -p /etc/titan/tls /etc/nginx/conf.d/titan /var/log/titan /var/www/titan-decoy/acme \\
                 /usr/local/etc/xray /etc/hysteria /etc/wireguard
        chown -R www-data:www-data /var/www/titan-decoy

        echo "[3/8] xray-core"
        if ! command -v xray >/dev/null 2>&1; then
          bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
        else
          bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata || true
        fi
        systemctl enable xray >/dev/null 2>&1 || true

        echo "[4/8] kernel tuning (bbr / tfo / file limits)"
        cat > /etc/sysctl.d/99-titan.conf <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65000
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
fs.file-max = 1000000
SYSCTL
        sysctl --system >/dev/null

        echo "[5/8] nginx limits + decoy site"
        mkdir -p /etc/systemd/system/nginx.service.d
        cat > /etc/systemd/system/nginx.service.d/titan-limits.conf <<'UNIT'
[Service]
LimitNOFILE=1048576
LimitNPROC=1048576
UNIT
        systemctl daemon-reload
        printf '%s' '<h1>Welcome to nginx!</h1>' > /var/www/titan-decoy/index.html

        echo "[6/8] firewall"
        ufw --force reset >/dev/null 2>&1 || true
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow 22/tcp >/dev/null
        ufw allow 80/tcp >/dev/null
        ufw allow 443/tcp >/dev/null
        ufw allow {node.agent_port}/tcp >/dev/null
        echo "y" | ufw enable >/dev/null 2>&1 || true

        echo "[7/8] agent"
        install -m 0755 /tmp/titan_agent.py /usr/local/bin/titan_agent.py
        cat > /etc/systemd/system/titan-agent.service <<'UNIT'
{SYSTEMD_UNIT.format(token=node.agent_token, port=node.agent_port).rstrip()}
UNIT
        systemctl daemon-reload
        systemctl enable titan-agent >/dev/null 2>&1
        systemctl restart titan-agent

        echo "[8/8] verify"
        sleep 2
        systemctl --no-pager --lines=0 status titan-agent | head -n 5 || true
        curl -s -m 5 -H "X-Titan-Token: {node.agent_token}" http://127.0.0.1:{node.agent_port}/health | head -c 400 || true
        echo
        echo "TiTaN node ready. Now press 'استقرار' in the panel."
        """
    )


def _run_ssh(node: Node, script: str, agent_source: str, *, timeout: int = 900) -> dict:
    """Blocking paramiko session — executed inside a thread."""
    try:
        import paramiko  # imported lazily so the panel still boots without it
    except ImportError:
        return {"ok": False, "message": "paramiko نصب نیست — از اسکریپت دستی استفاده کنید", "script": generate_bootstrap_script(node)}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict = {
        "hostname": node.ssh_host or node.address,
        "port": node.ssh_port,
        "username": node.ssh_user,
        "timeout": 20,
        "banner_timeout": 30,
        "auth_timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if node.ssh_key_path:
        connect_kwargs["key_filename"] = node.ssh_key_path
    else:
        connect_kwargs["password"] = node.ssh_password or ""

    log: list[str] = []
    try:
        client.connect(**connect_kwargs)
    except Exception as exc:
        return {"ok": False, "message": f"اتصال SSH برقرار نشد: {exc}", "log": log}

    try:
        sftp = client.open_sftp()
        with sftp.file("/tmp/titan_agent.py", "w") as handle:
            handle.write(agent_source)
        sftp.close()
        log.append("agent uploaded to /tmp/titan_agent.py")

        stdin, stdout, stderr = client.exec_command(script, timeout=timeout, get_pty=True)
        for line in iter(stdout.readline, ""):
            if not line:
                break
            log.append(line.rstrip())
        exit_status = stdout.channel.recv_exit_status()
        errors = stderr.read().decode(errors="ignore").strip()
        if errors:
            log.append(errors[-1500:])
        return {"ok": exit_status == 0, "message": "نصب انجام شد" if exit_status == 0 else f"خروج با کد {exit_status}", "log": log[-120:]}
    except Exception as exc:
        return {"ok": False, "message": f"اجرای نصب ناموفق بود: {exc}", "log": log}
    finally:
        client.close()


async def bootstrap_node(node: Node) -> dict:
    """Async wrapper so the API can `await` the SSH install."""
    agent_source = AGENT_SOURCE.read_text(encoding="utf-8") if AGENT_SOURCE.exists() else "# agent source missing"
    script = generate_bootstrap_script(node)
    return await asyncio.get_event_loop().run_in_executor(None, lambda: _run_ssh(node, script, agent_source))


def check_ssh(node: Node) -> dict:
    try:
        import paramiko
    except ImportError:
        return {"ok": False, "message": "paramiko نصب نیست"}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=node.ssh_host or node.address,
            port=node.ssh_port,
            username=node.ssh_user,
            password=node.ssh_password or "",
            key_filename=node.ssh_key_path or None,
            timeout=12,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, _ = client.exec_command("uname -a && (xray version 2>/dev/null | head -1 || echo 'xray: not installed')")
        output = stdout.read().decode(errors="ignore").strip()
        return {"ok": True, "message": output}
    except Exception as exc:
        return {"ok": False, "message": f"SSH failed: {exc}"}
    finally:
        client.close()
