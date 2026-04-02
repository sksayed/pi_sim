#!/usr/bin/env python3
"""
Run on the Gateway Pi (in a new terminal). Optionally ensures Mosquitto (MQTT)
is listening locally, detects this machine's LAN IPv4, and writes GATEWAY_IP
into the repo's .env so edge Pis can reach the broker on this host.

Usage:
  python scripts/set_gateway_ip_env.py
  python scripts/set_gateway_ip_env.py --ip 192.168.1.50
  python scripts/set_gateway_ip_env.py --dry-run
  python scripts/set_gateway_ip_env.py --skip-mqtt
  sudo python scripts/set_gateway_ip_env.py   # if systemctl start needs root
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def detect_ipv4() -> str | None:
    """Best-effort primary IPv4 (not loopback). Multiple fallbacks for Linux/Pi."""
    # 1) UDP trick: does not need real traffic; kernel picks outbound iface.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(0.3)
            s.connect(("8.8.8.8", 80))
            addr, _ = s.getsockname()
            if addr and not addr.startswith("127."):
                return addr
        finally:
            s.close()
    except OSError:
        pass

    # 2) hostname -I (common on Raspberry Pi OS / Debian)
    try:
        r = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        for part in r.stdout.split():
            p = part.strip()
            if p and not p.startswith("127.") and ":" not in p:
                return p
    except (OSError, subprocess.TimeoutExpired):
        pass

    # 3) ip route (Linux)
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
        if m and not m.group(1).startswith("127."):
            return m.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


def parse_gateway_port(env_path: Path) -> int:
    """Read GATEWAY_PORT from .env if present; default 1883."""
    if not env_path.exists():
        return 1883
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s*GATEWAY_PORT\s*=\s*(\d+)\s*$", line)
            if m:
                return max(1, min(65535, int(m.group(1))))
    except OSError:
        pass
    return 1883


def mqtt_broker_listening(host: str, port: int, timeout_s: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def ensure_mosquitto_running(port: int, dry_run: bool) -> bool:
    """
    If nothing listens on 127.0.0.1:port, try to start the mosquitto service.
    Returns True if the broker is listening after this function, or dry-run.
    """
    if mqtt_broker_listening("127.0.0.1", port):
        print(f"MQTT broker already listening on 127.0.0.1:{port}")
        return True

    if dry_run:
        print(f"[dry-run] Would try to start Mosquitto (nothing on 127.0.0.1:{port}).")
        return True

    print(f"No MQTT listener on 127.0.0.1:{port} — trying to start Mosquitto…")

    attempts: list[list[str]] = [
        ["systemctl", "start", "mosquitto"],
        ["service", "mosquitto", "start"],
    ]
    last_err = ""
    for cmd in attempts:
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            if r.stderr:
                last_err = r.stderr.strip()
            elif r.stdout:
                last_err = r.stdout.strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            last_err = str(exc)
            continue

        # Give the daemon a moment to bind.
        for _ in range(20):
            if mqtt_broker_listening("127.0.0.1", port):
                print(f"Mosquitto is up; listening on 127.0.0.1:{port}")
                return True
            time.sleep(0.1)

    print(
        f"Could not start Mosquitto on port {port}.",
        file=sys.stderr,
    )
    if last_err:
        print(f"  Last message: {last_err}", file=sys.stderr)
    print(
        "  Install or start manually, e.g.:\n"
        "    sudo apt install mosquitto\n"
        "    sudo systemctl enable --now mosquitto\n"
        "  Or run this script with sudo so systemctl start can succeed.",
        file=sys.stderr,
    )
    return False


def upsert_env_gateway_ip(env_path: Path, ip: str, dry_run: bool) -> bool:
    key = "GATEWAY_IP"
    line_new = f"{key}={ip}\n"

    if not env_path.exists():
        content = f"# Generated by scripts/set_gateway_ip_env.py\n{line_new}"
        if dry_run:
            print(f"[dry-run] would create {env_path} with:\n{content}", end="")
            return True
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text(content, encoding="utf-8")
        return True

    text = env_path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    found = False
    out: list[str] = []
    for line in lines:
        if re.match(rf"^\s*{re.escape(key)}\s*=", line):
            if not found:
                out.append(line_new)
                found = True
            # drop duplicate GATEWAY_IP lines
            continue
        out.append(line)

    if not found:
        if text and not text.endswith("\n"):
            out.append("\n")
        out.append(line_new)

    new_body = "".join(out)
    if new_body == text:
        print(f"{key} already set to {ip!r} in {env_path}")
        return False

    if dry_run:
        print(f"[dry-run] would update {env_path} → {key}={ip}")
        return True

    tmp_path = env_path.parent / f".env.tmp.{os.getpid()}"
    try:
        tmp_path.write_text(new_body, encoding="utf-8")
        os.replace(tmp_path, env_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Set GATEWAY_IP in .env from this host's LAN IP.")
    parser.add_argument("--ip", help="Use this IPv4 instead of auto-detect")
    parser.add_argument("--env-file", type=Path, default=None, help="Path to .env (default: repo root .env)")
    parser.add_argument("--dry-run", action="store_true", help="Print actions only; do not write")
    parser.add_argument(
        "--skip-mqtt",
        action="store_true",
        help="Do not try to start Mosquitto; only update .env",
    )
    args = parser.parse_args()

    root = repo_root()
    env_path = args.env_file if args.env_file else root / ".env"

    port = parse_gateway_port(env_path)
    if not args.skip_mqtt:
        if not ensure_mosquitto_running(port, args.dry_run) and not args.dry_run:
            # Still update .env so the user has the IP; broker must be fixed separately.
            print("Continuing to update .env anyway (broker not confirmed up).", file=sys.stderr)

    ip = args.ip.strip() if args.ip else None
    if not ip:
        ip = detect_ipv4()
    if not ip:
        print(
            "Could not detect IPv4. Pass it explicitly, e.g.\n"
            "  python scripts/set_gateway_ip_env.py --ip 192.168.1.50",
            file=sys.stderr,
        )
        return 1

    print(f"Detected / using IPv4: {ip}")
    print(f"Env file: {env_path}")

    changed = upsert_env_gateway_ip(env_path, ip, args.dry_run)
    if changed and not args.dry_run:
        print(f"Updated GATEWAY_IP={ip} in {env_path}")
        print("Copy this .env (or at least MASTER_SECRET + GATEWAY_IP + GATEWAY_PORT) to each edge Pi.")
    elif not changed and not args.dry_run:
        print("No change needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
