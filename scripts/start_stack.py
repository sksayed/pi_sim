#!/usr/bin/env python3
"""
Start the local MQTT stack in one command.

Default order:
1) Start Mosquitto
2) Start MQTT firewall service
3) Start gateway process
4) Start one or more client processes
"""

from __future__ import annotations

import argparse
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")


def _run_once(command: str, step_name: str, dry_run: bool) -> None:
    print(f"[{step_name}] {command}")
    if dry_run:
        return
    result = subprocess.run(shlex.split(command), cwd=REPO_ROOT, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"{step_name} failed with exit code {result.returncode}: {command}"
        )


def _spawn(command: str, step_name: str, dry_run: bool) -> subprocess.Popen | None:
    print(f"[{step_name}] {command}")
    if dry_run:
        return None
    return subprocess.Popen(
        shlex.split(command),
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
    )


def _wait_for_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.5)
    return False


def _is_systemd_service_active(service_name: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", service_name],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "active"


def _terminate_all(processes: Iterable[subprocess.Popen | None]) -> None:
    for proc in processes:
        if proc is None:
            continue
        if proc.poll() is not None:
            continue
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            continue


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch Mosquitto, firewall, gateway, and clients in sequence."
    )
    parser.add_argument(
        "--broker-host",
        default=os.getenv("GATEWAY_IP", "127.0.0.1"),
        help="Broker host to health-check after Mosquitto startup (default: GATEWAY_IP or 127.0.0.1).",
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=int(os.getenv("GATEWAY_PORT", "1883")),
        help="Broker port to health-check (default: GATEWAY_PORT or 1883).",
    )
    parser.add_argument(
        "--broker-timeout",
        type=float,
        default=15.0,
        help="Seconds to wait for broker readiness.",
    )
    parser.add_argument(
        "--mosquitto-cmd",
        default="sudo systemctl start mosquitto",
        help="Command used to start Mosquitto.",
    )
    parser.add_argument(
        "--firewall-cmd",
        default="sudo systemctl start mqtt_firewall",
        help="Command used to start the firewall service.",
    )
    parser.add_argument(
        "--gateway-cmd",
        default=f"{shlex.quote(sys.executable)} gateway/gateway.py",
        help="Command used to start the gateway process.",
    )
    parser.add_argument(
        "--client-cmd",
        action="append",
        default=[],
        help=(
            "Client launch command. Repeat for multiple clients. "
            "Example: --client-cmd 'python client/client_a.py'"
        ),
    )
    parser.add_argument(
        "--skip-mosquitto",
        action="store_true",
        help="Skip Mosquitto startup step.",
    )
    parser.add_argument(
        "--skip-firewall",
        action="store_true",
        help="Skip firewall startup step.",
    )
    parser.add_argument(
        "--skip-gateway",
        action="store_true",
        help="Skip gateway startup step.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing them.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    launched: list[subprocess.Popen | None] = []

    try:
        if not args.skip_mosquitto:
            _run_once(args.mosquitto_cmd, "1/4 Mosquitto", args.dry_run)
            if not args.dry_run:
                print("[CHECK] Waiting for broker readiness...")
                ok = _wait_for_port(args.broker_host, args.broker_port, args.broker_timeout)
                if not ok:
                    if _is_systemd_service_active("mosquitto"):
                        print(
                            "[WARN] TCP readiness check failed, but mosquitto service is active. "
                            "Continuing (this can happen with NFQUEUE rules before firewall attach)."
                        )
                        print("[CHECK] Broker service is active via systemd.")
                    else:
                        raise RuntimeError(
                            f"Broker not reachable at {args.broker_host}:{args.broker_port} "
                            f"within {args.broker_timeout:.1f}s."
                        )
                else:
                    print(f"[CHECK] Broker is up at {args.broker_host}:{args.broker_port}.")
        else:
            print("[1/4 Mosquitto] skipped")

        if not args.skip_firewall:
            _run_once(args.firewall_cmd, "2/4 Firewall", args.dry_run)
        else:
            print("[2/4 Firewall] skipped")

        if not args.skip_gateway:
            gateway_proc = _spawn(args.gateway_cmd, "3/4 Gateway", args.dry_run)
            launched.append(gateway_proc)
        else:
            print("[3/4 Gateway] skipped")

        client_cmds = args.client_cmd or [f"{shlex.quote(sys.executable)} client/client_a.py"]
        for idx, cmd in enumerate(client_cmds, start=1):
            proc = _spawn(cmd, f"4/4 Client {idx}", args.dry_run)
            launched.append(proc)

        if args.dry_run:
            print("[DONE] Dry run completed.")
            return 0

        print("[RUNNING] Stack started. Press Ctrl+C to stop launched processes.")
        while True:
            for proc in launched:
                if proc is not None and proc.poll() is not None:
                    raise RuntimeError(
                        f"A launched process exited unexpectedly with code {proc.returncode}."
                    )
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user.")
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1
    finally:
        _terminate_all(launched)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
