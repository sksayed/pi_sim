#!/usr/bin/env python3
"""
Stop services/processes started by scripts/start_stack.py.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess


def _run(command: str, step_name: str, dry_run: bool) -> None:
    print(f"[{step_name}] {command}")
    if dry_run:
        return
    result = subprocess.run(shlex.split(command), check=False)
    if result.returncode != 0:
        print(f"[WARN] {step_name} exited with code {result.returncode}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stop mosquitto/firewall services and optional Python stack processes."
    )
    parser.add_argument(
        "--mosquitto-stop-cmd",
        default="sudo systemctl stop mosquitto",
        help="Command used to stop Mosquitto.",
    )
    parser.add_argument(
        "--firewall-stop-cmd",
        default="sudo systemctl stop mqtt_firewall",
        help="Command used to stop MQTT firewall service.",
    )
    parser.add_argument(
        "--stop-firewall",
        action="store_true",
        help="Also stop firewall service.",
    )
    parser.add_argument(
        "--stop-python-stack",
        action="store_true",
        help=(
            "Also terminate local Python processes for gateway and demo clients "
            "(gateway.py, client_a.py, client_b.py, client_c.py)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing them.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    _run(args.mosquitto_stop_cmd, "1/3 Stop Mosquitto", args.dry_run)

    if args.stop_firewall:
        _run(args.firewall_stop_cmd, "2/3 Stop Firewall", args.dry_run)
    else:
        print("[2/3 Stop Firewall] skipped (pass --stop-firewall to enable)")

    if args.stop_python_stack:
        _run("pkill -f gateway/gateway.py", "3/3 Stop Gateway process", args.dry_run)
        _run("pkill -f client/client_a.py", "3/3 Stop Client A process", args.dry_run)
        _run("pkill -f client/client_b.py", "3/3 Stop Client B process", args.dry_run)
        _run("pkill -f client/client_c.py", "3/3 Stop Client C process", args.dry_run)
    else:
        print("[3/3 Stop Python stack] skipped (pass --stop-python-stack to enable)")

    print("[DONE] Stop sequence finished.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
