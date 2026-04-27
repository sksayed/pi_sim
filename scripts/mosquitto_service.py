#!/usr/bin/env python3
"""
Manage Mosquitto service from one script.

Usage:
  python scripts/mosquitto_service.py start
  python scripts/mosquitto_service.py stop
  python scripts/mosquitto_service.py restart
  python scripts/mosquitto_service.py status
"""

from __future__ import annotations

import argparse
import subprocess


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Start/stop/restart/check status of Mosquitto service."
    )
    parser.add_argument(
        "action",
        choices=("start", "stop", "restart", "status"),
        help="Service action to execute.",
    )
    parser.add_argument(
        "--service-name",
        default="mosquitto",
        help="Systemd service name (default: mosquitto).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the command without executing it.",
    )
    return parser.parse_args()


def run_action(action: str, service_name: str, dry_run: bool) -> int:
    command = ["sudo", "systemctl", action, service_name]
    print(f"[CMD] {' '.join(command)}")

    if dry_run:
        return 0

    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        print(f"[ERROR] '{action}' failed with exit code {result.returncode}")
        return result.returncode

    print(f"[OK] '{action}' completed for service '{service_name}'.")
    return 0


def main() -> int:
    args = parse_args()
    return run_action(args.action, args.service_name, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
