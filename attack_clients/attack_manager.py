#!/usr/bin/env python3
"""
attack_manager.py — Launch all attack types in sequence with a stagger interval.

Each attack runs in its own subprocess for a fixed duration, then the next one
starts. Prints a timestamped timeline so you can correlate with firewall verdicts.

Usage:
    python attack_clients/attack_manager.py                    # all attacks, defaults
    python attack_clients/attack_manager.py --duration 30      # each attack runs 30s
    python attack_clients/attack_manager.py --stagger 2        # 2s gap between launches
    python attack_clients/attack_manager.py --scenario mixed   # run all concurrently
    python attack_clients/attack_manager.py --list             # show attack plan
"""

from __future__ import annotations

import argparse
import os
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON    = str(REPO_ROOT / ".venv" / "bin" / "python")

# ── Attack definitions ────────────────────────────────────────────────────────
# Each entry: (name, command_args, description)
ATTACKS: list[tuple[str, str, str]] = [
    (
        "flood",
        f"{PYTHON} attack_clients/run_attack.py flood --rate 200",
        "High-rate MQTT publish flood",
    ),
    (
        "malformed",
        f"{PYTHON} attack_clients/run_attack.py malformed --rate 5",
        "Malformed payload mutations (8 strategies)",
    ),
    (
        "replay",
        f"{PYTHON} attack_clients/run_attack.py replay --mode replay --rate 5",
        "Replay captured legitimate messages",
    ),
    (
        "slowloris",
        f"{PYTHON} attack_clients/run_attack.py slowloris --mode hold --connections 30",
        "Slow-connection resource exhaustion",
    ),
]


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _launch(cmd: str, name: str) -> subprocess.Popen:
    print(f"[{_ts()}] ▶  START  {name}")
    return subprocess.Popen(
        shlex.split(cmd),
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )


def _stop(proc: subprocess.Popen, name: str) -> None:
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    print(f"[{_ts()}] ■  STOP   {name}")


def run_sequential_attacks(attacks: list, duration: float, stagger: float) -> None:
    """Run each attack one at a time for `duration` seconds, `stagger` gap between."""
    print(f"\n[MANAGER] Mode: sequential | each attack runs {duration}s | stagger {stagger}s\n")
    for name, cmd, desc in attacks:
        print(f"[{_ts()}] ── {name}: {desc}")
        proc = _launch(cmd, name)
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            _stop(proc, name)
            raise
        _stop(proc, name)
        if stagger > 0:
            print(f"[{_ts()}]    (gap {stagger}s)")
            time.sleep(stagger)
    print(f"\n[{_ts()}] [MANAGER] Sequential run complete.")


def run_mixed_attacks(attacks: list, duration: float, stagger: float) -> None:
    """Launch all attacks with `stagger` seconds between each start, all run concurrently."""
    print(f"\n[MANAGER] Mode: mixed | stagger {stagger}s between launches | total ~{duration}s\n")
    procs: list[tuple[str, subprocess.Popen]] = []
    try:
        for name, cmd, desc in attacks:
            print(f"[{_ts()}] ── {name}: {desc}")
            proc = _launch(cmd, name)
            procs.append((name, proc))
            time.sleep(stagger)

        print(f"[{_ts()}] All attacks running. Waiting {duration}s...")
        time.sleep(duration)

    except KeyboardInterrupt:
        print(f"\n[{_ts()}] Interrupted.")
    finally:
        for name, proc in procs:
            _stop(proc, name)
        print(f"[{_ts()}] [MANAGER] Mixed run complete.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Attack manager — launch all attacks sequentially or concurrently.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=["sequential", "mixed"],
        default="sequential",
        help="sequential: one at a time | mixed: all concurrent with stagger (default: sequential)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=20.0,
        help="Seconds each attack runs (sequential) or total run time (mixed). Default: 20",
    )
    parser.add_argument(
        "--stagger",
        type=float,
        default=2.0,
        help="Seconds between attack launches. Default: 2",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print the attack plan without running.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list:
        print("\nAttack plan:\n")
        for i, (name, cmd, desc) in enumerate(ATTACKS, 1):
            print(f"  {i}. {name:<12} — {desc}")
            print(f"              cmd: {cmd}")
        print()
        return 0

    # Check replay capture file exists
    capture_file = REPO_ROOT / "attack_clients" / "captured.jsonl"
    active_attacks = list(ATTACKS)
    if not capture_file.exists():
        print(
            f"[WARN] Replay attack needs a capture file: {capture_file}\n"
            f"       Run first:  python attack_clients/run_attack.py replay --mode capture\n"
            f"       Skipping replay attack for now.\n"
        )
        active_attacks = [(n, c, d) for n, c, d in active_attacks if n != "replay"]

    try:
        if args.scenario == "mixed":
            run_mixed_attacks(active_attacks, args.duration, args.stagger)
        else:
            run_sequential_attacks(active_attacks, args.duration, args.stagger)
    except KeyboardInterrupt:
        print(f"\n[{_ts()}] [MANAGER] Stopped by user.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
