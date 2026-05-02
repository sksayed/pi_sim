"""
run_benign.py — CLI launcher for all benign traffic simulation clients.

Usage:
    python benign_clients/run_benign.py steady
    python benign_clients/run_benign.py subscriber
    python benign_clients/run_benign.py subscriber --topics nodes/+/data --qos 1

    python benign_clients/run_benign.py mixed
    python benign_clients/run_benign.py mixed --min-interval 0.5 --max-interval 3.0

    python benign_clients/run_benign.py burst
    python benign_clients/run_benign.py burst --burst-min 5 --burst-max 20 --rate 10

    python benign_clients/run_benign.py --list

    # Run all four concurrently for 60 seconds
    python benign_clients/run_benign.py all --duration 60

All clients respect GATEWAY_IP and GATEWAY_PORT from .env.
"""

from __future__ import annotations

import argparse
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON    = str(REPO_ROOT / ".venv" / "bin" / "python")

CLIENTS = {
    "steady": {
        "description": "Steady plaintext publish (crypto_type=benign) — fixed-rate baseline benign",
        "extra_args": [
            ("--interval", "PUBLISH_INTERVAL", "Seconds between publishes (default: 2)"),
        ],
    },
    "subscriber": {
        "description": "Subscribe to all node topics — generates bwd-heavy bidirectional flows",
        "extra_args": [
            ("--topics",   "BENIGN_SUB_TOPICS",      "Comma-separated topics (default: nodes/+/data)"),
            ("--qos",      "BENIGN_SUB_QOS",          "QoS level 0/1/2 (default: 1)"),
            ("--duration", "BENIGN_SUB_DURATION_S",   "Run for N seconds (0 = forever, default: 0)"),
        ],
    },
    "mixed": {
        "description": "Publish + subscribe at variable rate — simulates a real IoT sensor node",
        "extra_args": [
            ("--min-interval", "BENIGN_MIXED_MIN_INTERVAL_S",  "Min seconds between publishes (default: 0.5)"),
            ("--max-interval", "BENIGN_MIXED_MAX_INTERVAL_S",  "Max seconds between publishes (default: 3.0)"),
            ("--idle-prob",    "BENIGN_MIXED_IDLE_PROB",       "Probability of random idle pause (default: 0.05)"),
            ("--count",        "BENIGN_MIXED_COUNT",           "Stop after N publishes (0 = forever, default: 0)"),
        ],
    },
    "burst": {
        "description": "Burst publish + idle — event-driven sensor (short high-rate windows then quiet)",
        "extra_args": [
            ("--burst-min", "BENIGN_BURST_SIZE_MIN",   "Min messages per burst (default: 5)"),
            ("--burst-max", "BENIGN_BURST_SIZE_MAX",   "Max messages per burst (default: 20)"),
            ("--rate",      "BENIGN_BURST_RATE_HZ",    "Publish rate within burst in msg/s (default: 10)"),
            ("--idle-min",  "BENIGN_BURST_IDLE_MIN_S", "Min idle seconds between bursts (default: 3)"),
            ("--idle-max",  "BENIGN_BURST_IDLE_MAX_S", "Max idle seconds between bursts (default: 15)"),
            ("--count",     "BENIGN_BURST_COUNT",      "Stop after N bursts (0 = forever, default: 0)"),
        ],
    },
}


def _list_clients() -> None:
    print("\nAvailable benign client types:\n")
    for name, info in CLIENTS.items():
        print(f"  {name:<12}  {info['description']}")
        for flag, env, desc in info["extra_args"]:
            print(f"               {flag:<16} {desc}")
        print()
    print("  all           Run all three clients concurrently")
    print("               --duration N   Seconds to run (default: 60)")
    print()


def _set_env(key: str, value: str | None) -> None:
    if value is not None:
        os.environ[key] = value


def _launch(cmd: str, name: str) -> subprocess.Popen:
    print(f"[BENIGN-MANAGER] Starting {name} ...")
    return subprocess.Popen(
        shlex.split(cmd),
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
    )


def _stop(proc: subprocess.Popen, name: str) -> None:
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    print(f"[BENIGN-MANAGER] Stopped {name}")


def run_all(duration: float) -> None:
    cmds = [
        ("steady",     f"{PYTHON} benign_clients/run_benign.py steady"),
        ("subscriber", f"{PYTHON} benign_clients/run_benign.py subscriber"),
        ("mixed",      f"{PYTHON} benign_clients/run_benign.py mixed"),
        ("burst",      f"{PYTHON} benign_clients/run_benign.py burst"),
    ]
    procs = []
    try:
        for name, cmd in cmds:
            procs.append((name, _launch(cmd, name)))
            time.sleep(0.5)

        print(f"[BENIGN-MANAGER] All clients running. Duration: {duration}s")
        time.sleep(duration)

    except KeyboardInterrupt:
        print("\n[BENIGN-MANAGER] Interrupted.")
    finally:
        for name, proc in procs:
            _stop(proc, name)
        print("[BENIGN-MANAGER] Done.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benign MQTT traffic simulation launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("client", nargs="?",
                        choices=list(CLIENTS.keys()) + ["all"],  # steady, subscriber, mixed, burst, all
                        help="Client type to run (or 'all' to run all concurrently)")
    parser.add_argument("--list", action="store_true", help="List all client types")
    # steady (client_a) args
    parser.add_argument("--interval",     help="PUBLISH_INTERVAL override (seconds, default: 2)")
    # subscriber args
    parser.add_argument("--topics",       help="BENIGN_SUB_TOPICS override")
    parser.add_argument("--qos",          help="BENIGN_SUB_QOS override")
    parser.add_argument("--duration",     help="Duration seconds (subscriber or all mode)")
    # mixed args
    parser.add_argument("--min-interval", help="BENIGN_MIXED_MIN_INTERVAL_S override")
    parser.add_argument("--max-interval", help="BENIGN_MIXED_MAX_INTERVAL_S override")
    parser.add_argument("--idle-prob",    help="BENIGN_MIXED_IDLE_PROB override")
    # burst args
    parser.add_argument("--burst-min",    help="BENIGN_BURST_SIZE_MIN override")
    parser.add_argument("--burst-max",    help="BENIGN_BURST_SIZE_MAX override")
    parser.add_argument("--rate",         help="BENIGN_BURST_RATE_HZ override")
    parser.add_argument("--idle-min",     help="BENIGN_BURST_IDLE_MIN_S override")
    parser.add_argument("--idle-max",     help="BENIGN_BURST_IDLE_MAX_S override")
    # shared
    parser.add_argument("--count",        help="Stop-after-N override (mixed or burst)")
    args = parser.parse_args()

    if args.list or not args.client:
        _list_clients()
        return

    if args.client == "all":
        run_all(float(args.duration or 60))
        return

    # Apply env overrides
    _set_env("PUBLISH_INTERVAL",           getattr(args, "interval", None))
    _set_env("BENIGN_SUB_TOPICS",          args.topics)
    _set_env("BENIGN_SUB_QOS",             args.qos)
    _set_env("BENIGN_SUB_DURATION_S",      args.duration)
    _set_env("BENIGN_MIXED_MIN_INTERVAL_S", args.min_interval)
    _set_env("BENIGN_MIXED_MAX_INTERVAL_S", args.max_interval)
    _set_env("BENIGN_MIXED_IDLE_PROB",     args.idle_prob)
    _set_env("BENIGN_MIXED_COUNT",         args.count)
    _set_env("BENIGN_BURST_SIZE_MIN",      args.burst_min)
    _set_env("BENIGN_BURST_SIZE_MAX",      args.burst_max)
    _set_env("BENIGN_BURST_RATE_HZ",       args.rate)
    _set_env("BENIGN_BURST_IDLE_MIN_S",    args.idle_min)
    _set_env("BENIGN_BURST_IDLE_MAX_S",    args.idle_max)
    _set_env("BENIGN_BURST_COUNT",         args.count)

    if args.client == "steady":
        from benign_clients.benign_steady_client import run
        run()
    elif args.client == "subscriber":
        from benign_clients.benign_subscriber import run
        run()
    elif args.client == "mixed":
        from benign_clients.benign_mixed_client import run
        run()
    elif args.client == "burst":
        from benign_clients.benign_burst_client import run
        run()


if __name__ == "__main__":
    sys.path.insert(0, str(REPO_ROOT))
    main()
