"""
run_attack.py — CLI launcher for all attack simulation clients.

Usage:
    python attack_clients/run_attack.py flood
    python attack_clients/run_attack.py flood --rate 500 --count 1000

    python attack_clients/run_attack.py replay --mode capture
    python attack_clients/run_attack.py replay --mode replay --rate 5

    python attack_clients/run_attack.py malformed --strategy 2
    python attack_clients/run_attack.py malformed --rate 1

    python attack_clients/run_attack.py slowloris --mode hold --connections 100
    python attack_clients/run_attack.py slowloris --mode exhaust

    python attack_clients/run_attack.py --list

All attacks also respect GATEWAY_IP and GATEWAY_PORT from .env.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Ensure repo root is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


ATTACKS = {
    "flood": {
        "description": "High-rate MQTT publish flood (max speed, random ciphertext)",
        "extra_args": [
            ("--rate",  "ATTACK_RATE_HZ",        "Messages per second (0 = max speed, default: 0)"),
            ("--count", "ATTACK_BURST_COUNT",     "Stop after N messages (0 = infinite, default: 0)"),
            ("--topic", "ATTACK_FLOOD_TARGET",    "Override MQTT topic"),
        ],
    },
    "replay": {
        "description": "Replay previously captured legitimate messages",
        "extra_args": [
            ("--rate",  "ATTACK_RATE_HZ",         "Replay speed in msg/s (default: 2)"),
            ("--count", "ATTACK_BURST_COUNT",      "Stop after N replays (default: 0)"),
            ("--file",  "REPLAY_CAPTURE_FILE",     "Path to .jsonl capture file"),
            ("--topic", "REPLAY_TARGET_TOPIC",     "Override publish topic"),
        ],
        "modes": ["capture", "replay"],
        "mode_help": "capture: record traffic | replay: re-publish saved messages",
    },
    "malformed": {
        "description": "Send malformed/garbage MQTT payloads (8 mutation strategies)",
        "extra_args": [
            ("--rate",     "ATTACK_RATE_HZ",      "Messages per second (default: 1)"),
            ("--count",    "ATTACK_BURST_COUNT",   "Stop after N messages (default: 0)"),
            ("--strategy", "MALFORMED_STRATEGY",   "Fix a single strategy 0-7 (default: cycle all)"),
        ],
    },
    "slowloris": {
        "description": "Slow-connection resource exhaustion (many persistent TCP connections)",
        "extra_args": [
            ("--connections", "SLOWLORIS_CONNECTIONS", "Concurrent connections to open (default: 50)"),
            ("--drip",        "SLOWLORIS_DRIP_S",      "Seconds between keep-alive drips (default: 15)"),
            ("--count",       "ATTACK_BURST_COUNT",    "Stop after opening N connections (default: 0)"),
        ],
        "modes": ["hold", "exhaust"],
        "mode_help": "hold: persistent drip | exhaust: open as fast as possible",
    },
}


def list_attacks() -> None:
    print("\nAvailable attack types:\n")
    for name, info in ATTACKS.items():
        print(f"  {name:<12}  {info['description']}")
        if "modes" in info:
            print(f"               Modes: {', '.join(info['modes'])}  ({info['mode_help']})")
        for flag, env, desc in info.get("extra_args", []):
            print(f"               {flag:<14} {desc}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attack simulation launcher for MQTT IDS/IPS testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("attack", nargs="?", choices=list(ATTACKS.keys()),
                        help="Attack type to run")
    parser.add_argument("--list", action="store_true",
                        help="List all available attacks and their options")
    parser.add_argument("--mode", help="Sub-mode for replay / slowloris attacks")
    parser.add_argument("--rate",        help="ATTACK_RATE_HZ override")
    parser.add_argument("--count",       help="ATTACK_BURST_COUNT override")
    parser.add_argument("--topic",       help="Topic override (flood / replay)")
    parser.add_argument("--file",        help="REPLAY_CAPTURE_FILE override")
    parser.add_argument("--strategy",    help="MALFORMED_STRATEGY override (0-7)")
    parser.add_argument("--connections", help="SLOWLORIS_CONNECTIONS override")
    parser.add_argument("--drip",        help="SLOWLORIS_DRIP_S override")
    args = parser.parse_args()

    if args.list or not args.attack:
        list_attacks()
        return

    # Apply CLI overrides to environment so submodules pick them up via os.getenv
    _set_env("ATTACK_RATE_HZ",        args.rate)
    _set_env("ATTACK_BURST_COUNT",    args.count)
    _set_env("MALFORMED_STRATEGY",    args.strategy)
    _set_env("SLOWLORIS_CONNECTIONS", args.connections)
    _set_env("SLOWLORIS_DRIP_S",      args.drip)

    if args.attack == "flood":
        _set_env("ATTACK_FLOOD_TARGET", args.topic)
        from attack_clients.flood_client import FloodClient
        FloodClient().run()

    elif args.attack == "replay":
        _set_env("REPLAY_CAPTURE_FILE",  args.file)
        _set_env("REPLAY_TARGET_TOPIC",  args.topic)
        from attack_clients.replay_client import run_capture, run_replay
        mode = args.mode or "replay"
        if mode == "capture":
            run_capture()
        else:
            run_replay()

    elif args.attack == "malformed":
        from attack_clients.malformed_client import MalformedClient
        MalformedClient().run()

    elif args.attack == "slowloris":
        from attack_clients.slowloris_client import run_hold, run_exhaust
        mode = args.mode or "hold"
        if mode == "exhaust":
            run_exhaust()
        else:
            run_hold()


def _set_env(key: str, value: str | None) -> None:
    if value is not None:
        os.environ[key] = value


if __name__ == "__main__":
    main()
