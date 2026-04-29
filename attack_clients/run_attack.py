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

    python attack_clients/run_attack.py connect_flood --mode serial
    python attack_clients/run_attack.py connect_flood --mode parallel --threads 20

    python attack_clients/run_attack.py port_scan --mode port_scan
    python attack_clients/run_attack.py port_scan --mode os_scan    # requires root
    python attack_clients/run_attack.py port_scan --mode vul_scan

    python attack_clients/run_attack.py udp_flood --mode dos
    python attack_clients/run_attack.py udp_flood --mode ddos --threads 10

    python attack_clients/run_attack.py icmp_flood --mode dos       # requires root
    python attack_clients/run_attack.py icmp_flood --mode ddos      # requires root

    python attack_clients/run_attack.py syn_flood --mode dos        # requires root
    python attack_clients/run_attack.py syn_flood --mode ddos       # requires root

    python attack_clients/run_attack.py arp_spoof                   # requires root

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
        "description": "High-rate MQTT publish flood — MQTT-DoS/DDoS-Publish_Flood",
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
        "description": "Malformed/garbage MQTT payloads — MQTT-Malformed_Data",
        "extra_args": [
            ("--rate",     "ATTACK_RATE_HZ",      "Messages per second (default: 1)"),
            ("--count",    "ATTACK_BURST_COUNT",   "Stop after N messages (default: 0)"),
            ("--strategy", "MALFORMED_STRATEGY",   "Fix a single strategy 0-7 (default: cycle all)"),
        ],
    },
    "slowloris": {
        "description": "Slow-connection resource exhaustion — TCP_IP-DoS-TCP",
        "extra_args": [
            ("--connections", "SLOWLORIS_CONNECTIONS", "Concurrent connections to open (default: 50)"),
            ("--drip",        "SLOWLORIS_DRIP_S",      "Seconds between keep-alive drips (default: 15)"),
            ("--count",       "ATTACK_BURST_COUNT",    "Stop after opening N connections (default: 0)"),
        ],
        "modes": ["hold", "exhaust"],
        "mode_help": "hold: persistent drip | exhaust: open as fast as possible",
    },
    "connect_flood": {
        "description": "MQTT CONNECT/DISCONNECT flood — MQTT-DoS/DDoS-Connect_Flood",
        "extra_args": [
            ("--rate",    "ATTACK_RATE_HZ",            "Connections per second per thread (0 = max, default: 0)"),
            ("--count",   "ATTACK_BURST_COUNT",         "Stop after N total connections (default: 0)"),
            ("--threads", "CONNECT_FLOOD_THREADS",      "Thread count for parallel mode (default: 20)"),
        ],
        "modes": ["serial", "parallel"],
        "mode_help": "serial=MQTT-DoS-Connect_Flood | parallel=MQTT-DDoS-Connect_Flood",
    },
    "port_scan": {
        "description": "TCP port/OS/vulnerability recon — Recon-Port_Scan, Recon-OS_Scan, Recon-VulScan",
        "extra_args": [
            ("--rate",  "ATTACK_RATE_HZ",      "Probes per second (0 = max, default: 0)"),
            ("--count", "ATTACK_BURST_COUNT",   "Stop after N probes (default: 0)"),
            ("--start", "PORT_SCAN_START",      "First port (default: 1)"),
            ("--end",   "PORT_SCAN_END",        "Last port (default: 1024)"),
        ],
        "modes": ["port_scan", "os_scan", "vul_scan"],
        "mode_help": "port_scan: TCP connect scan | os_scan: flag probes (root) | vul_scan: banner grab",
    },
    "udp_flood": {
        "description": "UDP datagram flood — TCP_IP-DoS/DDoS-UDP (needs iptables UDP rule for NFQUEUE)",
        "extra_args": [
            ("--rate",    "ATTACK_RATE_HZ",          "Datagrams/s per thread (0 = max, default: 0)"),
            ("--count",   "ATTACK_BURST_COUNT",       "Stop after N datagrams (default: 0)"),
            ("--threads", "UDP_FLOOD_THREADS",        "Thread count for ddos mode (default: 10)"),
            ("--payload", "UDP_FLOOD_PAYLOAD_SIZE",   "Datagram payload size in bytes (default: 1024)"),
        ],
        "modes": ["dos", "ddos"],
        "mode_help": "dos=single-thread | ddos=multi-thread",
    },
    "icmp_flood": {
        "description": "ICMP echo-request flood — TCP_IP-DoS/DDoS-ICMP (requires root)",
        "extra_args": [
            ("--rate",    "ATTACK_RATE_HZ",       "Packets/s per thread (0 = max, default: 0)"),
            ("--count",   "ATTACK_BURST_COUNT",    "Stop after N packets (default: 0)"),
            ("--threads", "ICMP_FLOOD_THREADS",    "Thread count for ddos mode (default: 10)"),
            ("--payload", "ICMP_FLOOD_PAYLOAD",    "ICMP payload size in bytes (default: 56)"),
        ],
        "modes": ["dos", "ddos"],
        "mode_help": "dos=single-thread | ddos=multi-thread",
    },
    "syn_flood": {
        "description": "TCP SYN flood — TCP_IP-DoS/DDoS-SYN (requires root)",
        "extra_args": [
            ("--rate",    "ATTACK_RATE_HZ",       "Packets/s per thread (0 = max, default: 0)"),
            ("--count",   "ATTACK_BURST_COUNT",    "Stop after N packets (default: 0)"),
            ("--threads", "SYN_FLOOD_THREADS",     "Thread count for ddos mode (default: 10)"),
        ],
        "modes": ["dos", "ddos"],
        "mode_help": "dos=single-thread | ddos=multi-thread",
    },
    "arp_spoof": {
        "description": "Gratuitous ARP reply flood — ARP_Spoofing (requires root, isolated lab only)",
        "extra_args": [
            ("--rate",  "ATTACK_RATE_HZ",       "Packets per second (default: 2)"),
            ("--count", "ATTACK_BURST_COUNT",    "Stop after N packets (default: 0)"),
            ("--iface", "ARP_SPOOF_INTERFACE",   "Network interface (default: eth0)"),
        ],
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
    # Shared / multi-use args
    parser.add_argument("--mode",    help="Sub-mode (attack-specific)")
    parser.add_argument("--rate",    help="ATTACK_RATE_HZ override")
    parser.add_argument("--count",   help="ATTACK_BURST_COUNT override")
    parser.add_argument("--threads", help="Thread count override (connect_flood/udp_flood/icmp_flood/syn_flood)")
    parser.add_argument("--payload", help="Payload size in bytes (udp_flood/icmp_flood)")
    # flood / replay
    parser.add_argument("--topic",   help="MQTT topic override (flood / replay)")
    parser.add_argument("--file",    help="REPLAY_CAPTURE_FILE override")
    # malformed
    parser.add_argument("--strategy", help="MALFORMED_STRATEGY override (0-7)")
    # slowloris
    parser.add_argument("--connections", help="SLOWLORIS_CONNECTIONS override")
    parser.add_argument("--drip",        help="SLOWLORIS_DRIP_S override")
    # port_scan
    parser.add_argument("--start", help="PORT_SCAN_START override")
    parser.add_argument("--end",   help="PORT_SCAN_END override")
    # arp_spoof
    parser.add_argument("--iface", help="ARP_SPOOF_INTERFACE override")
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
    _set_env("PORT_SCAN_START",       args.start)
    _set_env("PORT_SCAN_END",         args.end)
    _set_env("ARP_SPOOF_INTERFACE",   args.iface)

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

    elif args.attack == "connect_flood":
        _set_env("CONNECT_FLOOD_THREADS", args.threads)
        from attack_clients.connect_flood_client import run_serial, run_parallel
        mode = args.mode or "serial"
        if mode == "parallel":
            run_parallel()
        else:
            run_serial()

    elif args.attack == "port_scan":
        from attack_clients.port_scan_client import run_port_scan, run_os_scan, run_vul_scan
        mode = args.mode or "port_scan"
        if mode == "os_scan":
            run_os_scan()
        elif mode == "vul_scan":
            run_vul_scan()
        else:
            run_port_scan()

    elif args.attack == "udp_flood":
        _set_env("UDP_FLOOD_THREADS",      args.threads)
        _set_env("UDP_FLOOD_PAYLOAD_SIZE", args.payload)
        from attack_clients.udp_flood_client import run_dos as udp_dos, run_ddos as udp_ddos
        mode = args.mode or "dos"
        if mode == "ddos":
            udp_ddos()
        else:
            udp_dos()

    elif args.attack == "icmp_flood":
        _set_env("ICMP_FLOOD_THREADS", args.threads)
        _set_env("ICMP_FLOOD_PAYLOAD", args.payload)
        from attack_clients.icmp_flood_client import run_dos as icmp_dos, run_ddos as icmp_ddos
        mode = args.mode or "dos"
        if mode == "ddos":
            icmp_ddos()
        else:
            icmp_dos()

    elif args.attack == "syn_flood":
        _set_env("SYN_FLOOD_THREADS", args.threads)
        from attack_clients.syn_flood_client import run_dos as syn_dos, run_ddos as syn_ddos
        mode = args.mode or "dos"
        if mode == "ddos":
            syn_ddos()
        else:
            syn_dos()

    elif args.attack == "arp_spoof":
        from attack_clients.arp_spoof_client import run
        run()


def _set_env(key: str, value: str | None) -> None:
    if value is not None:
        os.environ[key] = value


if __name__ == "__main__":
    main()
