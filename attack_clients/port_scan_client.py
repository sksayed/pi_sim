"""
port_scan_client.py — TCP port reconnaissance attack.

Three scan profiles matching CIC IoMT 2024 recon classes:

  --mode port_scan   Sequential TCP connect scan across a port range.
                     Matches Recon-Port_Scan.

  --mode os_scan     Probes the target with varied TCP flag combinations
                     (SYN-only, FIN, NULL, XMAS) to fingerprint the OS.
                     Matches Recon-OS_Scan.

  --mode vul_scan    Probes a fixed list of well-known service ports and
                     sends a banner-grabbing payload to each.
                     Matches Recon-VulScan.

Network signature the firewall should detect:
  - Many short-lived TCP flows from the same source (high SYN count)
  - Mix of RST and no-response results → low bwd bytes
  - Sequential port pattern (port_scan mode)
  - Unusual TCP flag combinations (os_scan mode)
  - Probes to high-entropy port list (vul_scan mode)

Environment variables:
  PORT_SCAN_START   First port to probe (default: 1)
  PORT_SCAN_END     Last port to probe (default: 1024)
  PORT_SCAN_TARGET  Target IP (default: GATEWAY_IP)
  ATTACK_RATE_HZ    Probes per second (0 = max, default: 0)
  ATTACK_BURST_COUNT Stop after N probes (0 = infinite, default: 0)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP  = os.getenv("GATEWAY_IP", "127.0.0.1")
SCAN_TARGET = os.getenv("PORT_SCAN_TARGET", GATEWAY_IP)
PORT_START  = int(os.getenv("PORT_SCAN_START", "1"))
PORT_END    = int(os.getenv("PORT_SCAN_END", "1024"))
RATE_HZ     = float(os.getenv("ATTACK_RATE_HZ", "0"))
BURST_COUNT = int(os.getenv("ATTACK_BURST_COUNT", "0"))

# Well-known ports probed by a vulnerability scanner
VULN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    512, 513, 514, 993, 995, 1883, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8883, 27017,
]

BANNER_PROBE = b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"


def _sleep() -> None:
    if RATE_HZ > 0:
        time.sleep(1.0 / RATE_HZ)


# ── Port scan (Recon-Port_Scan) ────────────────────────────────────────────────

def run_port_scan() -> None:
    print(f"[PORT-SCAN] Mode: port_scan (Recon-Port_Scan)  "
          f"target: {SCAN_TARGET}  range: {PORT_START}-{PORT_END}")
    probed = 0
    open_ports: list[int] = []

    for port in range(PORT_START, PORT_END + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            rc = s.connect_ex((SCAN_TARGET, port))
            s.close()
            if rc == 0:
                open_ports.append(port)
                print(f"[PORT-SCAN] OPEN   port {port}")
        except OSError:
            pass

        probed += 1
        if probed % 100 == 0:
            print(f"[PORT-SCAN] Probed {probed} ports  open={len(open_ports)}")

        if BURST_COUNT > 0 and probed >= BURST_COUNT:
            break
        _sleep()

    print(f"[PORT-SCAN] Done. Probed {probed} ports. Open: {open_ports}")


# ── OS scan (Recon-OS_Scan) ────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_tcp_packet(src_ip: str, dst_ip: str, dst_port: int, flags: int) -> bytes:
    """Craft a raw TCP packet with the given flag byte (no payload)."""
    src_port = 54321
    seq = 0
    ack = 0
    offset_res = (5 << 4)
    window = 65535
    urgent = 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack,
        offset_res, flags, window, 0, urgent,
    )

    # Pseudo-header for checksum
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, len(tcp_header))
    chk = _checksum(pseudo + tcp_header)

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack,
        offset_res, flags, window, chk, urgent,
    )

    # Minimal IP header
    ip_ihl_ver = (4 << 4) | 5
    ip_tos = 0
    ip_len = 20 + len(tcp_header)
    ip_id = 54321
    ip_frag = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_src = src_bytes
    ip_dst = dst_bytes
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag,
        ip_ttl, ip_proto, 0, ip_src, ip_dst,
    )
    ip_chk = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag,
        ip_ttl, ip_proto, ip_chk, ip_src, ip_dst,
    )
    return ip_header + tcp_header


# TCP flag byte constants
FLAG_SYN  = 0x02
FLAG_FIN  = 0x01
FLAG_NULL = 0x00
FLAG_XMAS = 0x29   # FIN + PSH + URG

OS_SCAN_PROBES = [
    ("SYN",  FLAG_SYN),
    ("FIN",  FLAG_FIN),
    ("NULL", FLAG_NULL),
    ("XMAS", FLAG_XMAS),
]


def run_os_scan() -> None:
    """Send varied TCP flag combinations to fingerprint the OS (needs root)."""
    print(f"[OS-SCAN] Mode: os_scan (Recon-OS_Scan)  target: {SCAN_TARGET}:{GATEWAY_IP}")
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("[OS-SCAN] ERROR: raw socket requires root. Run with sudo.", file=sys.stderr)
        sys.exit(1)

    src_ip = socket.gethostbyname(socket.gethostname()) or "127.0.0.1"
    probed = 0

    ports_to_probe = [22, 80, 443, 1883, 8080]
    try:
        while True:
            for port in ports_to_probe:
                for probe_name, flags in OS_SCAN_PROBES:
                    pkt = _build_tcp_packet(src_ip, SCAN_TARGET, port, flags)
                    try:
                        raw.sendto(pkt, (SCAN_TARGET, 0))
                    except OSError as e:
                        print(f"[OS-SCAN] sendto error: {e}", file=sys.stderr)

                    probed += 1
                    if probed % 20 == 0:
                        print(f"[OS-SCAN] Sent {probed} probes (last: {probe_name} → port {port})")

                    if BURST_COUNT > 0 and probed >= BURST_COUNT:
                        raise KeyboardInterrupt
                    _sleep()

    except KeyboardInterrupt:
        pass
    finally:
        raw.close()
    print(f"[OS-SCAN] Done. Total probes sent: {probed}")


# ── Vulnerability scan (Recon-VulScan) ────────────────────────────────────────

def run_vul_scan() -> None:
    """Connect to well-known service ports and grab banners (Recon-VulScan)."""
    print(f"[VUL-SCAN] Mode: vul_scan (Recon-VulScan)  target: {SCAN_TARGET}")
    print(f"[VUL-SCAN] Probing {len(VULN_PORTS)} well-known ports")
    probed = 0
    cycle = 0

    try:
        while True:
            cycle += 1
            for port in VULN_PORTS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((SCAN_TARGET, port)) == 0:
                        try:
                            s.sendall(BANNER_PROBE)
                            banner = s.recv(256)
                            print(f"[VUL-SCAN] port {port:5d}  OPEN  banner={banner[:40]!r}")
                        except OSError:
                            print(f"[VUL-SCAN] port {port:5d}  OPEN  (no banner)")
                    s.close()
                except OSError:
                    pass

                probed += 1
                if BURST_COUNT > 0 and probed >= BURST_COUNT:
                    raise KeyboardInterrupt
                _sleep()

            print(f"[VUL-SCAN] Cycle {cycle} complete. Total probes: {probed}")

    except KeyboardInterrupt:
        pass
    print(f"[VUL-SCAN] Done. Total probes sent: {probed}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="TCP port/OS/vulnerability reconnaissance")
    parser.add_argument(
        "--mode",
        choices=["port_scan", "os_scan", "vul_scan"],
        default="port_scan",
        help="port_scan: sequential TCP connect | os_scan: flag probes (root) | vul_scan: banner grab",
    )
    args = parser.parse_args()

    if args.mode == "os_scan":
        run_os_scan()
    elif args.mode == "vul_scan":
        run_vul_scan()
    else:
        run_port_scan()
