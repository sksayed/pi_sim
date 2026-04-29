"""
benign_burst_client.py — Legitimate MQTT client with burst-then-idle pattern.

Simulates an event-driven IoT sensor that sends a rapid batch of readings
when an event fires (e.g. motion detected, door opened, threshold crossed),
then goes idle until the next event.

Why this matters for the benign class:
  - Without this, the model learns that ANY momentarily high publish rate
    is an attack.  A burst client proves that short, finite-length high-rate
    windows are also normal — the key difference from a flood is that the
    burst stops and the device goes quiet.
  - The flow classifier sees: short burst of fwd packets → long idle → next
    burst.  Flood attacks never have the idle gap.

Network signature per burst-window flow (benign):
  - High instantaneous Srate but only for a few packets (low total count)
  - Short flow duration
  - Non-zero bwd (broker ACKs each message)
  - Normal Weight (both fwd and bwd non-zero)
  - Very low IAT variance within a burst, very high IAT variance across idle

Environment variables:
  BENIGN_BURST_DEVICE_ID     Device ID (default: benign-burst-<random>)
  BENIGN_BURST_TOPIC         Publish topic (default: nodes/<device_id>/data)
  BENIGN_BURST_SIZE_MIN      Min messages per burst (default: 5)
  BENIGN_BURST_SIZE_MAX      Max messages per burst (default: 20)
  BENIGN_BURST_RATE_HZ       Publish rate within a burst in msg/s (default: 10)
  BENIGN_BURST_IDLE_MIN_S    Min idle seconds between bursts (default: 3.0)
  BENIGN_BURST_IDLE_MAX_S    Max idle seconds between bursts (default: 15.0)
  BENIGN_BURST_COUNT         Stop after N total bursts (0 = forever, default: 0)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP    = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT  = int(os.getenv("GATEWAY_PORT", "1883"))

_rand_suffix  = uuid.uuid4().hex[:6]
DEVICE_ID     = os.getenv("BENIGN_BURST_DEVICE_ID", f"benign-burst-{_rand_suffix}")
PUB_TOPIC     = os.getenv("BENIGN_BURST_TOPIC",      f"nodes/{DEVICE_ID}/data")
BURST_MIN     = int(os.getenv("BENIGN_BURST_SIZE_MIN",   "5"))
BURST_MAX     = int(os.getenv("BENIGN_BURST_SIZE_MAX",   "20"))
BURST_RATE_HZ = float(os.getenv("BENIGN_BURST_RATE_HZ",  "10"))
IDLE_MIN_S    = float(os.getenv("BENIGN_BURST_IDLE_MIN_S", "3.0"))
IDLE_MAX_S    = float(os.getenv("BENIGN_BURST_IDLE_MAX_S", "15.0"))
MAX_BURSTS    = int(os.getenv("BENIGN_BURST_COUNT", "0"))

_EVENTS = [
    "motion_detected",
    "door_opened",
    "temperature_threshold",
    "humidity_spike",
    "vibration_alert",
    "light_level_change",
]


def _reading_payload(seq: int, burst_id: int, event: str) -> bytes:
    return json.dumps({
        "device_id":  DEVICE_ID,
        "crypto_type": "benign",
        "seq":        seq,
        "burst_id":   burst_id,
        "event":      event,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "value":      round(random.uniform(0.0, 100.0), 3),
        "unit":       random.choice(["celsius", "lux", "rh", "m/s2"]),
    }).encode()


def run() -> None:
    connected = False

    def on_connect(client, userdata, flags, rc):
        nonlocal connected
        connected = rc == 0
        if rc == 0:
            print(f"[BENIGN-BURST] Connected to {GATEWAY_IP}:{GATEWAY_PORT}  "
                  f"topic={PUB_TOPIC}")
        else:
            print(f"[BENIGN-BURST] Connection failed (rc={rc})", file=sys.stderr)

    c = mqtt.Client(client_id=f"benign-burst-{_rand_suffix}", clean_session=True)
    c.on_connect = on_connect

    print(f"[BENIGN-BURST] Connecting to {GATEWAY_IP}:{GATEWAY_PORT} ...")
    try:
        c.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[BENIGN-BURST] Could not connect: {exc}", file=sys.stderr)
        sys.exit(1)

    c.loop_start()
    # Wait for connection
    for _ in range(20):
        if connected:
            break
        time.sleep(0.1)

    sleep_between = 1.0 / BURST_RATE_HZ
    seq       = 1
    burst_num = 0
    total_sent = 0

    try:
        while True:
            burst_num += 1
            burst_size = random.randint(BURST_MIN, BURST_MAX)
            event      = random.choice(_EVENTS)
            print(f"[BENIGN-BURST] Burst #{burst_num}  event={event}  "
                  f"size={burst_size}  rate={BURST_RATE_HZ:.0f}msg/s")

            for _ in range(burst_size):
                payload = _reading_payload(seq, burst_num, event)
                res = c.publish(PUB_TOPIC, payload=payload, qos=0)
                if res.rc == mqtt.MQTT_ERR_SUCCESS:
                    total_sent += 1
                seq += 1
                time.sleep(sleep_between)

            print(f"[BENIGN-BURST] Burst #{burst_num} done  total_sent={total_sent}")

            if MAX_BURSTS > 0 and burst_num >= MAX_BURSTS:
                break

            idle = random.uniform(IDLE_MIN_S, IDLE_MAX_S)
            print(f"[BENIGN-BURST] Idle for {idle:.1f}s ...")
            time.sleep(idle)

    except KeyboardInterrupt:
        print(f"\n[BENIGN-BURST] Stopped. Bursts={burst_num}  total_sent={total_sent}")
    finally:
        c.loop_stop()
        c.disconnect()


if __name__ == "__main__":
    run()
