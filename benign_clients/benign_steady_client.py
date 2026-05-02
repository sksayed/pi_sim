"""
benign_steady_client.py — Steady-rate plaintext MQTT benign sensor client.

Simulates a simple IoT sensor that publishes readings at a fixed interval
with no client-side encryption.  The gateway re-encrypts the payload with
PQC before forwarding to cloud (benign_pipeline.py).

Why this matters for the benign class:
  - Provides a steady, predictable IAT distribution (contrast with burst/mixed).
  - The firewall should classify this as benign based on low, constant Srate
    and balanced bidirectional flow (CONNACK + QoS ACKs from broker).

Network signature (benign):
  - Low, fixed Srate (paced by PUBLISH_INTERVAL seconds)
  - Non-zero Drate (CONNACK + QoS ACKs)
  - Very low IAT variance (fixed sleep)
  - Normal Weight (both fwd and bwd non-trivial)

Environment variables:
  BENIGN_STEADY_DEVICE_ID    Device ID (default: benign-steady-<random>)
  BENIGN_STEADY_TOPIC        Publish topic (default: nodes/<device_id>/data)
  PUBLISH_INTERVAL           Seconds between publishes (default: 2)
  BENIGN_STEADY_COUNT        Stop after N messages (0 = forever, default: 0)
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

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "1883"))

_rand_suffix = uuid.uuid4().hex[:6]
DEVICE_ID    = os.getenv("BENIGN_STEADY_DEVICE_ID", f"benign-steady-{_rand_suffix}")
PUB_TOPIC    = os.getenv("BENIGN_STEADY_TOPIC", f"nodes/{DEVICE_ID}/data")
INTERVAL_S   = float(os.getenv("PUBLISH_INTERVAL", "2"))
MAX_COUNT    = int(os.getenv("BENIGN_STEADY_COUNT", "0"))


def _sensor_payload(seq: int) -> bytes:
    return json.dumps({
        "device_id":   DEVICE_ID,
        "crypto_type": "benign",
        "seq":         seq,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "temperature": round(20.0 + random.uniform(-3.0, 3.0), 2),
        "humidity":    round(55.0 + random.uniform(-5.0, 5.0), 2),
        "pressure_hpa": round(1013.0 + random.uniform(-2.0, 2.0), 1),
        "battery_mv":  random.randint(3200, 3700),
        "t_publish_ns": time.time_ns(),
    }).encode()


def run() -> None:
    connected = False

    def on_connect(client, userdata, flags, rc):
        nonlocal connected
        connected = rc == 0
        if rc == 0:
            print(f"[BENIGN-STEADY] Connected to {GATEWAY_IP}:{GATEWAY_PORT}  "
                  f"topic={PUB_TOPIC}  interval={INTERVAL_S}s")
        else:
            print(f"[BENIGN-STEADY] Connection failed (rc={rc})", file=sys.stderr)

    def on_disconnect(client, userdata, rc):
        if rc != 0:
            print(f"[BENIGN-STEADY] Disconnected unexpectedly (rc={rc})", file=sys.stderr)

    c = mqtt.Client(client_id=f"benign-steady-{_rand_suffix}", clean_session=True)
    c.on_connect    = on_connect
    c.on_disconnect = on_disconnect

    print(f"[BENIGN-STEADY] Connecting to {GATEWAY_IP}:{GATEWAY_PORT} ...")
    try:
        c.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[BENIGN-STEADY] Could not connect: {exc}", file=sys.stderr)
        sys.exit(1)

    c.loop_start()
    for _ in range(20):
        if connected:
            break
        time.sleep(0.1)

    seq  = 1
    sent = 0

    try:
        while True:
            payload = _sensor_payload(seq)
            res = c.publish(PUB_TOPIC, payload=payload, qos=0)
            if res.rc == mqtt.MQTT_ERR_SUCCESS:
                sent += 1
                print(f"[BENIGN-STEADY] Published #{sent}  seq={seq}  size={len(payload)}B")

            seq += 1
            if MAX_COUNT > 0 and sent >= MAX_COUNT:
                break

            time.sleep(INTERVAL_S)

    except KeyboardInterrupt:
        print(f"\n[BENIGN-STEADY] Stopped after {sent} messages.")
    finally:
        c.loop_stop()
        c.disconnect()


if __name__ == "__main__":
    run()
