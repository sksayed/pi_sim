"""
benign_mixed_client.py — Legitimate MQTT client that both publishes and subscribes.

Simulates a real IoT device that:
  1. Subscribes to a control/command topic (e.g. actuator commands from gateway).
  2. Publishes sensor readings at a randomised rate (uniform in
     [BENIGN_MIXED_MIN_INTERVAL_S, BENIGN_MIXED_MAX_INTERVAL_S]).
  3. Occasionally goes quiet for a short idle period, then resumes.

Why this matters for the benign class:
  - Flood attacks have a fixed, maximum-rate send pattern.
  - A real sensor publishes at variable intervals driven by its sampling
    period — adding temporal jitter to the IAT distribution.
  - Because the client also subscribes, the flow is genuinely bidirectional
    (publish ACKs + subscribed messages = non-trivial bwd bytes).

Network signature (benign):
  - Moderate, variable Srate (not maximised)
  - Non-zero Drate (CONNACK + broker pushes + QoS ACKs)
  - Variable IAT (random sleep between publishes)
  - Normal Weight (fwd and bwd both non-trivial)

Environment variables:
  BENIGN_MIXED_DEVICE_ID         Device ID to publish under (default: benign-mixed-<random>)
  BENIGN_MIXED_PUB_TOPIC         Publish topic (default: nodes/<device_id>/data)
  BENIGN_MIXED_SUB_TOPIC         Subscribe topic (default: nodes/<device_id>/cmd)
  BENIGN_MIXED_MIN_INTERVAL_S    Min seconds between publishes (default: 0.5)
  BENIGN_MIXED_MAX_INTERVAL_S    Max seconds between publishes (default: 3.0)
  BENIGN_MIXED_IDLE_PROB         Probability of entering a short idle after each message (default: 0.05)
  BENIGN_MIXED_IDLE_DURATION_S   Seconds to stay idle when triggered (default: 5.0)
  BENIGN_MIXED_COUNT             Stop after N publishes (0 = forever, default: 0)
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

try:
    from benign_clients.send_log import log_connect, log_send
except ImportError:
    from send_log import log_connect, log_send

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "1883"))

_rand_suffix = uuid.uuid4().hex[:6]
DEVICE_ID    = os.getenv("BENIGN_MIXED_DEVICE_ID", f"benign-mixed-{_rand_suffix}")
PUB_TOPIC    = os.getenv("BENIGN_MIXED_PUB_TOPIC",  f"nodes/{DEVICE_ID}/data")
SUB_TOPIC    = os.getenv("BENIGN_MIXED_SUB_TOPIC",   f"nodes/{DEVICE_ID}/cmd")
MIN_INTERVAL = float(os.getenv("BENIGN_MIXED_MIN_INTERVAL_S", "0.5"))
MAX_INTERVAL = float(os.getenv("BENIGN_MIXED_MAX_INTERVAL_S", "3.0"))
IDLE_PROB    = float(os.getenv("BENIGN_MIXED_IDLE_PROB", "0.05"))
IDLE_DUR_S   = float(os.getenv("BENIGN_MIXED_IDLE_DURATION_S", "5.0"))
MAX_COUNT    = int(os.getenv("BENIGN_MIXED_COUNT", "0"))


def _sensor_payload(seq: int) -> bytes:
    return json.dumps({
        "device_id":   DEVICE_ID,
        "crypto_type": "benign",
        "seq":         seq,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "temperature": round(20.0 + random.uniform(-2.0, 2.0), 2),
        "humidity":    round(55.0 + random.uniform(-5.0, 5.0), 2),
        "battery_mv":  random.randint(3200, 3700),
        "t_publish_ns": time.time_ns(),
    }).encode()


def run() -> None:
    received_cmds = 0

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            log_connect("mixed", DEVICE_ID, client)
            client.subscribe(SUB_TOPIC, qos=1)
            print(f"[BENIGN-MIXED] Connected. pub={PUB_TOPIC}  sub={SUB_TOPIC}")
        else:
            print(f"[BENIGN-MIXED] Connection failed (rc={rc})", file=sys.stderr)

    def on_message(client, userdata, msg):
        nonlocal received_cmds
        received_cmds += 1
        print(f"[BENIGN-MIXED] CMD received #{received_cmds}: {msg.payload[:60]!r}")

    c = mqtt.Client(client_id=f"benign-mixed-{_rand_suffix}", clean_session=True)
    c.on_connect = on_connect
    c.on_message = on_message

    print(f"[BENIGN-MIXED] Connecting to {GATEWAY_IP}:{GATEWAY_PORT} ...")
    try:
        c.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[BENIGN-MIXED] Could not connect: {exc}", file=sys.stderr)
        sys.exit(1)

    c.loop_start()
    seq = 1
    sent = 0

    try:
        while True:
            payload = _sensor_payload(seq)
            res = c.publish(PUB_TOPIC, payload=payload, qos=1)
            log_send("mixed", DEVICE_ID, seq, 1, res.rc)
            if res.rc == mqtt.MQTT_ERR_SUCCESS:
                sent += 1
                print(f"[BENIGN-MIXED] Published #{sent}  seq={seq}  "
                      f"size={len(payload)}B")

            seq += 1
            if MAX_COUNT > 0 and sent >= MAX_COUNT:
                break

            # Occasionally go idle (simulates sensor sleeping or event-driven gaps)
            if random.random() < IDLE_PROB:
                idle = IDLE_DUR_S + random.uniform(-1.0, 1.0)
                print(f"[BENIGN-MIXED] Idle for {idle:.1f}s ...")
                time.sleep(max(0.1, idle))
            else:
                time.sleep(random.uniform(MIN_INTERVAL, MAX_INTERVAL))

    except KeyboardInterrupt:
        print(f"\n[BENIGN-MIXED] Stopped. Published {sent}, received {received_cmds} cmds.")
    finally:
        c.loop_stop()
        c.disconnect()


if __name__ == "__main__":
    run()
