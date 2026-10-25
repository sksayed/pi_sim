"""
benign_subscriber.py — Legitimate MQTT subscriber (IoT dashboard / monitor).

Connects to the broker and subscribes to all node data topics using the
wildcard `nodes/+/data`.  Incoming messages are acknowledged at the MQTT
layer (QoS 1), generating a flow that is **backward-heavy**: many incoming
bytes (broker → subscriber) with only small upstream MQTT control packets
(SUBSCRIBE, PINGREQ).

Why this matters for the benign class:
  - Flood attacks produce fwd >> bwd (Weight ≈ 0).
  - A subscriber produces bwd >> fwd — the opposite pattern.
  - Without subscriber flows in training/evaluation, the model never sees
    this half of normal IoT traffic.

Network signature (benign):
  - Low Srate (only periodic PINGREQs from subscriber)
  - High Drate (broker pushes all published messages)
  - High Weight (fwd ≈ 0, bwd >> 0  — note: Weight = fwd×bwd, near-zero
    here too but for the OPPOSITE reason vs. floods; other features differ)
  - Moderate, stable IAT (paced by upstream publish rate)

Environment variables:
  BENIGN_SUB_TOPICS      Comma-separated topics (default: nodes/+/data)
  BENIGN_SUB_QOS         QoS level 0/1/2 (default: 1)
  BENIGN_SUB_DURATION_S  Run for this many seconds (0 = forever, default: 0)
  BENIGN_CLIENT_ID       MQTT client id prefix (default: benign-sub)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

try:
    from benign_clients.send_log import log_connect
except ImportError:
    from send_log import log_connect

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP  = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "1883"))
RAW_TOPICS  = os.getenv("BENIGN_SUB_TOPICS", "nodes/+/data")
QOS         = int(os.getenv("BENIGN_SUB_QOS", "1"))
DURATION_S  = float(os.getenv("BENIGN_SUB_DURATION_S", "0"))
CLIENT_ID   = os.getenv("BENIGN_CLIENT_ID", f"benign-sub-{uuid.uuid4().hex[:6]}")

TOPICS = [t.strip() for t in RAW_TOPICS.split(",") if t.strip()]


def run() -> None:
    received = 0

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            log_connect("subscriber", CLIENT_ID, client)
            for topic in TOPICS:
                client.subscribe(topic, qos=QOS)
            print(f"[BENIGN-SUB] Connected. Subscribed to: {TOPICS}  QoS={QOS}")
        else:
            print(f"[BENIGN-SUB] Connection failed (rc={rc})", file=sys.stderr)

    def on_message(client, userdata, msg):
        nonlocal received
        received += 1
        if received % 50 == 0:
            print(f"[BENIGN-SUB] Received {received} messages  "
                  f"(last topic: {msg.topic}  size: {len(msg.payload)}B)")

    c = mqtt.Client(client_id=CLIENT_ID, clean_session=True)
    c.on_connect = on_connect
    c.on_message = on_message

    print(f"[BENIGN-SUB] Connecting to {GATEWAY_IP}:{GATEWAY_PORT} ...")
    try:
        c.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[BENIGN-SUB] Could not connect: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        if DURATION_S > 0:
            c.loop_start()
            time.sleep(DURATION_S)
            c.loop_stop()
        else:
            c.loop_forever()
    except KeyboardInterrupt:
        print(f"\n[BENIGN-SUB] Stopped. Total messages received: {received}")
    finally:
        c.disconnect()


if __name__ == "__main__":
    run()
