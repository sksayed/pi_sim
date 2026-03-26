"""
gateway.py — MQTT Subscriber (runs on the Gateway Raspberry Pi)

The Gateway Pi also hosts the Mosquitto broker. This script connects to that
local broker, subscribes to the configured topic, and prints every message
received from the Client Pi.
"""

import os
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

# ── Load .env from repo root ───────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1883))
MQTT_TOPIC   = os.getenv("MQTT_TOPIC", "pi/sensor/data")


# ── Callbacks ──────────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[GATEWAY] Connected to broker at {GATEWAY_IP}:{GATEWAY_PORT}")
        client.subscribe(MQTT_TOPIC, qos=1)
        print(f"[GATEWAY] Subscribed to topic: {MQTT_TOPIC}")
    else:
        print(f"[GATEWAY] Connection failed — return code {rc}", file=sys.stderr)


def on_message(client, userdata, msg):
    payload = msg.payload.decode("utf-8")
    print(f"[GATEWAY] Received on '{msg.topic}': {payload}")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[GATEWAY] Unexpected disconnect (rc={rc}). Reconnecting…", file=sys.stderr)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    client = mqtt.Client(client_id="gateway-subscriber", clean_session=True)
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    print(f"[GATEWAY] Connecting to broker at {GATEWAY_IP}:{GATEWAY_PORT} …")

    try:
        client.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[GATEWAY] Could not connect to broker: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[GATEWAY] Shutting down.")
        client.disconnect()


if __name__ == "__main__":
    main()
