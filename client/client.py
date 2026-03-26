"""
client.py — MQTT Publisher (runs on the Client Raspberry Pi)

Connects to the MQTT broker hosted on the Gateway Pi and publishes a
simulated sensor reading every PUBLISH_INTERVAL seconds.
"""

import os
import sys
import time
import json
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

# ── Load .env from repo root ───────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP       = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT     = int(os.getenv("GATEWAY_PORT", 1883))
CLIENT_ID        = os.getenv("CLIENT_ID", "pi-client-01")
MQTT_TOPIC       = os.getenv("MQTT_TOPIC", "pi/sensor/data")
PUBLISH_INTERVAL = float(os.getenv("PUBLISH_INTERVAL", 2))


# ── Callbacks ──────────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[CLIENT] Connected to broker at {GATEWAY_IP}:{GATEWAY_PORT}")
    else:
        print(f"[CLIENT] Connection failed — return code {rc}", file=sys.stderr)


def on_publish(client, userdata, mid):
    print(f"[CLIENT] Message delivered (mid={mid})")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[CLIENT] Unexpected disconnect (rc={rc}).", file=sys.stderr)


# ── Helpers ────────────────────────────────────────────────────────────────────

def build_payload(sequence: int) -> str:
    """Return a JSON string simulating a sensor reading."""
    return json.dumps({
        "client_id": CLIENT_ID,
        "sequence":  sequence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message":   f"Hello from {CLIENT_ID} — reading #{sequence}",
    })


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    client = mqtt.Client(client_id=CLIENT_ID, clean_session=True)
    client.on_connect    = on_connect
    client.on_publish    = on_publish
    client.on_disconnect = on_disconnect

    print(f"[CLIENT] Connecting to broker at {GATEWAY_IP}:{GATEWAY_PORT} …")

    try:
        client.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[CLIENT] Could not connect to broker: {exc}", file=sys.stderr)
        sys.exit(1)

    client.loop_start()

    sequence = 1
    try:
        while True:
            payload = build_payload(sequence)
            result  = client.publish(MQTT_TOPIC, payload=payload, qos=1)

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print(f"[CLIENT] Published to '{MQTT_TOPIC}': {payload}")
            else:
                print(f"[CLIENT] Publish failed (rc={result.rc})", file=sys.stderr)

            sequence += 1
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print("\n[CLIENT] Shutting down.")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
