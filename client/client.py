"""
client.py — Standalone AES-256-GCM MQTT client.

Encrypts a simulated sensor reading with AES-256-GCM and publishes it to the
Gateway Pi every PUBLISH_INTERVAL seconds.

Usage:
    python client.py

Requires .env at the project root with at minimum:
    MASTER_SECRET, GATEWAY_IP, GATEWAY_PORT
"""

import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ── Config ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(dotenv_path=ROOT / ".env")

MASTER_SECRET    = os.getenv("MASTER_SECRET", "")
GATEWAY_IP       = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT     = int(os.getenv("GATEWAY_PORT", 1883))
PUBLISH_INTERVAL = float(os.getenv("PUBLISH_INTERVAL", 2))

DEVICE_ID   = "client-a"
CRYPTO_TYPE = "AES-256-GCM"
TOPIC       = f"nodes/{DEVICE_ID}/data"

if not MASTER_SECRET:
    print("[CLIENT] ERROR: MASTER_SECRET not set in .env", file=sys.stderr)
    sys.exit(1)

# ── Derive AES key via HKDF ────────────────────────────────────────────────────
_aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=f"aes:{DEVICE_ID}".encode(),
    backend=default_backend(),
).derive(MASTER_SECRET.encode())

_aesgcm = AESGCM(_aes_key)


# ── Encryption ─────────────────────────────────────────────────────────────────

def encrypt_payload(seq: int) -> dict:
    plaintext = json.dumps({
        "device_id": DEVICE_ID,
        "seq":       seq,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data":      f"Temperature reading #{seq}: {20.0 + seq * 0.1:.1f} C",
    }).encode("utf-8")

    nonce      = os.urandom(12)
    ciphertext = _aesgcm.encrypt(nonce, plaintext, None)

    return {
        "device_id":   DEVICE_ID,
        "crypto_type": CRYPTO_TYPE,
        "seq":         seq,
        "nonce":       base64.b64encode(nonce).decode(),
        "ciphertext":  base64.b64encode(ciphertext).decode(),
    }


# ── MQTT callbacks ─────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[CLIENT] Connected to broker at {GATEWAY_IP}:{GATEWAY_PORT}")
    else:
        print(f"[CLIENT] Connection failed — rc={rc}", file=sys.stderr)


def on_publish(client, userdata, mid):
    print(f"[CLIENT] Delivered (mid={mid})")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[CLIENT] Unexpected disconnect (rc={rc})", file=sys.stderr)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(f"[CLIENT] Device   : {DEVICE_ID}")
    print(f"[CLIENT] Crypto   : {CRYPTO_TYPE}")
    print(f"[CLIENT] Topic    : {TOPIC}")
    print(f"[CLIENT] Interval : {PUBLISH_INTERVAL}s")
    print(f"[CLIENT] Connecting to {GATEWAY_IP}:{GATEWAY_PORT} …")

    mqttc = mqtt.Client(client_id=DEVICE_ID, clean_session=True)
    mqttc.on_connect    = on_connect
    mqttc.on_publish    = on_publish
    mqttc.on_disconnect = on_disconnect

    try:
        mqttc.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[CLIENT] Could not connect: {exc}", file=sys.stderr)
        sys.exit(1)

    mqttc.loop_start()

    seq = 1
    try:
        while True:
            msg    = encrypt_payload(seq)
            body   = json.dumps(msg)
            result = mqttc.publish(TOPIC, payload=body, qos=1)

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print(f"[CLIENT] Published seq={seq} → {TOPIC}")
            else:
                print(f"[CLIENT] Publish failed (rc={result.rc})", file=sys.stderr)

            seq += 1
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print("\n[CLIENT] Shutting down.")
        mqttc.loop_stop()
        mqttc.disconnect()


if __name__ == "__main__":
    main()
