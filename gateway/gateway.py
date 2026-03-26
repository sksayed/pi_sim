"""
gateway.py — MQTT Subscriber + Decryption Router (runs on the Gateway Pi).

Subscribes to nodes/+/data and dispatches each incoming message to the correct
decryption handler based on the `crypto_type` field. After successful
decryption the plaintext data is printed along with metadata.

Replay-attack protection: per-device sequence numbers are tracked; any message
whose seq is not strictly greater than the last seen seq is silently dropped.

Supported crypto_type values:
    AES-256-GCM              — Client A
    Kyber512-AES-GCM         — Client B
    Kyber768-Dilithium3-AES-GCM — Client C
"""

import base64
import json
import os
import sys
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.key_manager import load_key_manager, PQC_AVAILABLE
from shared.topics import TOPIC_PATTERN

# ── Load env ───────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1883))

# ── State ──────────────────────────────────────────────────────────────────────
# Maps device_id → last accepted sequence number.
_last_seq: dict[str, int] = {}


# ── Decryption handlers ────────────────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _check_replay(device_id: str, seq: int) -> bool:
    """Return True and update state if seq is fresh; False if replayed."""
    last = _last_seq.get(device_id, 0)
    if seq <= last:
        print(
            f"[GATEWAY] REPLAY REJECTED  device={device_id} "
            f"seq={seq} last_seen={last}"
        )
        return False
    _last_seq[device_id] = seq
    return True


def _print_accepted(device_id: str, crypto_type: str, plaintext_json: str) -> None:
    try:
        data = json.loads(plaintext_json)
        payload = data.get("data", plaintext_json)
    except json.JSONDecodeError:
        payload = plaintext_json

    print(
        f"[GATEWAY] ACCEPTED  device={device_id}  crypto={crypto_type}\n"
        f"          payload → {payload}"
    )


def _decrypt_client_a(km, msg: dict) -> None:
    """AES-256-GCM: derive key from device_id and decrypt."""
    device_id = msg["device_id"]
    seq       = msg["seq"]

    if not _check_replay(device_id, seq):
        return

    try:
        key        = km.aes_key(device_id)
        nonce      = _b64d(msg["nonce"])
        ciphertext = _b64d(msg["ciphertext"])
        plaintext  = AESGCM(key).decrypt(nonce, ciphertext, None)
        _print_accepted(device_id, msg["crypto_type"], plaintext.decode("utf-8"))
    except InvalidTag:
        print(f"[GATEWAY] AUTH FAILED   device={device_id} — AES-GCM tag invalid")
    except Exception as exc:
        print(f"[GATEWAY] ERROR   device={device_id}: {exc}", file=sys.stderr)


def _decrypt_client_b(km, msg: dict) -> None:
    """Kyber-512 KEM + AES-256-GCM: decapsulate to recover AES key, then decrypt."""
    device_id = msg["device_id"]
    seq       = msg["seq"]

    if not _check_replay(device_id, seq):
        return

    try:
        _, sk         = km.kyber512_keypair()
        kem_ct        = _b64d(msg["kem_ciphertext"])
        shared_secret = km.kyber_decapsulate("Kyber512", sk, kem_ct)

        nonce      = _b64d(msg["nonce"])
        ciphertext = _b64d(msg["ciphertext"])
        plaintext  = AESGCM(shared_secret).decrypt(nonce, ciphertext, None)
        _print_accepted(device_id, msg["crypto_type"], plaintext.decode("utf-8"))
    except InvalidTag:
        print(f"[GATEWAY] AUTH FAILED   device={device_id} — AES-GCM tag invalid")
    except Exception as exc:
        print(f"[GATEWAY] ERROR   device={device_id}: {exc}", file=sys.stderr)


def _decrypt_client_c(km, msg: dict) -> None:
    """Kyber-768 KEM + AES-256-GCM + Dilithium-3: decapsulate, decrypt, verify sig."""
    device_id = msg["device_id"]
    seq       = msg["seq"]

    if not _check_replay(device_id, seq):
        return

    try:
        _, sk         = km.kyber768_keypair()
        kem_ct        = _b64d(msg["kem_ciphertext"])
        shared_secret = km.kyber_decapsulate("Kyber768", sk, kem_ct)

        nonce      = _b64d(msg["nonce"])
        ciphertext = _b64d(msg["ciphertext"])
        plaintext  = AESGCM(shared_secret).decrypt(nonce, ciphertext, None)

        # Verify Dilithium-3 signature over the decrypted plaintext.
        signature    = _b64d(msg["signature"])
        dil_pk, _    = km.dilithium3_keypair(device_id)
        sig_valid    = km.dilithium3_verify(plaintext, signature, dil_pk)

        if not sig_valid:
            print(
                f"[GATEWAY] SIG REJECTED  device={device_id} "
                "— Dilithium-3 signature verification failed"
            )
            return

        _print_accepted(device_id, msg["crypto_type"], plaintext.decode("utf-8"))

    except InvalidTag:
        print(f"[GATEWAY] AUTH FAILED   device={device_id} — AES-GCM tag invalid")
    except Exception as exc:
        print(f"[GATEWAY] ERROR   device={device_id}: {exc}", file=sys.stderr)


# ── Dispatch table ─────────────────────────────────────────────────────────────

_HANDLERS = {
    "AES-256-GCM":               _decrypt_client_a,
    "Kyber512-AES-GCM":          _decrypt_client_b,
    "Kyber768-Dilithium3-AES-GCM": _decrypt_client_c,
}


# ── MQTT callbacks ─────────────────────────────────────────────────────────────

def _make_on_message(km):
    def on_message(client, userdata, mqtt_msg):
        try:
            msg = json.loads(mqtt_msg.payload.decode("utf-8"))
        except json.JSONDecodeError:
            print(
                f"[GATEWAY] Non-JSON message on {mqtt_msg.topic} — ignored",
                file=sys.stderr,
            )
            return

        crypto_type = msg.get("crypto_type", "")
        handler     = _HANDLERS.get(crypto_type)

        if handler is None:
            print(
                f"[GATEWAY] Unknown crypto_type='{crypto_type}' — ignored",
                file=sys.stderr,
            )
            return

        handler(km, msg)

    return on_message


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[GATEWAY] Connected to broker at {GATEWAY_IP}:{GATEWAY_PORT}")
        client.subscribe(TOPIC_PATTERN, qos=1)
        print(f"[GATEWAY] Subscribed to: {TOPIC_PATTERN}")
    else:
        print(f"[GATEWAY] Connection failed — rc={rc}", file=sys.stderr)


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[GATEWAY] Unexpected disconnect (rc={rc})", file=sys.stderr)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    km   = load_key_manager()
    mode = "real PQC (pyoqs)" if PQC_AVAILABLE else "SIMULATION (no pyoqs)"
    print(f"[GATEWAY] Crypto mode : {mode}")
    print(f"[GATEWAY] Replay protection : enabled (per-device seq tracking)")

    client = mqtt.Client(client_id=f"gateway-{uuid.uuid4().hex[:8]}", clean_session=True)
    client.on_connect    = on_connect
    client.on_message    = _make_on_message(km)
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
