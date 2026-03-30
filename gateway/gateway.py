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
    PQC-RESEARCH-PROFILE     — Research profiles A/B/C (alg_kem + alg_sig fields)
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
from shared.metrics import log_gateway_pqc
from shared.topics import TOPIC_PATTERN

# ── Load env ───────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1883))

# ── State ──────────────────────────────────────────────────────────────────────
# Maps (device_id, session_id) → last_seq.
# This allows multiple concurrent client instances for the same device/profile
# to run simultaneously without resetting each other's replay window.
_sessions: dict[tuple[str, str], int] = {}


# ── Decryption handlers ────────────────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _check_replay(device_id: str, session_id: str, seq: int) -> bool:
    """Return True and update state if (session_id, seq) is fresh; False if replayed.

    A new session_id resets the sequence counter for that device — allowing the
    client to restart without triggering false replay rejections.
    Within the same session, seq must be strictly increasing.
    """
    key = (device_id, session_id)
    last_seq = _sessions.get(key)
    if last_seq is None:
        _sessions[key] = seq
        return True

    if seq <= last_seq:
        print(
            f"[GATEWAY] REPLAY REJECTED  device={device_id} "
            f"session={session_id[:8]}… seq={seq} last_seen={last_seq}"
        )
        return False

    _sessions[key] = seq
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
    device_id  = msg["device_id"]
    session_id = msg.get("session_id", "default")
    seq        = msg["seq"]

    if not _check_replay(device_id, session_id, seq):
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
    device_id  = msg["device_id"]
    session_id = msg.get("session_id", "default")
    seq        = msg["seq"]

    if not _check_replay(device_id, session_id, seq):
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
    device_id  = msg["device_id"]
    session_id = msg.get("session_id", "default")
    seq        = msg["seq"]

    if not _check_replay(device_id, session_id, seq):
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


def _decrypt_research_profile(km, msg: dict) -> None:
    """
    Generic KEM + AES-256-GCM + signature.

    Expected fields:
      device_id, session_id, seq, alg_kem, alg_sig,
      kem_ciphertext, nonce, ciphertext, signature
    """
    device_id  = msg["device_id"]
    session_id = msg.get("session_id", "default")
    seq        = msg["seq"]

    if not _check_replay(device_id, session_id, seq):
        return

    alg_kem = msg.get("alg_kem", "")
    alg_sig = msg.get("alg_sig", "")
    payload_bytes = int(msg.pop("_payload_bytes", 0))

    try:
        process = psutil.Process()
        start_rss = process.memory_info().rss
        start_cpu_user, start_cpu_sys = _cpu_times_ns(process)
        t_start = time.perf_counter_ns()

        # Gateway's KEM keypair is deterministically derived from MASTER_SECRET.
        _, kem_sk = km.kem_keypair(alg_kem)
        kem_ct = _b64d(msg["kem_ciphertext"])
        t0 = time.perf_counter_ns()
        shared_secret = km.kem_decapsulate(alg_kem, kem_sk, kem_ct)
        t1 = time.perf_counter_ns()

        nonce = _b64d(msg["nonce"])
        ciphertext = _b64d(msg["ciphertext"])
        t2 = time.perf_counter_ns()
        plaintext = AESGCM(shared_secret[:32]).decrypt(nonce, ciphertext, None)
        t3 = time.perf_counter_ns()

        signature = _b64d(msg["signature"])
        sig_pk, _ = km.sig_keypair(alg_sig, device_id)
        t4 = time.perf_counter_ns()
        sig_ok = km.sig_verify(alg_sig, plaintext, signature, sig_pk)
        t5 = time.perf_counter_ns()
        if not sig_ok:
            print(
                f"[GATEWAY] SIG REJECTED  device={device_id} "
                f"alg_sig={alg_sig} — signature verification failed"
            )
            t_end = time.perf_counter_ns()
            end_cpu_user, end_cpu_sys = _cpu_times_ns(process)
            end_rss = process.memory_info().rss
            log_gateway_pqc(
                device_id=device_id,
                session_id=session_id,
                seq=seq,
                profile=str(msg.get("profile", "?")),
                alg_kem=alg_kem,
                alg_sig=alg_sig,
                payload_bytes=payload_bytes,
                pqc_available=PQC_AVAILABLE,
                accepted=False,
                t_total_ns=t_end - t_start,
                t_decap_ns=t1 - t0,
                t_aes_dec_ns=t3 - t2,
                t_verify_ns=t5 - t4,
                cpu_user_ns=end_cpu_user - start_cpu_user,
                cpu_sys_ns=end_cpu_sys - start_cpu_sys,
                rss_delta_kb=int((end_rss - start_rss) / 1024),
            )
            return

        profile = msg.get("profile", "?")
        _print_accepted(device_id, f"{msg['crypto_type']}[{profile}] {alg_kem} + {alg_sig}", plaintext.decode("utf-8"))

        t_end = time.perf_counter_ns()
        end_cpu_user, end_cpu_sys = _cpu_times_ns(process)
        end_rss = process.memory_info().rss
        log_gateway_pqc(
            device_id=device_id,
            session_id=session_id,
            seq=seq,
            profile=str(profile),
            alg_kem=alg_kem,
            alg_sig=alg_sig,
            payload_bytes=payload_bytes,
            pqc_available=PQC_AVAILABLE,
            accepted=True,
            t_total_ns=t_end - t_start,
            t_decap_ns=t1 - t0,
            t_aes_dec_ns=t3 - t2,
            t_verify_ns=t5 - t4,
            cpu_user_ns=end_cpu_user - start_cpu_user,
            cpu_sys_ns=end_cpu_sys - start_cpu_sys,
            rss_delta_kb=int((end_rss - start_rss) / 1024),
        )

    except InvalidTag:
        print(f"[GATEWAY] AUTH FAILED   device={device_id} — AES-GCM tag invalid")
    except Exception as exc:
        print(f"[GATEWAY] ERROR   device={device_id}: {exc}", file=sys.stderr)


# ── Dispatch table ─────────────────────────────────────────────────────────────

_HANDLERS = {
    "AES-256-GCM":               _decrypt_client_a,
    "Kyber512-AES-GCM":          _decrypt_client_b,
    "Kyber768-Dilithium3-AES-GCM": _decrypt_client_c,
    "PQC-RESEARCH-PROFILE":      _decrypt_research_profile,
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

        # Attach raw payload size for gateway benchmarking (crypto-only timing is
        # recorded inside handlers).
        msg["_payload_bytes"] = len(mqtt_msg.payload)
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
