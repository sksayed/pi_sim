"""
benign_pipeline.py — Gateway PQC re-encryption pipeline for benign IoT messages.

Single responsibility: receive a plaintext benign sensor message that has passed
the firewall, re-encrypt it with a PQC KEM + signature + AES-256-GCM scheme, and
log all pipeline timing metrics to CSV for paper analysis.

The encrypted payload is printed as CLOUD-READY. If GW_CLOUD_FORWARD=1, a background
thread POSTs it to the cloud PC over HTTPS. The MQTT callback does not wait.
Default is off, so the labelled paper runs do not send anything.

Configuration (env vars):
    GW_REENCRYPT_KEM    KEM algorithm   (default: ML-KEM-768)
    GW_REENCRYPT_SIG    Signature algo  (default: ML-DSA-65)
    GW_CLOUD_DEVICE_ID  Device ID used for key derivation on the cloud side
                        (default: gateway-cloud-relay)
    GW_REENCRYPT_LOG_WAN_TRANSIT  If 1/true, CSV column t_broker_transit_ns is
                        (gateway_recv_wall - client t_publish_ns), i.e. includes
                        WAN + clock skew. Default 0: column is 0 — use CSV for
                        on-gateway work only (t_recv_to_done_ns, t_reencrypt_ns).

On-device pipeline (what this CSV captures):
    MQTT has already traversed NFQUEUE/mqtt_firewall.py and the broker before
    gateway.py's on_message runs. t_recv_to_done_ns spans that callback (JSON
    routing + re-encrypt handler) on a monotonic clock — not WAN, not the LightGBM
    pass (see Firewall_logs/*.jsonl verdict / t_inference_ns for flow-level IDS).
"""

from __future__ import annotations

import base64
import binascii
import csv
import json
import os
import struct
import sys
import time
import threading
import queue
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from shared.key_manager import PQC_AVAILABLE

# ── Configuration ─────────────────────────────────────────────────────────────
def _env_truthy(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


REENCRYPT_KEM    = os.getenv("GW_REENCRYPT_KEM", "ML-KEM-768")
REENCRYPT_SIG    = os.getenv("GW_REENCRYPT_SIG", "ML-DSA-65")
CLOUD_DEVICE_ID  = os.getenv("GW_CLOUD_DEVICE_ID", "gateway-cloud-relay")
LOG_WAN_TRANSIT  = _env_truthy("GW_REENCRYPT_LOG_WAN_TRANSIT", "0")
REENCRYPT_CSV    = os.getenv(
    "GW_REENCRYPT_CSV_PATH",
    str(_REPO_ROOT / "benchmarks" / "gateway" / "reencrypt_metrics.csv"),
)

# (kem_alg, sig_alg, cloud_public_key, gateway_signing_key, relay_id)
# None keeps the journal path: both keys are derived from MASTER_SECRET.
_UPLINK: tuple[str, str, bytes, bytes, str] | None = None


def use_provisioned_uplink(kem_alg: str, sig_alg: str, cloud_pk: bytes,
                           gateway_sk: bytes, relay_id: str = "gateway") -> None:
    """Use independently generated cloud and gateway keys for the HTTPS path."""
    global _UPLINK
    _UPLINK = (kem_alg, sig_alg, cloud_pk, gateway_sk, relay_id)

_CSV_FIELDS = [
    "ts_unix_ns",
    "device_id",
    "seq",
    "kem",
    "sig",
    "payload_bytes",
    "t_publish_ns",
    "t_broker_transit_ns",
    "t_recv_to_done_ns",
    "t_encap_ns",
    "t_aes_enc_ns",
    "t_sign_ns",
    "t_reencrypt_ns",
    "pqc_available",
]


# ── Thread-safe CSV logger ─────────────────────────────────────────────────────
@dataclass(frozen=True)
class _ReencryptRow:
    ts_unix_ns: int
    device_id: str
    seq: int
    kem: str
    sig: str
    payload_bytes: int
    t_publish_ns: int
    t_broker_transit_ns: int
    t_recv_to_done_ns: int
    t_encap_ns: int
    t_aes_enc_ns: int
    t_sign_ns: int
    t_reencrypt_ns: int
    pqc_available: bool


class _CsvLogger:
    _instance: "_CsvLogger | None" = None
    _lock = threading.Lock()

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._q: "queue.Queue[_ReencryptRow | None]" = queue.Queue(maxsize=5000)
        t = threading.Thread(target=self._run, daemon=True, name="reencrypt-csv")
        t.start()

    @classmethod
    def get(cls) -> "_CsvLogger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = _CsvLogger(REENCRYPT_CSV)
            return cls._instance

    def log(self, row: _ReencryptRow) -> None:
        try:
            self._q.put_nowait(row)
        except queue.Full:
            pass

    def _run(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        exists = self._path.exists()
        with self._path.open("a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
            if not exists:
                w.writeheader()
            while True:
                item = self._q.get()
                if item is None:
                    return
                w.writerow(item.__dict__)
                f.flush()


# ── Signed envelope encoding ───────────────────────────────────────────────────

_ENVELOPE_DOMAIN = b"PI-SIM-GW-ENVELOPE-V1"


def encode_signed_envelope(device_id: str, seq: int, kem_ct: bytes,
                           nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Canonical bytes signed by the gateway:
    M = Encode(device_id, seq, kem_ciphertext, aes_nonce, aes_ciphertext).

    Domain tag, then each field as a 4-byte big-endian length followed by its
    bytes, so distinct field tuples never encode to the same M. device_id is
    UTF-8; seq is an unsigned 64-bit big-endian integer.
    """
    fields = (
        str(device_id).encode("utf-8"),
        int(seq).to_bytes(8, "big"),
        kem_ct,
        nonce,
        ciphertext,
    )
    return _ENVELOPE_DOMAIN + b"".join(struct.pack(">I", len(f)) + f for f in fields)


def verify_cloud_envelope(km, envelope: dict, sig_pk: bytes,
                          sig_alg: str = REENCRYPT_SIG) -> bool:
    """Receiver-side check of a cloud_payload produced by handle_benign()."""
    try:
        message = encode_signed_envelope(
            envelope["device_id"],
            envelope["seq"],
            base64.b64decode(envelope["kem_ciphertext"], validate=True),
            base64.b64decode(envelope["nonce"], validate=True),
            base64.b64decode(envelope["ciphertext"], validate=True),
        )
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (KeyError, TypeError, ValueError, OverflowError, binascii.Error):
        return False
    return bool(km.sig_verify(sig_alg, message, signature, sig_pk))


# ── Main handler ───────────────────────────────────────────────────────────────

def handle_benign(km, msg: dict, t_recv_ns: int = 0, t_handler_start: int = 0) -> dict | None:
    """
    Re-encrypt a benign plaintext sensor message with PQC and log pipeline timing.

    Called by gateway.py for crypto_type="benign" messages that passed the firewall.
    """
    device_id     = msg.get("device_id", "unknown")
    seq           = int(msg.get("seq", 0))
    t_publish_ns  = int(msg.get("t_publish_ns", 0))
    t_broker_transit_ns = (
        (t_recv_ns - t_publish_ns) if (LOG_WAN_TRANSIT and t_publish_ns) else 0
    )

    # Serialise the full plaintext sensor payload for encryption
    plaintext = json.dumps({
        k: v for k, v in msg.items()
        if k not in ("t_publish_ns",)
    }, separators=(",", ":")).encode()

    try:
        # Derive keys only when Phase 3 has not installed an independent pair.
        # The journal path keeps HKDF derivation. The HTTPS path uses a cloud
        # public key and a gateway signing key that were generated with the
        # system RNG and never leave their own machines.
        if _UPLINK is None:
            kem_alg = REENCRYPT_KEM
            sig_alg = REENCRYPT_SIG
            cloud_pk, _ = km.kem_keypair(kem_alg)
            _, sig_sk = km.sig_keypair(sig_alg, CLOUD_DEVICE_ID)
            relay_id = CLOUD_DEVICE_ID
        else:
            kem_alg, sig_alg, cloud_pk, sig_sk, relay_id = _UPLINK

        # ── KEM encapsulate ────────────────────────────────────────────────────
        t0 = time.perf_counter_ns()
        kem_ct, shared_secret = km.kem_encapsulate(kem_alg, cloud_pk)
        t1 = time.perf_counter_ns()

        # ── AES-256-GCM encrypt ────────────────────────────────────────────────
        nonce = os.urandom(12)
        t2 = time.perf_counter_ns()
        ciphertext = AESGCM(shared_secret[:32]).encrypt(nonce, plaintext, None)
        t3 = time.perf_counter_ns()

        # ── Sign encrypted envelope ────────────────────────────────────────────
        signed_message = encode_signed_envelope(device_id, seq, kem_ct, nonce, ciphertext)
        t4 = time.perf_counter_ns()
        signature = km.sig_sign(sig_alg, signed_message, sig_sk)
        t5 = time.perf_counter_ns()

        t_done = time.perf_counter_ns()

        t_encap_ns     = t1 - t0
        t_aes_enc_ns   = t3 - t2
        t_sign_ns      = t5 - t4
        t_reencrypt_ns = t_encap_ns + t_aes_enc_ns + t_sign_ns
        t_recv_to_done = t_done - t_handler_start

        cloud_payload = {
            "device_id":     device_id,
            "relay_id":      relay_id,
            "seq":           seq,
            "t_publish_ns":  t_publish_ns,
            "kem":           kem_alg,
            "sig":           sig_alg,
            "kem_ciphertext": base64.b64encode(kem_ct).decode(),
            "nonce":          base64.b64encode(nonce).decode(),
            "ciphertext":     base64.b64encode(ciphertext).decode(),
            "signature":      base64.b64encode(signature).decode(),
        }

        _wan = f"wan_ms={t_broker_transit_ns/1e6:.2f}  " if LOG_WAN_TRANSIT else ""
        print(
            f"[BENIGN-PIPELINE] CLOUD-READY  device={device_id}  seq={seq}  "
            f"kem={kem_alg}  sig={sig_alg}  "
            f"{_wan}"
            f"reencrypt={t_reencrypt_ns/1e6:.2f}ms  "
            f"on_device_gw={t_recv_to_done/1e6:.2f}ms"
        )

        _CsvLogger.get().log(_ReencryptRow(
            ts_unix_ns          = time.time_ns(),
            device_id           = device_id,
            seq                 = seq,
            kem                 = kem_alg,
            sig                 = sig_alg,
            payload_bytes       = len(plaintext),
            t_publish_ns        = t_publish_ns,
            t_broker_transit_ns = t_broker_transit_ns,
            t_recv_to_done_ns   = t_recv_to_done,
            t_encap_ns          = t_encap_ns,
            t_aes_enc_ns        = t_aes_enc_ns,
            t_sign_ns           = t_sign_ns,
            t_reencrypt_ns      = t_reencrypt_ns,
            pqc_available       = PQC_AVAILABLE,
        ))
        return cloud_payload

    except Exception as exc:
        print(f"[BENIGN-PIPELINE] ERROR  device={device_id} seq={seq}: {exc}", file=sys.stderr)
        return None
