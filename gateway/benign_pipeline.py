"""
benign_pipeline.py — Gateway PQC re-encryption pipeline for benign IoT messages.

Single responsibility: receive a plaintext benign sensor message that has passed
the firewall, re-encrypt it with a PQC KEM + signature + AES-256-GCM scheme, and
log all pipeline timing metrics to CSV for paper analysis.

The encrypted payload is printed as CLOUD-READY (actual cloud forwarding is Phase 3).

Configuration (env vars):
    GW_REENCRYPT_KEM    KEM algorithm   (default: ML-KEM-768)
    GW_REENCRYPT_SIG    Signature algo  (default: ML-DSA-65)
    GW_CLOUD_DEVICE_ID  Device ID used for key derivation on the cloud side
                        (default: gateway-cloud-relay)
"""

from __future__ import annotations

import base64
import csv
import json
import os
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
REENCRYPT_KEM    = os.getenv("GW_REENCRYPT_KEM", "ML-KEM-768")
REENCRYPT_SIG    = os.getenv("GW_REENCRYPT_SIG", "ML-DSA-65")
CLOUD_DEVICE_ID  = os.getenv("GW_CLOUD_DEVICE_ID", "gateway-cloud-relay")
REENCRYPT_CSV    = os.getenv(
    "GW_REENCRYPT_CSV_PATH",
    str(_REPO_ROOT / "benchmarks" / "gateway" / "reencrypt_metrics.csv"),
)

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


# ── Main handler ───────────────────────────────────────────────────────────────

def handle_benign(km, msg: dict, t_recv_ns: int = 0, t_handler_start: int = 0) -> None:
    """
    Re-encrypt a benign plaintext sensor message with PQC and log pipeline timing.

    Called by gateway.py for crypto_type="benign" messages that passed the firewall.
    """
    device_id     = msg.get("device_id", "unknown")
    seq           = int(msg.get("seq", 0))
    t_publish_ns  = int(msg.get("t_publish_ns", 0))
    t_broker_transit_ns = (t_recv_ns - t_publish_ns) if t_publish_ns else 0

    # Serialise the full plaintext sensor payload for encryption
    plaintext = json.dumps({
        k: v for k, v in msg.items()
        if k not in ("t_publish_ns",)
    }, separators=(",", ":")).encode()

    try:
        # Derive cloud-side KEM public key (gateway knows cloud's public key)
        gw_pk, _ = km.kem_keypair(REENCRYPT_KEM)

        # Derive signing key for this relay device
        _, sig_sk = km.sig_keypair(REENCRYPT_SIG, CLOUD_DEVICE_ID)

        # ── KEM encapsulate ────────────────────────────────────────────────────
        t0 = time.perf_counter_ns()
        kem_ct, shared_secret = km.kem_encapsulate(REENCRYPT_KEM, gw_pk)
        t1 = time.perf_counter_ns()

        # ── AES-256-GCM encrypt ────────────────────────────────────────────────
        nonce = os.urandom(12)
        t2 = time.perf_counter_ns()
        ciphertext = AESGCM(shared_secret[:32]).encrypt(nonce, plaintext, None)
        t3 = time.perf_counter_ns()

        # ── Sign plaintext ─────────────────────────────────────────────────────
        t4 = time.perf_counter_ns()
        signature = km.sig_sign(REENCRYPT_SIG, plaintext, sig_sk)
        t5 = time.perf_counter_ns()

        t_done = time.perf_counter_ns()

        t_encap_ns     = t1 - t0
        t_aes_enc_ns   = t3 - t2
        t_sign_ns      = t5 - t4
        t_reencrypt_ns = t_encap_ns + t_aes_enc_ns + t_sign_ns
        t_recv_to_done = t_done - t_handler_start

        cloud_payload = {
            "device_id":     device_id,
            "relay_id":      CLOUD_DEVICE_ID,
            "seq":           seq,
            "kem":           REENCRYPT_KEM,
            "sig":           REENCRYPT_SIG,
            "kem_ciphertext": base64.b64encode(kem_ct).decode(),
            "nonce":          base64.b64encode(nonce).decode(),
            "ciphertext":     base64.b64encode(ciphertext).decode(),
            "signature":      base64.b64encode(signature).decode(),
        }

        print(
            f"[BENIGN-PIPELINE] CLOUD-READY  device={device_id}  seq={seq}  "
            f"kem={REENCRYPT_KEM}  sig={REENCRYPT_SIG}  "
            f"transit={t_broker_transit_ns/1e6:.2f}ms  "
            f"reencrypt={t_reencrypt_ns/1e6:.2f}ms  "
            f"total_gw={t_recv_to_done/1e6:.2f}ms"
        )

        _CsvLogger.get().log(_ReencryptRow(
            ts_unix_ns          = time.time_ns(),
            device_id           = device_id,
            seq                 = seq,
            kem                 = REENCRYPT_KEM,
            sig                 = REENCRYPT_SIG,
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

    except Exception as exc:
        print(f"[BENIGN-PIPELINE] ERROR  device={device_id} seq={seq}: {exc}", file=sys.stderr)
