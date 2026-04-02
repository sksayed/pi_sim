"""
Classical (non-PQC) research clients for comparison with PQC-RESEARCH-PROFILE.

Wire format (nodes/{device_id}/data), JSON:
  crypto_type: CLASSICAL-AES-GCM | CLASSICAL-CHACHA20 | CLASSICAL-ECDH-ECDSA
  Symmetric baselines: nonce + ciphertext (base64).
  CLASSICAL-ECDH-ECDSA also: ecdh_ephemeral_pub, signature (base64); static gateway
  ECDH key + per-device ECDSA keys are HKDF-derived from MASTER_SECRET (document in
  the paper: this is classical asymmetric KEM+sign + symmetric AEAD, not pre-provisioned AES only).

Use PAYLOAD_TARGET_BYTES or env PAYLOAD_TARGET_BYTES for 5K/10K/100K-style tests.
"""

from __future__ import annotations

import base64
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import fcntl
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client.research_base_client import ResearchProfileClient  # noqa: E402
from shared.key_manager import load_key_manager, PQC_AVAILABLE  # noqa: E402
from shared.metrics import benchmark_pqc  # noqa: E402
from shared.payload_pad import pad_json_plaintext  # noqa: E402

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
GATEWAY_IP = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1883))


class ClassicResearchClientBase(ResearchProfileClient):
    """Reuse tagging, MQTT, and payload sizing; override crypto to classical schemes."""

    CRYPTO_KIND: str = "CLASSICAL"
    # Subclasses set CRYPTO_TYPE, PROFILE_NAME, ALG_KEM="-", ALG_SIG scheme label, SECURITY_BITS
    ALG_KEM: str = "-"

    def __init__(self) -> None:
        # Skip PQC key setup from ResearchProfileClient — replace with symmetric only.
        if not self.DEVICE_ID:
            raise NotImplementedError("Subclass must set DEVICE_ID")

        self._profile_id = self.DEVICE_ID
        self._client_tag = os.getenv(self.CLIENT_TAG_ENV, "").strip()
        if not self._client_tag:
            self._client_tag = self._allocate_client_tag(self._profile_id)

        self._client_uuid = uuid.uuid4().hex
        self.DEVICE_ID = f"{self._profile_id}-{self._client_tag}"

        self._session_id = uuid.uuid4().hex
        self._instance_id = uuid.uuid4().hex
        self._topic = f"nodes/{self.DEVICE_ID}/data"

        self.PQC_AVAILABLE = PQC_AVAILABLE
        self._km = load_key_manager()

        self._mqtt = mqtt.Client(client_id=f"{self.DEVICE_ID}-{self._instance_id[:8]}", clean_session=True)
        self._mqtt.on_connect = self._on_connect
        self._mqtt.on_publish = self._on_publish
        self._mqtt.on_disconnect = self._on_disconnect


class ClassicResearchAES(ClassicResearchClientBase):
    """AES-256-GCM with key from HKDF (same as client A style)."""

    CRYPTO_TYPE = "CLASSICAL-AES-GCM"
    ALG_SIG = "AES-256-GCM"

    @benchmark_pqc
    def build_message(self, seq: int) -> dict:
        pt_target = self._effective_payload_target()
        obj = {
            "device_id": self.DEVICE_ID,
            "profile_id": self._profile_id,
            "client_tag": self._client_tag,
            "client_uuid": self._client_uuid,
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": self.sample_data(seq),
        }
        plaintext = pad_json_plaintext(obj, pt_target)
        key = self._km.aes_key(self.DEVICE_ID)

        nonce = os.urandom(12)
        t0 = time.perf_counter_ns()
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        t1 = time.perf_counter_ns()

        return {
            "device_id": self.DEVICE_ID,
            "profile_id": self._profile_id,
            "client_tag": self._client_tag,
            "client_uuid": self._client_uuid,
            "session_id": self._session_id,
            "instance_id": self._instance_id,
            "seq": seq,
            "crypto_type": self.CRYPTO_TYPE,
            "crypto_kind": self.CRYPTO_KIND,
            "profile": self.PROFILE_NAME,
            "payload_target_bytes": pt_target,
            "security_bits": self.SECURITY_BITS,
            "alg_kem": self.ALG_KEM,
            "alg_sig": self.ALG_SIG,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "_t_encap_ns": 0,
            "_t_sign_ns": 0,
            "_t_aes_ns": t1 - t0,
        }


class ClassicResearchChaCha(ClassicResearchClientBase):
    """ChaCha20-Poly1305 with key from HKDF."""

    CRYPTO_TYPE = "CLASSICAL-CHACHA20"
    ALG_SIG = "ChaCha20-Poly1305"

    @benchmark_pqc
    def build_message(self, seq: int) -> dict:
        pt_target = self._effective_payload_target()
        obj = {
            "device_id": self.DEVICE_ID,
            "profile_id": self._profile_id,
            "client_tag": self._client_tag,
            "client_uuid": self._client_uuid,
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": self.sample_data(seq),
        }
        plaintext = pad_json_plaintext(obj, pt_target)
        key = self._km.chacha20poly1305_key(self.DEVICE_ID)

        nonce = os.urandom(12)
        t0 = time.perf_counter_ns()
        ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
        t1 = time.perf_counter_ns()

        return {
            "device_id": self.DEVICE_ID,
            "profile_id": self._profile_id,
            "client_tag": self._client_tag,
            "client_uuid": self._client_uuid,
            "session_id": self._session_id,
            "instance_id": self._instance_id,
            "seq": seq,
            "crypto_type": self.CRYPTO_TYPE,
            "crypto_kind": self.CRYPTO_KIND,
            "profile": self.PROFILE_NAME,
            "payload_target_bytes": pt_target,
            "security_bits": self.SECURITY_BITS,
            "alg_kem": self.ALG_KEM,
            "alg_sig": self.ALG_SIG,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "_t_encap_ns": 0,
            "_t_sign_ns": 0,
            "_t_aes_ns": t1 - t0,
        }


class ProfileClassicAes(ClassicResearchAES):
    DEVICE_ID = "classic-aes"
    PROFILE_NAME = "CA"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"ClassicResearchAES seq={seq}"


class ProfileClassicChaCha(ClassicResearchChaCha):
    DEVICE_ID = "classic-chacha"
    PROFILE_NAME = "CC"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"ClassicResearchChaCha seq={seq}"


class ClassicResearchECDH_ECDSA(ClassicResearchClientBase):
    """
    Classical asymmetric baseline: ephemeral ECDH (P-256) with a static gateway
    key (derived from MASTER_SECRET) + ECDSA-P256-SHA256 over plaintext + AES-256-GCM.

    Timers align with PQC research rows: encap ≈ ephemeral ECDH + HKDF, aes, sign.
    """

    CRYPTO_TYPE = "CLASSICAL-ECDH-ECDSA"
    CRYPTO_KIND = "CLASSICAL-ASYM"
    ALG_KEM = "ECDH-P256"
    ALG_SIG = "ECDSA-P256-SHA256"

    def __init__(self) -> None:
        super().__init__()
        self._gw_ecdh_pub = self._km.ecdh_p256_static_peer_public_key()
        self._ecdsa_sk = self._km.ecdsa_p256_signing_key(self.DEVICE_ID)

    @benchmark_pqc
    def build_message(self, seq: int) -> dict:
        pt_target = self._effective_payload_target()
        obj = {
            "device_id": self.DEVICE_ID,
            "profile_id": self._profile_id,
            "client_tag": self._client_tag,
            "client_uuid": self._client_uuid,
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": self.sample_data(seq),
        }
        plaintext = pad_json_plaintext(obj, pt_target)

        t0 = time.perf_counter_ns()
        ephemeral = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared = ephemeral.exchange(ec.ECDH(), self._gw_ecdh_pub)
        aes_key = self._km.derive_classical_ecdh_aes_key(shared)
        eph_pub_b = ephemeral.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        t1 = time.perf_counter_ns()

        nonce = os.urandom(12)
        t2 = time.perf_counter_ns()
        ct = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        t3 = time.perf_counter_ns()

        t4 = time.perf_counter_ns()
        signature = self._ecdsa_sk.sign(plaintext, ec.ECDSA(hashes.SHA256()))
        t5 = time.perf_counter_ns()

        return {
            "device_id": self.DEVICE_ID,
            "profile_id": self._profile_id,
            "client_tag": self._client_tag,
            "client_uuid": self._client_uuid,
            "session_id": self._session_id,
            "instance_id": self._instance_id,
            "seq": seq,
            "crypto_type": self.CRYPTO_TYPE,
            "crypto_kind": self.CRYPTO_KIND,
            "profile": self.PROFILE_NAME,
            "payload_target_bytes": pt_target,
            "security_bits": self.SECURITY_BITS,
            "alg_kem": self.ALG_KEM,
            "alg_sig": self.ALG_SIG,
            "ecdh_ephemeral_pub": base64.b64encode(eph_pub_b).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "signature": base64.b64encode(signature).decode(),
            "_t_encap_ns": t1 - t0,
            "_t_aes_ns": t3 - t2,
            "_t_sign_ns": t5 - t4,
        }


class ProfileClassicEcdhEcdsa(ClassicResearchECDH_ECDSA):
    DEVICE_ID = "classic-ecdh-ecdsa"
    PROFILE_NAME = "CE"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"ClassicResearchECDH-ECDSA seq={seq}"


if __name__ == "__main__":
    raise SystemExit("Run profile_classic_*.py entrypoints")
