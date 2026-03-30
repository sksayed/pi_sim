"""
research_base_client.py — Benchmarking-oriented PQC client base class.

This does NOT replace the existing demo clients. It provides a separate client
family used for the journal comparative study profiles.

Wire format (JSON over MQTT) published to nodes/{device_id}/data:
  {
    "device_id": "...",
    "session_id": "...",
    "seq": 1,
    "crypto_type": "PQC-RESEARCH-PROFILE",
    "profile": "A|B|C",
    "alg_kem": "...",
    "alg_sig": "...",
    "kem_ciphertext": "<b64>",
    "nonce": "<b64>",
    "ciphertext": "<b64>",
    "signature": "<b64>"
  }
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Ensure repo root is on sys.path so shared/ imports work from any cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.key_manager import load_key_manager, PQC_AVAILABLE
from shared.metrics import benchmark_pqc


load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
GATEWAY_IP = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1883))
PUBLISH_INTERVAL = float(os.getenv("PUBLISH_INTERVAL", 2))


class ResearchProfileClient(ABC):
    DEVICE_ID: str = ""
    PROFILE_NAME: str = ""
    ALG_KEM: str = ""
    ALG_SIG: str = ""
    SECURITY_BITS: int = 0
    CRYPTO_TYPE: str = "PQC-RESEARCH-PROFILE"

    def __init__(self) -> None:
        if not self.DEVICE_ID:
            raise NotImplementedError("Subclass must set DEVICE_ID")
        self._session_id = uuid.uuid4().hex
        self._topic = f"nodes/{self.DEVICE_ID}/data"

        self.PQC_AVAILABLE = PQC_AVAILABLE
        self._km = load_key_manager()

        # Deterministically derive the gateway keypair for this KEM algorithm.
        self._gw_pk, _ = self._km.kem_keypair(self.ALG_KEM)

        # Deterministically derive this client's signing keypair.
        _, self._sig_sk = self._km.sig_keypair(self.ALG_SIG, self.DEVICE_ID)

        self._mqtt = mqtt.Client(client_id=self.DEVICE_ID, clean_session=True)
        self._mqtt.on_connect = self._on_connect
        self._mqtt.on_publish = self._on_publish
        self._mqtt.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, flags, rc):
        tag = f"[{self.DEVICE_ID.upper()}]"
        if rc == 0:
            print(f"{tag} Connected to broker at {GATEWAY_IP}:{GATEWAY_PORT}")
        else:
            print(f"{tag} Connection failed — rc={rc}", file=sys.stderr)

    def _on_publish(self, client, userdata, mid):
        print(f"[{self.DEVICE_ID.upper()}] Delivered (mid={mid})")

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print(f"[{self.DEVICE_ID.upper()}] Unexpected disconnect (rc={rc})", file=sys.stderr)

    def _b64(self, b: bytes) -> str:
        return base64.b64encode(b).decode()

    def _make_plaintext(self, seq: int) -> bytes:
        obj = {
            "device_id": self.DEVICE_ID,
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": self.sample_data(seq),
        }
        return json.dumps(obj).encode("utf-8")

    @abstractmethod
    def sample_data(self, seq: int) -> str:
        """Return simulated sensor data string for this profile."""

    @benchmark_pqc
    def build_message(self, seq: int) -> dict:
        plaintext = self._make_plaintext(seq)

        # KEM encap benchmark
        t0 = time.perf_counter_ns()
        kem_ct, shared_secret = self._km.kem_encapsulate(self.ALG_KEM, self._gw_pk)
        t1 = time.perf_counter_ns()

        # AES-256-GCM encryption benchmark
        aes = AESGCM(shared_secret[:32])
        nonce = os.urandom(12)
        t2 = time.perf_counter_ns()
        ciphertext = aes.encrypt(nonce, plaintext, None)
        t3 = time.perf_counter_ns()

        # Signature benchmark (sign plaintext)
        t4 = time.perf_counter_ns()
        signature = self._km.sig_sign(self.ALG_SIG, plaintext, self._sig_sk)
        t5 = time.perf_counter_ns()

        return {
            "device_id": self.DEVICE_ID,
            "session_id": self._session_id,
            "seq": seq,
            "crypto_type": self.CRYPTO_TYPE,
            "profile": self.PROFILE_NAME,
            "alg_kem": self.ALG_KEM,
            "alg_sig": self.ALG_SIG,
            "kem_ciphertext": self._b64(kem_ct),
            "nonce": self._b64(nonce),
            "ciphertext": self._b64(ciphertext),
            "signature": self._b64(signature),
            # internal timing fields consumed by the decorator
            "_t_encap_ns": t1 - t0,
            "_t_aes_ns": t3 - t2,
            "_t_sign_ns": t5 - t4,
        }

    def run(self) -> None:
        tag = f"[{self.DEVICE_ID.upper()}]"
        mode = "real PQC" if self.PQC_AVAILABLE else "SIMULATION"
        print(f"{tag} Profile     : {self.PROFILE_NAME}")
        print(f"{tag} KEM         : {self.ALG_KEM}")
        print(f"{tag} SIG         : {self.ALG_SIG}")
        print(f"{tag} Security    : {self.SECURITY_BITS} bits (for η)")
        print(f"{tag} PQC mode    : {mode}")
        print(f"{tag} Session ID  : {self._session_id}")
        print(f"{tag} Topic       : {self._topic}")
        print(f"{tag} Connecting to {GATEWAY_IP}:{GATEWAY_PORT} …")

        try:
            self._mqtt.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
        except Exception as exc:
            print(f"{tag} Could not connect: {exc}", file=sys.stderr)
            sys.exit(1)

        self._mqtt.loop_start()

        seq = 1
        try:
            while True:
                msg = self.build_message(seq)
                body = json.dumps(msg)
                res = self._mqtt.publish(self._topic, payload=body, qos=1)
                if res.rc == mqtt.MQTT_ERR_SUCCESS:
                    print(f"{tag} Published seq={seq} to '{self._topic}'")
                else:
                    print(f"{tag} Publish failed (rc={res.rc})", file=sys.stderr)
                seq += 1
                time.sleep(PUBLISH_INTERVAL)
        except KeyboardInterrupt:
            print(f"\n{tag} Shutting down.")
            self._mqtt.loop_stop()
            self._mqtt.disconnect()

