"""
research_base_client.py — Benchmarking-oriented PQC client base class.

This does NOT replace the existing demo clients. It provides a separate client
family used for the journal comparative study profiles.

Wire format (JSON over MQTT) published to nodes/{device_id}/data:
  {
    "device_id": "...",
    "profile_id": "...",
    "client_uuid": "...",
    "session_id": "...",
    "seq": 1,
    "crypto_type": "PQC-RESEARCH-PROFILE",
    "profile": "1..7",
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
from typing import Any, Dict

import fcntl

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Ensure repo root is on sys.path so shared/ imports work from any cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.key_manager import load_key_manager, PQC_AVAILABLE
from shared.metrics import benchmark_pqc
from shared.payload_pad import pad_json_plaintext


load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
GATEWAY_IP = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1883))


class ResearchProfileClient(ABC):
    DEVICE_ID: str = ""
    PROFILE_NAME: str = ""
    ALG_KEM: str = ""
    ALG_SIG: str = ""
    SECURITY_BITS: int = 0
    CRYPTO_TYPE: str = "PQC-RESEARCH-PROFILE"
    PUBLISH_INTERVAL_ENV: str = "PUBLISH_INTERVAL"
    PUBLISH_INTERVAL_DEFAULT_S: float = 2.0
    CLIENT_TAG_ENV: str = "CLIENT_TAG"
    CLIENT_TAG_STATE_ENV: str = "CLIENT_TAG_STATE_PATH"
    # Target plaintext JSON size (bytes) when >0; also set env PAYLOAD_TARGET_BYTES.
    # Suggested: 5120, 10240, 102400 for 5KB / 10KB / ~100KB.
    PAYLOAD_TARGET_BYTES: int = 0
    CRYPTO_KIND: str = "PQC"

    def __init__(self) -> None:
        if not self.DEVICE_ID:
            raise NotImplementedError("Subclass must set DEVICE_ID")

        # Allow multiple concurrent clients per profile without topic/id clashes.
        # Treat subclass DEVICE_ID as a stable profile identifier and create a
        # short per-instance device_id for MQTT + key derivation.
        self._profile_id = self.DEVICE_ID

        # If you only run a small number of clients (e.g. <=10), a full UUID is
        # visually noisy. Prefer a small integer tag:
        #   (auto) → device_id "profile-1-01", "profile-1-02", ...
        #   export CLIENT_TAG=07 → device_id "profile-1-07"
        self._client_tag = os.getenv(self.CLIENT_TAG_ENV, "").strip()
        if not self._client_tag:
            self._client_tag = self._allocate_client_tag(self._profile_id)

        # Keep a full UUID available for offline correlation if desired.
        self._client_uuid = uuid.uuid4().hex

        self.DEVICE_ID = f"{self._profile_id}-{self._client_tag}"

        self._session_id = uuid.uuid4().hex
        self._instance_id = uuid.uuid4().hex
        self._topic = f"nodes/{self.DEVICE_ID}/data"

        self.PQC_AVAILABLE = PQC_AVAILABLE
        self._km = load_key_manager()

        # Deterministically derive the gateway keypair for this KEM algorithm.
        self._gw_pk, _ = self._km.kem_keypair(self.ALG_KEM)

        # Deterministically derive this client's signing keypair.
        _, self._sig_sk = self._km.sig_keypair(self.ALG_SIG, self.DEVICE_ID)

        # MQTT client IDs must be unique per broker connection.
        self._mqtt = mqtt.Client(client_id=f"{self.DEVICE_ID}-{self._instance_id[:8]}", clean_session=True)
        self._mqtt.on_connect = self._on_connect
        self._mqtt.on_publish = self._on_publish
        self._mqtt.on_disconnect = self._on_disconnect

    def _allocate_client_tag(self, profile_id: str) -> str:
        """
        Allocate the next numeric client tag for this profile.

        Uses a small JSON state file with an advisory file lock so launching
        multiple clients in parallel won't collide.
        """
        state_path = os.getenv(self.CLIENT_TAG_STATE_ENV, "benchmarks/client/client_tag_state.json")
        p = Path(state_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        with p.open("a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                raw = f.read().strip()
                state: Dict[str, Any] = json.loads(raw) if raw else {}
                counters: Dict[str, int] = state.get("counters", {})
                n = int(counters.get(profile_id, 0)) + 1
                counters[profile_id] = n
                state["counters"] = counters

                f.seek(0)
                f.truncate()
                f.write(json.dumps(state, indent=2, sort_keys=True))
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        return f"{n:02d}"

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

    def _effective_payload_target(self) -> int:
        v = int(getattr(self, "PAYLOAD_TARGET_BYTES", 0) or 0)
        if v > 0:
            return v
        raw = os.getenv("PAYLOAD_TARGET_BYTES", "").strip()
        if raw:
            try:
                return int(raw)
            except ValueError:
                pass
        return 0

    def _plaintext_bytes(self, seq: int) -> bytes:
        obj = {
            "device_id": self.DEVICE_ID,
            "profile_id": self._profile_id,
            "client_tag": self._client_tag,
            "client_uuid": self._client_uuid,
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": self.sample_data(seq),
        }
        return pad_json_plaintext(obj, self._effective_payload_target())

    @abstractmethod
    def sample_data(self, seq: int) -> str:
        """Return simulated sensor data string for this profile."""

    @benchmark_pqc
    def build_message(self, seq: int) -> dict:
        plaintext = self._plaintext_bytes(seq)
        pt_target = self._effective_payload_target()

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
            "kem_ciphertext": self._b64(kem_ct),
            "nonce": self._b64(nonce),
            "ciphertext": self._b64(ciphertext),
            "signature": self._b64(signature),
            # internal timing fields consumed by the decorator
            "_t_encap_ns": t1 - t0,
            "_t_aes_ns": t3 - t2,
            "_t_sign_ns": t5 - t4,
        }

    def _max_messages_limit(self, max_messages: int | None) -> int | None:
        """Resolve publish cap: explicit arg, then BENCHMARK_MAX_MESSAGES env, else unlimited."""
        if max_messages is not None and max_messages > 0:
            return int(max_messages)
        raw = os.getenv("BENCHMARK_MAX_MESSAGES", "").strip()
        if raw:
            try:
                n = int(raw)
                return n if n > 0 else None
            except ValueError:
                pass
        return None

    def run(self, max_messages: int | None = None) -> None:
        tag = f"[{self.DEVICE_ID.upper()}]"
        mode = "real PQC" if self.PQC_AVAILABLE else "SIMULATION"
        limit = self._max_messages_limit(max_messages)
        print(f"{tag} Profile ID  : {self._profile_id}")
        print(f"{tag} Client tag  : {self._client_tag}")
        print(f"{tag} Client UUID : {self._client_uuid}")
        print(f"{tag} Profile     : {self.PROFILE_NAME}")
        print(f"{tag} KEM         : {self.ALG_KEM}")
        print(f"{tag} SIG         : {self.ALG_SIG}")
        print(f"{tag} Security    : {self.SECURITY_BITS} bits (for η)")
        print(f"{tag} PQC mode    : {mode}")
        print(f"{tag} Session ID  : {self._session_id}")
        print(f"{tag} Plaintarget  : {self._effective_payload_target() or 'off'} B")
        print(f"{tag} Topic       : {self._topic}")
        if limit is not None:
            print(f"{tag} Max messages: {limit} (then disconnect)")
        print(f"{tag} Connecting to {GATEWAY_IP}:{GATEWAY_PORT} …")

        try:
            self._mqtt.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
        except Exception as exc:
            print(f"{tag} Could not connect: {exc}", file=sys.stderr)
            sys.exit(1)

        self._mqtt.loop_start()

        seq = 1
        try:
            while limit is None or seq <= limit:
                msg = self.build_message(seq)
                msg["t_publish_ns"] = time.time_ns()
                body = json.dumps(msg)
                res = self._mqtt.publish(self._topic, payload=body, qos=1)
                if res.rc == mqtt.MQTT_ERR_SUCCESS:
                    print(f"{tag} Published seq={seq} to '{self._topic}'")
                else:
                    print(f"{tag} Publish failed (rc={res.rc})", file=sys.stderr)
                seq += 1
                if limit is not None and seq > limit:
                    break
                time.sleep(self.get_publish_interval_s())
        except KeyboardInterrupt:
            print(f"\n{tag} Shutting down (keyboard interrupt).", file=sys.stderr)
        finally:
            self._mqtt.loop_stop()
            self._mqtt.disconnect()

    def get_publish_interval_s(self) -> float:
        """
        Override point for subclasses.

        Default behaviour reads from `PUBLISH_INTERVAL_ENV` and falls back
        to `PUBLISH_INTERVAL_DEFAULT_S`.
        """
        raw = os.getenv(self.PUBLISH_INTERVAL_ENV)
        if raw is None or raw == "":
            return float(self.PUBLISH_INTERVAL_DEFAULT_S)
        try:
            return float(raw)
        except ValueError:
            return float(self.PUBLISH_INTERVAL_DEFAULT_S)

