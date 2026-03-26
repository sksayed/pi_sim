"""
client_b.py — Kyber-512 KEM + AES-256-GCM hybrid client (runs on Client Pi B).

Steps:
  1. Retrieve the Gateway's Kyber-512 public key (regenerated deterministically
     from the shared MASTER_SECRET — same keypair the Gateway holds).
  2. Encapsulate against that public key to obtain (kem_ciphertext, shared_secret).
  3. Use the first 32 bytes of shared_secret as an AES-256 key.
  4. Encrypt the payload with AES-256-GCM.

Wire format published to nodes/client-b/data:
    {
        "device_id":     "client-b",
        "crypto_type":   "Kyber512-AES-GCM",
        "seq":           <int>,
        "kem_ciphertext":"<base64>",
        "nonce":         "<base64>",
        "ciphertext":    "<base64>"
    }
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.key_manager import load_key_manager, PQC_AVAILABLE
from client.base_client import BaseClient


class ClientB(BaseClient):
    DEVICE_ID   = "client-b"
    CRYPTO_TYPE = "Kyber512-AES-GCM"

    def __init__(self) -> None:
        super().__init__()
        self._km = load_key_manager()
        # Derive the Gateway's Kyber-512 public key (gateway holds the full pair).
        self._gw_pk, _ = self._km.kyber512_keypair()

        mode = "real PQC" if PQC_AVAILABLE else "SIMULATION"
        print(f"[{self.DEVICE_ID.upper()}] Kyber-512 mode: {mode}")

    def build_message(self, seq: int) -> dict:
        plaintext_obj = {
            "device_id": self.DEVICE_ID,
            "seq":       seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      f"Humidity reading #{seq}: {55.0 + seq * 0.2:.1f} %RH",
        }
        plaintext = json.dumps(plaintext_obj).encode("utf-8")

        kem_ct, shared_secret = self._km.kyber_encapsulate("Kyber512", self._gw_pk)

        nonce      = os.urandom(12)
        aes        = AESGCM(shared_secret)
        ciphertext = aes.encrypt(nonce, plaintext, None)

        return {
            "device_id":      self.DEVICE_ID,
            "crypto_type":    self.CRYPTO_TYPE,
            "seq":            seq,
            "kem_ciphertext": base64.b64encode(kem_ct).decode(),
            "nonce":          base64.b64encode(nonce).decode(),
            "ciphertext":     base64.b64encode(ciphertext).decode(),
        }


if __name__ == "__main__":
    ClientB().run()
