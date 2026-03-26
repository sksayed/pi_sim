"""
client_c.py — Kyber-768 KEM + AES-256-GCM + Dilithium-3 client (Client Pi C).

Steps:
  1. Retrieve the Gateway's Kyber-768 public key (deterministic from MASTER_SECRET).
  2. Encapsulate to obtain (kem_ciphertext, shared_secret).
  3. Use shared_secret as AES-256 key.
  4. Sign the plaintext payload with Dilithium-3 before encrypting.
  5. Encrypt (plaintext + signature) together with AES-256-GCM.

Wire format published to nodes/client-c/data:
    {
        "device_id":     "client-c",
        "crypto_type":   "Kyber768-Dilithium3-AES-GCM",
        "seq":           <int>,
        "kem_ciphertext":"<base64>",
        "nonce":         "<base64>",
        "ciphertext":    "<base64>",
        "signature":     "<base64>"
    }

Note: `signature` signs the *plaintext* JSON bytes. The Gateway verifies it
after decrypting, using the same Dilithium-3 public key derived from
MASTER_SECRET for this device_id.
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


class ClientC(BaseClient):
    DEVICE_ID   = "client-c"
    CRYPTO_TYPE = "Kyber768-Dilithium3-AES-GCM"

    def __init__(self) -> None:
        super().__init__()
        self._km = load_key_manager()

        self._gw_pk, _     = self._km.kyber768_keypair()
        _, self._dil_sk    = self._km.dilithium3_keypair(self.DEVICE_ID)

        mode = "real PQC" if PQC_AVAILABLE else "SIMULATION"
        print(f"[{self.DEVICE_ID.upper()}] Kyber-768 + Dilithium-3 mode: {mode}")

    def build_message(self, seq: int) -> dict:
        plaintext_obj = {
            "device_id": self.DEVICE_ID,
            "seq":       seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      f"Pressure reading #{seq}: {1013.25 + seq * 0.05:.2f} hPa",
        }
        plaintext = json.dumps(plaintext_obj).encode("utf-8")

        # Sign plaintext before encryption.
        signature = self._km.dilithium3_sign(plaintext, self._dil_sk)

        # KEM encapsulation → AES key.
        kem_ct, shared_secret = self._km.kyber_encapsulate("Kyber768", self._gw_pk)

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
            "signature":      base64.b64encode(signature).decode(),
        }


if __name__ == "__main__":
    ClientC().run()
