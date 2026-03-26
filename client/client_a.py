"""
client_a.py — AES-256-GCM client (runs on Client Pi A).

Encrypts each payload with AES-256-GCM using a 12-byte random nonce.
The AES key is derived deterministically from the shared MASTER_SECRET via
HKDF, scoped to this device's ID.

Wire format published to nodes/client-a/data:
    {
        "device_id":   "client-a",
        "crypto_type": "AES-256-GCM",
        "seq":         <int>,
        "nonce":       "<base64>",
        "ciphertext":  "<base64>"   # AES-GCM ciphertext + 16-byte tag
    }
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Path setup so shared/ is importable when running from any cwd ──────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.key_manager import load_key_manager
from client.base_client import BaseClient


class ClientA(BaseClient):
    DEVICE_ID   = "client-a"
    CRYPTO_TYPE = "AES-256-GCM"

    def __init__(self) -> None:
        super().__init__()
        km       = load_key_manager()
        self._aes = AESGCM(km.aes_key(self.DEVICE_ID))

    def build_message(self, seq: int) -> dict:
        plaintext = json.dumps({
            "device_id": self.DEVICE_ID,
            "seq":       seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      f"Temperature reading #{seq}: {20.0 + seq * 0.1:.1f} C",
        }).encode("utf-8")

        nonce      = os.urandom(12)
        ciphertext = self._aes.encrypt(nonce, plaintext, None)

        return {
            "device_id":   self.DEVICE_ID,
            "crypto_type": self.CRYPTO_TYPE,
            "seq":         seq,
            "nonce":       base64.b64encode(nonce).decode(),
            "ciphertext":  base64.b64encode(ciphertext).decode(),
        }


if __name__ == "__main__":
    ClientA().run()
