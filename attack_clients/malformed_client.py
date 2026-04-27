"""
malformed_client.py — Malformed/garbage MQTT payload attack.

Cycles through several mutation strategies to stress-test the gateway's
input validation and error handling:

  Strategy 0 — TRUNCATED_JSON    : valid JSON cut short mid-string
  Strategy 1 — RANDOM_BYTES      : completely random binary blob
  Strategy 2 — WRONG_TYPES       : correct keys but wrong value types
  Strategy 3 — MISSING_FIELDS    : omits required fields (device_id, nonce, etc.)
  Strategy 4 — OVERSIZED         : single key with a multi-MB value
  Strategy 5 — BAD_BASE64        : valid JSON structure but invalid base64 blobs
  Strategy 6 — INJECTED_UNICODE  : null bytes and control characters in strings
  Strategy 7 — EXTRA_DEEP_NESTING: deeply nested JSON (stack overflow attempt)

Network signature the firewall should detect:
  - Irregular packet sizes (varies wildly between strategies)
  - High Srate relative to Drate (gateway drops/errors quickly)
  - Low Weight (more fwd than bwd)

Environment variables:
  ATTACK_RATE_HZ        Messages per second (default: 1)
  ATTACK_BURST_COUNT    Stop after N messages (default: 0 = infinite)
  MALFORMED_STRATEGY    Fix a single strategy 0-7 (default: cycles through all)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_clients.base_attack_client import BaseAttackClient

# Default rate is slower so the gateway logs are readable
os.environ.setdefault("ATTACK_RATE_HZ", "1")


class MalformedClient(BaseAttackClient):
    """Cycles through malformed payload strategies."""

    ATTACK_NAME     = "malformed-payload"
    SPOOF_DEVICE_ID = "malformed-attacker"

    # Each strategy returns bytes (not dict) so we bypass JSON serialisation
    _STRATEGIES = [
        "TRUNCATED_JSON",
        "RANDOM_BYTES",
        "WRONG_TYPES",
        "MISSING_FIELDS",
        "OVERSIZED",
        "BAD_BASE64",
        "INJECTED_UNICODE",
        "EXTRA_DEEP_NESTING",
    ]

    def __init__(self) -> None:
        super().__init__()
        fixed = os.getenv("MALFORMED_STRATEGY", "")
        if fixed.isdigit() and 0 <= int(fixed) < len(self._STRATEGIES):
            self._fixed_strategy: int | None = int(fixed)
        else:
            self._fixed_strategy = None

    def _strategy_name(self, seq: int) -> str:
        if self._fixed_strategy is not None:
            return self._STRATEGIES[self._fixed_strategy]
        return self._STRATEGIES[seq % len(self._STRATEGIES)]

    def build_payload(self, seq: int) -> bytes:
        name = self._strategy_name(seq)
        print(f"[{self.ATTACK_NAME.upper()}] seq={seq}  strategy={name}")

        if name == "TRUNCATED_JSON":
            full = json.dumps({
                "device_id": self.SPOOF_DEVICE_ID,
                "crypto_type": "aes_gcm",
                "seq": seq,
                "nonce": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AAAAAAAAAAAAAAAA",
            })
            cut = random.randint(len(full) // 4, len(full) - 1)
            return full[:cut].encode()

        elif name == "RANDOM_BYTES":
            size = random.choice([16, 128, 512, 4096])
            return bytes(random.getrandbits(8) for _ in range(size))

        elif name == "WRONG_TYPES":
            return json.dumps({
                "device_id":   seq,           # int instead of str
                "crypto_type": None,          # null instead of str
                "seq":         "not-a-number",
                "nonce":       [1, 2, 3],     # list instead of str
                "ciphertext":  {"nested": True},
            }).encode()

        elif name == "MISSING_FIELDS":
            # Keep only a random subset of expected fields
            full = {
                "device_id":   self.SPOOF_DEVICE_ID,
                "crypto_type": "aes_gcm",
                "seq":         seq,
                "nonce":       "AAAAAAAAAAAAAAAA",
                "ciphertext":  "AAAAAAAAAAAAAAAA",
            }
            keys = list(full.keys())
            keep = random.sample(keys, k=random.randint(0, len(keys) - 1))
            return json.dumps({k: full[k] for k in keep}).encode()

        elif name == "OVERSIZED":
            # 512 KB of 'A' in a single field — tests broker/gateway size limits
            return json.dumps({
                "device_id":  self.SPOOF_DEVICE_ID,
                "ciphertext": "A" * (512 * 1024),
            }).encode()

        elif name == "BAD_BASE64":
            return json.dumps({
                "device_id":   self.SPOOF_DEVICE_ID,
                "crypto_type": "aes_gcm",
                "seq":         seq,
                "nonce":       "not!valid==base64$$$$",
                "ciphertext":  "also-not-base64-###",
            }).encode()

        elif name == "INJECTED_UNICODE":
            return json.dumps({
                "device_id":   f"{self.SPOOF_DEVICE_ID}\x00\x01\x02",
                "crypto_type": "aes_gcm\uffff",
                "seq":         seq,
                "nonce":       "\ud800\udc00",  # surrogate pair
                "ciphertext":  "\x00" * 32,
            }, ensure_ascii=False).encode("utf-8", errors="replace")

        elif name == "EXTRA_DEEP_NESTING":
            # Build a 500-level deep nested dict
            nested: dict = {"value": seq}
            for _ in range(500):
                nested = {"child": nested}
            return json.dumps({"device_id": self.SPOOF_DEVICE_ID, "data": nested}).encode()

        # Fallback
        return b"{}"


if __name__ == "__main__":
    MalformedClient().run()
