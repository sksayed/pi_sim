"""Pad JSON plaintext objects to a target UTF-8 byte length (benchmark helper)."""

from __future__ import annotations

import json
from typing import Any, Dict


def pad_json_plaintext(obj: Dict[str, Any], target_bytes: int) -> bytes:
    """
    Return compact JSON bytes for `obj`, growing `_padding` until len >= target_bytes.

    If target_bytes <= 0, returns JSON once without padding.
    """
    pad_key = "_padding"
    if target_bytes <= 0:
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    o = dict(obj)
    o[pad_key] = ""
    # Avoid infinite loop if target unreachably small
    for _ in range(1_000_000):
        b = json.dumps(o, separators=(",", ":")).encode("utf-8")
        if len(b) >= target_bytes:
            return b
        need = target_bytes - len(b)
        o[pad_key] += "X" * max(1, min(need, 65_536))

    return json.dumps(o, separators=(",", ":")).encode("utf-8")
