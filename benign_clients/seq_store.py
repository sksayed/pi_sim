"""Monotonic per-device sequence number.

The cloud accepts a message only when its sequence is strictly newer than the
last accepted value for that device. A new session must not start again at 1,
or every later publish is rejected as a replay. The next number is written to
disk before the publish, so a crash cannot reuse it. Gaps are allowed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _path(device_id: str) -> Path:
    root = Path(os.getenv("DEVICE_SEQ_DIR", str(_REPO / "keys" / "device_seq")))
    name = _SAFE.sub("_", device_id).strip("._") or "device"
    return root / name


def allocate(device_id: str) -> int:
    """Return the next sequence for this device and remember it."""
    path = _path(device_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    last = 0
    if path.exists():
        text = path.read_text().strip()
        if text:
            last = int(text)
    seq = last + 1
    tmp = path.with_suffix(".tmp")
    tmp.write_text(f"{seq}\n")
    os.replace(tmp, path)
    return seq
