"""Per-publish join fields shared by the benign clients, the gateway, and the cloud.

msg_id is unique to one publish. client_clock_offset_ns is gateway time minus
this Pi's time, measured by the session runner and passed in the environment.
Both travel inside the MQTT JSON, so the cloud sees them after decryption.
"""

from __future__ import annotations

import os
import time
import uuid


def client_clock_offset_ns() -> int | None:
    raw = os.getenv("BENIGN_CLOCK_OFFSET_NS", "").strip()
    if not raw:
        return None
    return int(raw)


def trace_fields() -> dict:
    fields: dict = {
        "msg_id": uuid.uuid4().hex,
        "t_publish_ns": time.time_ns(),
    }
    offset = client_clock_offset_ns()
    if offset is not None:
        fields["client_clock_offset_ns"] = offset
    return fields
