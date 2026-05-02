"""
attack_passthrough.py — Firewall-miss detector for the gateway.

Single responsibility: when a message tagged is_attack=True reaches the gateway
it means the firewall failed to classify or block that flow.  This module logs
the event so the researcher can manually review which attack types the model
missed and why.

Output:
    Firewall_logs/firewall_misses.jsonl  — one JSON object per missed attack
    Console warning printed immediately

JSON event fields:
    event         "firewall_miss"
    ts            wall-clock timestamp (float, seconds)
    attack_label  ATTACK_NAME from the attack client (e.g. "mqtt-flood")
    device_id     spoofed device ID in the payload
    seq           message sequence number
    crypto_type   crypto_type field the attack used (shows spoofing attempt)
    t_publish_ns  client-side publish timestamp (0 if not present)
    t_broker_transit_ns  time from publish to gateway receipt (ns)
    payload_preview  first 120 chars of raw payload for manual inspection
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

_MISS_LOG = Path(
    os.getenv("FW_MISS_JSONL", str(_REPO_ROOT / "Firewall_logs" / "firewall_misses.jsonl"))
)
_MISS_LOG.parent.mkdir(parents=True, exist_ok=True)

# Dedicated logger — writes only to the JSONL miss file, not to stdout/stderr.
_miss_logger = logging.getLogger("gw.firewall_miss")
_miss_logger.propagate = False
_miss_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(str(_MISS_LOG))
_fh.setFormatter(logging.Formatter("%(message)s"))
_miss_logger.addHandler(_fh)


def _log_miss(event: dict) -> None:
    _miss_logger.info(json.dumps(event, separators=(",", ":"), sort_keys=True))


def handle_attack_passthrough(
    msg: dict,
    t_recv_ns: int = 0,
    t_handler_start: int = 0,
    raw_payload: str = "",
) -> None:
    """
    Called when a message with is_attack=True reaches the gateway.

    Logs the firewall miss and prints a warning so the researcher can
    identify which flows the model failed to block.
    """
    attack_label  = msg.get("attack_label", "unknown")
    device_id     = msg.get("device_id",    "unknown")
    seq           = int(msg.get("seq", 0))
    crypto_type   = msg.get("crypto_type",  "unknown")
    t_publish_ns  = int(msg.get("t_publish_ns", 0))
    t_broker_transit_ns = (t_recv_ns - t_publish_ns) if t_publish_ns else 0

    payload_preview = (raw_payload or json.dumps(msg))[:120]

    print(
        f"[FIREWALL MISS] ⚠  attack_label={attack_label}  "
        f"device={device_id}  seq={seq}  crypto_type={crypto_type}  "
        f"transit={t_broker_transit_ns/1e6:.2f}ms  "
        f"— model failed to block this flow",
        file=sys.stderr,
    )

    _log_miss({
        "event":               "firewall_miss",
        "ts":                  time.time(),
        "attack_label":        attack_label,
        "device_id":           device_id,
        "seq":                 seq,
        "crypto_type":         crypto_type,
        "t_publish_ns":        t_publish_ns,
        "t_broker_transit_ns": t_broker_transit_ns,
        "payload_preview":     payload_preview,
    })
