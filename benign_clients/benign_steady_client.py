"""
benign_steady_client.py — Steady-rate AES-256-GCM MQTT client (client_a pattern).

Wraps client/client_a.py to make it available as a named benign traffic source
inside the benign_clients launcher.  Publishes structurally identical messages
to the real client_a — AES-256-GCM encrypted, fixed device ID, sequential seq —
at a steady configurable rate.

This is the baseline benign flow the firewall was originally evaluated against.
Including it alongside the other benign clients ensures the full benign class
is represented during IDS evaluation runs.

Network signature (benign):
  - Steady, moderate Srate (paced by PUBLISH_INTERVAL env var)
  - Non-zero Drate (CONNACK + QoS ACKs from broker)
  - Symmetric-ish IAT (fixed sleep between messages)
  - Normal Weight (both fwd and bwd non-trivial)

Environment variables (same as client_a.py):
  PUBLISH_INTERVAL   Seconds between publishes (default: 2)
  GATEWAY_IP / GATEWAY_PORT
  MASTER_SECRET      Required for real AES key derivation (see .env)
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is on the path so client/ and shared/ are importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client.client_a import ClientA


def run() -> None:
    ClientA().run()


if __name__ == "__main__":
    run()
