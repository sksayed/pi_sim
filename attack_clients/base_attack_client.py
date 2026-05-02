"""
base_attack_client.py — Lightweight MQTT base for attack simulation clients.

Intentionally does NOT use the normal crypto stack or MASTER_SECRET.
Attack clients only need raw MQTT publish capability with configurable rate.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "1883"))


class BaseAttackClient(ABC):
    """
    Base class for all attack simulation clients.

    Subclasses implement `build_payload(seq)` which returns either a dict
    (JSON-serialised automatically) or raw bytes sent as-is.

    Key differences from normal BaseClient:
      - No MASTER_SECRET / key derivation
      - No session_id integrity — attack clients may spoof or omit fields
      - Configurable burst rate (ATTACK_RATE_HZ env var)
      - Each client gets a random spoofed device ID by default
    """

    ATTACK_NAME: str = "generic-attack"
    # Override in subclass to use a fixed device ID instead of a random one
    SPOOF_DEVICE_ID: str = ""

    def __init__(self, target_topic: str | None = None) -> None:
        self._device_id = self.SPOOF_DEVICE_ID or f"attacker-{uuid.uuid4().hex[:8]}"
        self._topic = target_topic or f"nodes/{self._device_id}/data"
        self._client_id = f"atk-{uuid.uuid4().hex[:8]}"

        self._mqtt = mqtt.Client(client_id=self._client_id, clean_session=True)
        self._mqtt.on_connect    = self._on_connect
        self._mqtt.on_disconnect = self._on_disconnect

        # Attack rate: messages per second (0 = as fast as possible)
        self._rate_hz = float(os.getenv("ATTACK_RATE_HZ", "0"))
        # Number of messages to send (0 = infinite)
        self._burst_count = int(os.getenv("ATTACK_BURST_COUNT", "0"))

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def build_payload(self, seq: int) -> dict | bytes:
        """Return the payload for message #seq. dict → JSON, bytes → raw."""

    # ── MQTT callbacks ─────────────────────────────────────────────────────────

    def _on_connect(self, client, userdata, flags, rc):
        status = "OK" if rc == 0 else f"FAILED (rc={rc})"
        print(f"[{self.ATTACK_NAME.upper()}] Connected to {GATEWAY_IP}:{GATEWAY_PORT} — {status}")

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print(f"[{self.ATTACK_NAME.upper()}] Disconnected unexpectedly (rc={rc})", file=sys.stderr)

    # ── Run loop ───────────────────────────────────────────────────────────────

    def _sleep(self) -> None:
        if self._rate_hz > 0:
            time.sleep(1.0 / self._rate_hz)

    def run(self) -> None:
        print(f"[{self.ATTACK_NAME.upper()}] Attack type  : {self.ATTACK_NAME}")
        print(f"[{self.ATTACK_NAME.upper()}] Target topic : {self._topic}")
        print(f"[{self.ATTACK_NAME.upper()}] Rate         : {'max' if self._rate_hz == 0 else f'{self._rate_hz:.1f} msg/s'}")
        print(f"[{self.ATTACK_NAME.upper()}] Burst count  : {'unlimited' if self._burst_count == 0 else self._burst_count}")
        print(f"[{self.ATTACK_NAME.upper()}] Connecting to {GATEWAY_IP}:{GATEWAY_PORT} ...")

        try:
            self._mqtt.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
        except Exception as exc:
            print(f"[{self.ATTACK_NAME.upper()}] Could not connect: {exc}", file=sys.stderr)
            sys.exit(1)

        self._mqtt.loop_start()

        seq = 1
        sent = 0
        try:
            while True:
                payload = self.build_payload(seq)

                if isinstance(payload, dict):
                    payload["is_attack"]    = True
                    payload["attack_label"] = self.ATTACK_NAME
                    payload["t_publish_ns"] = time.time_ns()
                    body = json.dumps(payload).encode()
                else:
                    body = payload

                res = self._mqtt.publish(self._topic, payload=body, qos=0)
                if res.rc == mqtt.MQTT_ERR_SUCCESS:
                    sent += 1
                    if sent % 100 == 0 or self._rate_hz > 0:
                        print(f"[{self.ATTACK_NAME.upper()}] Sent {sent} messages (seq={seq})")

                seq += 1
                if self._burst_count > 0 and sent >= self._burst_count:
                    print(f"[{self.ATTACK_NAME.upper()}] Burst complete ({sent} messages sent).")
                    break

                self._sleep()

        except KeyboardInterrupt:
            print(f"\n[{self.ATTACK_NAME.upper()}] Interrupted after {sent} messages.")
        finally:
            self._mqtt.loop_stop()
            self._mqtt.disconnect()
