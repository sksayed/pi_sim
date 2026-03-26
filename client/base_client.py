"""
base_client.py — Shared MQTT connection and publish logic.

Every typed client (A, B, C) inherits BaseClient and only needs to implement
`build_message(seq)` which returns a dict ready to be JSON-serialised and
published.
"""

import json
import os
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

# ── Load .env from repo root ───────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP       = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT     = int(os.getenv("GATEWAY_PORT", 1883))
PUBLISH_INTERVAL = float(os.getenv("PUBLISH_INTERVAL", 2))


class BaseClient(ABC):
    """
    Abstract base for all typed MQTT clients.

    Subclasses must define:
        DEVICE_ID   (str)  — unique identifier sent on the wire
        CRYPTO_TYPE (str)  — human-readable label for the encryption scheme
        build_message(seq) — return a JSON-serialisable dict
    """

    DEVICE_ID: str = ""
    CRYPTO_TYPE: str = ""

    def __init__(self) -> None:
        if not self.DEVICE_ID:
            raise NotImplementedError("Subclass must set DEVICE_ID")

        self._topic = f"nodes/{self.DEVICE_ID}/data"
        self._mqtt  = mqtt.Client(client_id=self.DEVICE_ID, clean_session=True)
        self._mqtt.on_connect    = self._on_connect
        self._mqtt.on_publish    = self._on_publish
        self._mqtt.on_disconnect = self._on_disconnect

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def build_message(self, seq: int) -> dict:
        """Return a JSON-serialisable dict to publish for sequence `seq`."""

    # ── MQTT callbacks ─────────────────────────────────────────────────────────

    def _on_connect(self, client, userdata, flags, rc):
        tag = f"[{self.DEVICE_ID.upper()}]"
        if rc == 0:
            print(f"{tag} Connected to broker at {GATEWAY_IP}:{GATEWAY_PORT}")
        else:
            print(f"{tag} Connection failed — rc={rc}", file=sys.stderr)

    def _on_publish(self, client, userdata, mid):
        print(f"[{self.DEVICE_ID.upper()}] Delivered (mid={mid})")

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print(
                f"[{self.DEVICE_ID.upper()}] Unexpected disconnect (rc={rc})",
                file=sys.stderr,
            )

    # ── Run loop ───────────────────────────────────────────────────────────────

    def run(self) -> None:
        tag = f"[{self.DEVICE_ID.upper()}]"
        print(f"{tag} Crypto: {self.CRYPTO_TYPE}")
        print(f"{tag} Connecting to {GATEWAY_IP}:{GATEWAY_PORT} …")

        try:
            self._mqtt.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
        except Exception as exc:
            print(f"{tag} Could not connect: {exc}", file=sys.stderr)
            sys.exit(1)

        self._mqtt.loop_start()

        seq = 1
        try:
            while True:
                msg  = self.build_message(seq)
                body = json.dumps(msg)
                res  = self._mqtt.publish(self._topic, payload=body, qos=1)

                if res.rc == mqtt.MQTT_ERR_SUCCESS:
                    print(f"{tag} Published seq={seq} to '{self._topic}'")
                else:
                    print(f"{tag} Publish failed (rc={res.rc})", file=sys.stderr)

                seq += 1
                time.sleep(PUBLISH_INTERVAL)

        except KeyboardInterrupt:
            print(f"\n{tag} Shutting down.")
            self._mqtt.loop_stop()
            self._mqtt.disconnect()
