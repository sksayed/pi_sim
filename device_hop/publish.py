"""Seal a benign sensor dict when this device has been provisioned."""

from __future__ import annotations

import json
import os

from device_hop.envelope import seal
from device_hop.keys import device_signing_key, gateway_public_key


def _required() -> bool:
    return os.getenv("DEVICE_HOP", "").strip().lower() in ("1", "true", "yes", "on")


def protect(sensor: dict) -> dict:
    """Return sensor unchanged, or a device_kem object when keys are installed.

    DEVICE_HOP=1 refuses to publish until both keys are present.
    """
    gateway = gateway_public_key()
    signing = device_signing_key(str(sensor.get("device_id", "")))
    if gateway is None or signing is None:
        if _required():
            raise RuntimeError(
                "DEVICE_HOP=1 but the gateway public key or this device's signing key is not pinned"
            )
        return sensor
    gateway_pk, kem_alg = gateway
    sig_sk, sig_alg = signing
    plaintext = json.dumps(sensor, separators=(",", ":")).encode()
    body, _crypto_ns = seal(
        str(sensor["device_id"]),
        int(sensor["seq"]),
        plaintext,
        gateway_pk,
        sig_sk,
        kem_alg,
        sig_alg,
    )
    if sensor.get("msg_id"):
        body["msg_id"] = sensor["msg_id"]
    if sensor.get("t_publish_ns"):
        body["t_publish_ns"] = sensor["t_publish_ns"]
    if sensor.get("client_clock_offset_ns") is not None:
        body["client_clock_offset_ns"] = sensor["client_clock_offset_ns"]
    return body
