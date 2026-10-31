"""Seal and open one device-to-gateway message.

The signed bytes use a different domain tag from the gateway-to-cloud envelope,
so a signature from one hop cannot be replayed on the other.
"""

from __future__ import annotations

import base64
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cloud.uplink_keys import decapsulate, encapsulate, sign, verify

DOMAIN = b"PI-SIM-DEV-ENVELOPE-V1"


def encode(device_id: str, seq: int, kem_ct: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    fields = (
        str(device_id).encode("utf-8"),
        int(seq).to_bytes(8, "big"),
        kem_ct,
        nonce,
        ciphertext,
    )
    return DOMAIN + b"".join(struct.pack(">I", len(field)) + field for field in fields)


def seal(
    device_id: str,
    seq: int,
    plaintext: bytes,
    gateway_pk: bytes,
    sig_sk: bytes,
    kem_alg: str,
    sig_alg: str,
) -> tuple[dict, int]:
    """Return the MQTT object and the device cryptographic time in nanoseconds.

    That time is encapsulation plus AES-GCM plus the signature. It is not a
    Stage 2 measurement.
    """
    t0 = time.perf_counter_ns()
    kem_ct, shared = encapsulate(kem_alg, gateway_pk)
    t1 = time.perf_counter_ns()
    nonce = os.urandom(12)
    t2 = time.perf_counter_ns()
    ciphertext = AESGCM(shared[:32]).encrypt(nonce, plaintext, None)
    t3 = time.perf_counter_ns()
    message = encode(device_id, seq, kem_ct, nonce, ciphertext)
    t4 = time.perf_counter_ns()
    signature = sign(sig_alg, sig_sk, message)
    t5 = time.perf_counter_ns()
    crypto_ns = (t1 - t0) + (t3 - t2) + (t5 - t4)
    body = {
        "crypto_type": "device_kem",
        "device_id": device_id,
        "seq": int(seq),
        "kem": kem_alg,
        "sig": sig_alg,
        "kem_ciphertext": base64.b64encode(kem_ct).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
        "t_device_crypto_ns": crypto_ns,
    }
    return body, crypto_ns


def open_message(
    body: dict,
    gateway_sk: bytes,
    device_pk: bytes,
    kem_alg: str,
    sig_alg: str,
) -> tuple[bytes, int]:
    """Verify, decapsulate, and decrypt. Return plaintext and open time.

    Raises ValueError when the signature, the ciphertext, or the encoding is bad.
    """
    t0 = time.perf_counter_ns()
    try:
        kem_ct = base64.b64decode(body["kem_ciphertext"], validate=True)
        nonce = base64.b64decode(body["nonce"], validate=True)
        ciphertext = base64.b64decode(body["ciphertext"], validate=True)
        signature = base64.b64decode(body["signature"], validate=True)
        message = encode(str(body["device_id"]), int(body["seq"]), kem_ct, nonce, ciphertext)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed device envelope: {exc}") from exc
    if not verify(sig_alg, device_pk, message, signature):
        raise ValueError("device signature rejected")
    try:
        shared = decapsulate(kem_alg, gateway_sk, kem_ct)
        plaintext = AESGCM(shared[:32]).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("device decrypt failed") from exc
    return plaintext, time.perf_counter_ns() - t0
