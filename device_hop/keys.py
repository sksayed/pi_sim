"""Load pinned device-hop keys. Private keys are read only on their own machine."""

from __future__ import annotations

import os
from pathlib import Path

from cloud.uplink_keys import load_pinned, read_alg

_REPO = Path(__file__).resolve().parents[1]


def _path(env: str, default: str) -> Path:
    return Path(os.getenv(env, default))


def gateway_public_key() -> tuple[bytes, str] | None:
    """Pinned gateway ML-KEM public key for a device, or None if not installed."""
    pk_path = _path("DEVICE_HOP_GATEWAY_PK", str(_REPO / "keys" / "device_hop" / "gateway" / "kem.pk"))
    trust = _path("DEVICE_HOP_DEVICE_TRUST", str(_REPO / "keys" / "device_hop" / "device_trust.json"))
    if not pk_path.exists() or not trust.exists():
        return None
    pk = load_pinned(pk_path, trust, "gateway_hop_kem_pk")
    return pk, read_alg(pk_path, "ML-KEM-768")


def device_signing_key(device_id: str) -> tuple[bytes, str] | None:
    """This device's ML-DSA private key, or None if it was not generated here."""
    default = _REPO / "keys" / "device_hop" / "devices" / device_id / "sig.sk"
    sk_path = _path("DEVICE_HOP_SIG_SK", str(default))
    if not sk_path.exists():
        return None
    return sk_path.read_bytes(), read_alg(sk_path, "ML-DSA-65")


def gateway_secret_key() -> tuple[bytes, str] | None:
    """Gateway ML-KEM private key. None when this host has not generated one."""
    sk_path = _path("DEVICE_HOP_KEM_SK", str(_REPO / "keys" / "device_hop" / "gateway" / "kem.sk"))
    if not sk_path.exists():
        return None
    return sk_path.read_bytes(), read_alg(sk_path, "ML-KEM-768")


def device_public_key(device_id: str) -> tuple[bytes, str]:
    """Pinned ML-DSA public key for one device. Raises if the pin is missing."""
    pk_dir = _path("DEVICE_HOP_PK_DIR", str(_REPO / "keys" / "device_hop" / "devices"))
    pk_path = pk_dir / device_id / "sig.pk"
    trust = _path("DEVICE_HOP_GATEWAY_TRUST", str(_REPO / "keys" / "device_hop" / "gateway_trust.json"))
    pk = load_pinned(pk_path, trust, f"device_sig:{device_id}")
    return pk, read_alg(pk_path, "ML-DSA-65")
