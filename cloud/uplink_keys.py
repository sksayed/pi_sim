"""Independent ML-KEM and ML-DSA keys for the gateway-to-cloud hop.

Key generation uses liboqs' system RNG. It does not use the HKDF callback in
shared/key_manager.py. Private keys stay on the machine that generated them.
A public key is accepted only when its SHA-256 matches keys/trust.json.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

KEM_CANDIDATES = ("ML-KEM-768", "Kyber768")
SIG_CANDIDATES = ("ML-DSA-65", "Dilithium3", "Dilithium3-AES")


def _oqs():
    try:
        import oqs
    except ImportError as exc:
        raise RuntimeError(
            "liboqs-python is required to generate or use cloud uplink keys."
        ) from exc
    return oqs


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _first_enabled(kind: str, candidates: tuple[str, ...]) -> str:
    oqs = _oqs()
    last: Exception | None = None
    factory = oqs.KeyEncapsulation if kind == "kem" else oqs.Signature
    for name in candidates:
        try:
            factory(name)
            return name
        except Exception as exc:
            last = exc
    raise RuntimeError(f"liboqs has none of: {', '.join(candidates)}") from last


def kem_algorithm() -> str:
    return _first_enabled("kem", KEM_CANDIDATES)


def sig_algorithm() -> str:
    return _first_enabled("sig", SIG_CANDIDATES)


def generate_kem() -> tuple[bytes, bytes, str]:
    alg = kem_algorithm()
    kem = _oqs().KeyEncapsulation(alg)
    pk = kem.generate_keypair()
    return pk, kem.export_secret_key(), alg


def generate_sig() -> tuple[bytes, bytes, str]:
    alg = sig_algorithm()
    sig = _oqs().Signature(alg)
    pk = sig.generate_keypair()
    return pk, sig.export_secret_key(), alg


def write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, 0o600)


def load_pinned(pk_path: Path, trust_path: Path, label: str) -> bytes:
    """Load a public key whose fingerprint is already in the trust file."""
    pk = pk_path.read_bytes()
    got = fingerprint(pk)
    trust = json.loads(trust_path.read_text())
    expected = trust.get(label)
    if not expected:
        raise RuntimeError(f"{trust_path} has no pin for {label}.")
    if got != expected:
        raise RuntimeError(
            f"Public key {pk_path} fingerprint {got} does not match the pin for {label}."
        )
    return pk


def record_pin(trust_path: Path, label: str, pk_path: Path) -> str:
    pk = pk_path.read_bytes()
    digest = fingerprint(pk)
    trust = {}
    if trust_path.exists():
        trust = json.loads(trust_path.read_text())
    previous = trust.get(label)
    if previous and previous != digest:
        raise RuntimeError(
            f"{trust_path} already pins {label} to {previous}, not {digest}."
        )
    trust[label] = digest
    trust_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = trust_path.with_suffix(trust_path.suffix + ".tmp")
    tmp.write_text(json.dumps(trust, indent=2) + "\n")
    os.replace(tmp, trust_path)
    return digest


def read_alg(path: Path, default: str) -> str:
    sidecar = path.with_suffix(".alg")
    if sidecar.exists():
        return sidecar.read_text().strip()
    return default


def encapsulate(algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, shared secret) for one fresh encapsulation."""
    kem = _oqs().KeyEncapsulation(algorithm)
    ciphertext, shared = kem.encap_secret(public_key)
    return ciphertext, shared


def decapsulate(algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
    kem = _oqs().KeyEncapsulation(algorithm, secret_key=secret_key)
    return kem.decap_secret(ciphertext)


def sign(algorithm: str, secret_key: bytes, message: bytes) -> bytes:
    signer = _oqs().Signature(algorithm, secret_key=secret_key)
    return signer.sign(message)


def verify(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    verifier = _oqs().Signature(algorithm)
    try:
        return bool(verifier.verify(message, signature, public_key))
    except Exception:
        return False
