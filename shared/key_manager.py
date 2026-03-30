"""
key_manager.py — Deterministic key derivation for every device.

All keys (AES, KEM, signatures) are derived from a single MASTER_SECRET via
HKDF-SHA256. Because derivation is deterministic, every Pi independently
arrives at identical keys without transferring key material over the network.

When liboqs Python bindings are available, real post-quantum cryptography is
used. When they are absent a simulation fallback produces structurally-valid
byte outputs so the full MQTT + encryption pipeline still runs end-to-end.
"""

import ctypes
import hashlib
import hmac
import os
import sys
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ── PQC library ────────────────────────────────────────────────────────────────
try:
    import oqs  # liboqs-python bindings
    import warnings as _w
    _w.filterwarnings("ignore", message="liboqs version")
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    warnings.warn(
        "[KeyManager] pyoqs not found — running in SIMULATION mode. "
        "PQC operations use deterministic stubs; no real post-quantum security.",
        stacklevel=2,
    )

# ── liboqs C library (for derand / custom-RNG APIs) ───────────────────────────
_liboqs = None
if PQC_AVAILABLE:
    try:
        _liboqs = ctypes.CDLL("/usr/local/lib/liboqs.so")
    except OSError:
        pass

# C callback type: void (*)(uint8_t *buf, size_t n)
_RandCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)

# ── Simulation parameter table (best-effort sizes) ────────────────────────────
# These are only used when PQC bindings are unavailable. When PQC is available,
# actual ciphertext/signature sizes come from liboqs at runtime.
_KEM_PARAMS = {
    # Classic Kyber names (liboqs may also expose ML-KEM names)
    "Kyber512": {"ct": 768},
    "Kyber768": {"ct": 1088},
    # FIPS 203 names (approximate; used only in sim mode)
    "ML-KEM-512": {"ct": 768},
    "ML-KEM-768": {"ct": 1088},
    # FrodoKEM ciphertext is large; approximate size for sim-only wire realism.
    "FrodoKEM-640-AES": {"ct": 9720},
}
_SIG_PARAMS = {
    # FIPS 204 / ML-DSA (Dilithium family)
    "ML-DSA-44": {"sig": 2420},
    "ML-DSA-65": {"sig": 3293},
    # Falcon
    "Falcon-512": {"sig": 666},
    # SLH-DSA (SPHINCS+ family) — sizes vary by variant; sim only.
    "SLH_DSA_PURE_SHA2_128S": {"sig": 7856},
    "SLH-DSA-128s": {"sig": 7856},
}


# ── KeyManager ─────────────────────────────────────────────────────────────────

class KeyManager:
    """Derives all cryptographic keys from a single master secret."""

    def __init__(self, master_secret: str) -> None:
        if not master_secret:
            raise ValueError("MASTER_SECRET must not be empty.")
        self._master = master_secret.encode("utf-8")

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _hkdf(self, info: str, length: int) -> bytes:
        """Derive `length` bytes keyed by `info` from the master secret."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info.encode("utf-8"),
            backend=default_backend(),
        ).derive(self._master)

    # ── AES ────────────────────────────────────────────────────────────────────

    def aes_key(self, device_id: str) -> bytes:
        """Return a 32-byte AES-256 key scoped to `device_id`."""
        return self._hkdf(f"aes:{device_id}", 32)

    # ── Deterministic RNG hook (liboqs custom RNG) ─────────────────────────────

    def _with_deterministic_rng(self, info: str, seed_len: int, fn):
        """
        Temporarily replace liboqs's RNG with a deterministic stream derived
        from HKDF, call `fn()`, then restore the system RNG.
        """
        seed_bytes = self._hkdf(info, seed_len)
        buf = bytearray(seed_bytes * 64)  # large repeating buffer
        pos = [0]

        @_RandCallback
        def _fill(ptr, n):
            for i in range(n):
                ptr[i] = buf[pos[0] % len(buf)]
                pos[0] += 1

        if _liboqs:
            _liboqs.OQS_randombytes_custom_algorithm(_fill)
        try:
            return fn()
        finally:
            if _liboqs:
                _liboqs.OQS_randombytes_switch_algorithm(b"system")

    # ── Generic KEM (real + sim) ───────────────────────────────────────────────

    def kem_keypair(self, alg: str):
        """Return (public_key, secret_key) for the given KEM algorithm."""
        def _gen():
            kem = oqs.KeyEncapsulation(alg)
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            return pk, sk
        if PQC_AVAILABLE:
            return self._with_deterministic_rng(f"kem:{alg}:keypair", 64, _gen)

        # Simulation: derive deterministic pseudo-keys (sizes not required for KEM
        # ops in sim mode because we also simulate encap/decap).
        pk = self._hkdf(f"kem:{alg}:sim_pk", 64)
        sk = self._hkdf(f"kem:{alg}:sim_sk", 64)
        return pk, sk

    def kem_encapsulate(self, alg: str, public_key: bytes):
        """
        Encapsulate against `public_key`.
        Returns (kem_ciphertext, shared_secret_32_bytes).
        """
        if PQC_AVAILABLE:
            kem = oqs.KeyEncapsulation(alg)
            ct, ss = kem.encap_secret(public_key)
            return ct, ss[:32]

        ct_len = _KEM_PARAMS.get(alg, {}).get("ct", 512)
        ct = os.urandom(ct_len)
        ss = self._hkdf(f"kem:{alg}:sim_shared_secret", 32)
        return ct, ss

    def kem_decapsulate(self, alg: str, secret_key: bytes, kem_ciphertext: bytes):
        """Decapsulate `kem_ciphertext` with `secret_key` → shared_secret_32_bytes."""
        if PQC_AVAILABLE:
            kem = oqs.KeyEncapsulation(alg, secret_key=secret_key)
            ss = kem.decap_secret(kem_ciphertext)
            return ss[:32]

        return self._hkdf(f"kem:{alg}:sim_shared_secret", 32)

    def kyber512_keypair(self):
        """Return (public_key, secret_key) for Kyber-512."""
        return self.kem_keypair("Kyber512")

    def kyber768_keypair(self):
        """Return (public_key, secret_key) for Kyber-768."""
        return self.kem_keypair("Kyber768")

    def kyber_encapsulate(self, alg: str, public_key: bytes):
        """
        Encapsulate against `public_key`.
        Returns (kem_ciphertext, shared_secret_32_bytes).
        """
        return self.kem_encapsulate(alg, public_key)

    def kyber_decapsulate(self, alg: str, secret_key: bytes, kem_ciphertext: bytes):
        """
        Decapsulate `kem_ciphertext` with `secret_key`.
        Returns shared_secret_32_bytes.
        """
        return self.kem_decapsulate(alg, secret_key, kem_ciphertext)

    # ── Generic signatures (real + sim) ────────────────────────────────────────

    def sig_keypair(self, alg: str, device_id: str):
        """Return (public_key, secret_key) for the given signature algorithm."""
        def _gen():
            s = oqs.Signature(alg)
            pk = s.generate_keypair()
            sk = s.export_secret_key()
            return pk, sk
        if PQC_AVAILABLE:
            return self._with_deterministic_rng(f"sig:{alg}:{device_id}:keypair", 64, _gen)

        pk = self._hkdf(f"sig:{alg}:{device_id}:sim_pk", 64)
        sk = self._hkdf(f"sig:{alg}:{device_id}:sim_sk", 64)
        return pk, sk

    def dilithium3_keypair(self, device_id: str):
        """Return (public_key, secret_key) for ML-DSA-65 (formerly Dilithium-3)."""
        return self.sig_keypair("ML-DSA-65", device_id)

    def sig_sign(self, alg: str, message: bytes, secret_key: bytes) -> bytes:
        """Sign `message` with `alg`. Returns a signature."""
        if PQC_AVAILABLE:
            signer = oqs.Signature(alg, secret_key=secret_key)
            return signer.sign(message)

        # Simulation: HMAC-SHA256 padded/truncated to approximate algorithm size.
        tag = hmac.new(secret_key[:32], message, hashlib.sha256).digest()
        sig_len = _SIG_PARAMS.get(alg, {}).get("sig", 2048)
        if sig_len <= len(tag):
            return tag[:sig_len]
        return tag + os.urandom(sig_len - len(tag))

    def dilithium3_sign(self, message: bytes, secret_key: bytes) -> bytes:
        return self.sig_sign("ML-DSA-65", message, secret_key)

    def sig_verify(self, alg: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify `signature` over `message` with `alg`."""
        if PQC_AVAILABLE:
            verifier = oqs.Signature(alg)
            return verifier.verify(message, signature, public_key)

        # Simulation: accept if leading tag matches a deterministic HMAC.
        expected = hmac.new(public_key[:32], message, hashlib.sha256).digest()
        return hmac.compare_digest(signature[: len(expected)], expected)

    def dilithium3_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self.sig_verify("ML-DSA-65", message, signature, public_key)

    def _extract_device_id_from_sim_pk(self, public_key: bytes) -> str:
        """
        In sim mode the gateway knows the device_id from the MQTT message
        and calls dilithium3_keypair(device_id) directly, so this fallback is
        never actually reached. Kept as a safety guard.
        """
        return "unknown"


# ── Module-level convenience factory ──────────────────────────────────────────

def load_key_manager() -> KeyManager:
    """Load MASTER_SECRET from environment and return a KeyManager instance."""
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
    secret = os.getenv("MASTER_SECRET", "")
    if not secret:
        print(
            "[KeyManager] ERROR: MASTER_SECRET is not set in .env", file=sys.stderr
        )
        sys.exit(1)
    return KeyManager(secret)
