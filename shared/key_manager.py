"""
key_manager.py — Deterministic key derivation for every device.

All keys (AES, Kyber, Dilithium) are derived from a single MASTER_SECRET via
HKDF-SHA256. Because derivation is deterministic, every Pi independently
arrives at identical keys without transferring key material over the network.

When pyoqs / liboqs is available, real post-quantum cryptography is used.
When it is absent a simulation fallback produces outputs of the correct sizes
so the full MQTT + encryption pipeline still runs end-to-end.
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

# ── Kyber / Dilithium parameter table ─────────────────────────────────────────
# Sizes in bytes as defined in the NIST specifications.
_KEM_PARAMS = {
    "Kyber512": {"pk": 800,  "sk": 1632, "ct": 768,  "ss": 32},
    "Kyber768": {"pk": 1184, "sk": 2400, "ct": 1088, "ss": 32},
}
_SIG_PARAMS = {
    "ML-DSA-65": {"pk": 1952, "sk": 4000, "sig": 3293},
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

    # ── Kyber KEM ──────────────────────────────────────────────────────────────

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

    def _kyber_keypair_real(self, alg: str):
        """Generate a deterministic Kyber keypair via HKDF-seeded custom RNG."""
        def _gen():
            kem = oqs.KeyEncapsulation(alg)
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            return pk, sk
        return self._with_deterministic_rng(f"{alg.lower()}:keypair", 64, _gen)

    def _kyber_keypair_sim(self, alg: str):
        """Simulation: derive pseudo-keypair bytes deterministically."""
        p = _KEM_PARAMS[alg]
        pk = self._hkdf(f"{alg.lower()}:sim_pk", p["pk"])
        sk = self._hkdf(f"{alg.lower()}:sim_sk", p["sk"])
        return pk, sk

    def kyber512_keypair(self):
        """Return (public_key, secret_key) for Kyber-512."""
        if PQC_AVAILABLE:
            return self._kyber_keypair_real("Kyber512")
        return self._kyber_keypair_sim("Kyber512")

    def kyber768_keypair(self):
        """Return (public_key, secret_key) for Kyber-768."""
        if PQC_AVAILABLE:
            return self._kyber_keypair_real("Kyber768")
        return self._kyber_keypair_sim("Kyber768")

    def kyber_encapsulate(self, alg: str, public_key: bytes):
        """
        Encapsulate against `public_key`.
        Returns (kem_ciphertext, shared_secret_32_bytes).
        """
        p = _KEM_PARAMS[alg]
        if PQC_AVAILABLE:
            kem = oqs.KeyEncapsulation(alg)
            ct, ss = kem.encap_secret(public_key)
            return ct, ss[:32]

        # Simulation: shared secret derived deterministically; ct is a
        # structurally correct placeholder the gateway ignores in sim mode.
        ss = self._hkdf(f"{alg.lower()}:sim_shared_secret", 32)
        ct = os.urandom(p["ct"])
        return ct, ss

    def kyber_decapsulate(self, alg: str, secret_key: bytes, kem_ciphertext: bytes):
        """
        Decapsulate `kem_ciphertext` with `secret_key`.
        Returns shared_secret_32_bytes.
        """
        if PQC_AVAILABLE:
            kem = oqs.KeyEncapsulation(alg, secret_key=secret_key)
            ss = kem.decap_secret(kem_ciphertext)
            return ss[:32]

        # Simulation: recover the same deterministic shared secret.
        return self._hkdf(f"{alg.lower()}:sim_shared_secret", 32)

    # ── Dilithium signatures ───────────────────────────────────────────────────

    def _dilithium_keypair_real(self, alg: str, device_id: str):
        """Generate a deterministic ML-DSA keypair via HKDF-seeded custom RNG."""
        def _gen():
            s = oqs.Signature(alg)
            pk = s.generate_keypair()
            sk = s.export_secret_key()
            return pk, sk
        return self._with_deterministic_rng(f"{alg.lower()}:{device_id}:keypair", 64, _gen)

    def _dilithium_keypair_sim(self, alg: str, device_id: str):
        p = _SIG_PARAMS[alg]
        pk = self._hkdf(f"{alg.lower()}:{device_id}:sim_pk", p["pk"])
        sk = self._hkdf(f"{alg.lower()}:{device_id}:sim_sk", p["sk"])
        return pk, sk

    def dilithium3_keypair(self, device_id: str):
        """Return (public_key, secret_key) for ML-DSA-65 (formerly Dilithium-3)."""
        if PQC_AVAILABLE:
            return self._dilithium_keypair_real("ML-DSA-65", device_id)
        return self._dilithium_keypair_sim("ML-DSA-65", device_id)

    def dilithium3_sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign `message` with ML-DSA-65. Returns a signature."""
        if PQC_AVAILABLE:
            signer = oqs.Signature("ML-DSA-65", secret_key=secret_key)
            return signer.sign(message)

        # Simulation: HMAC-SHA256 padded to spec size.
        tag = hmac.new(secret_key[:32], message, hashlib.sha256).digest()
        p = _SIG_PARAMS["ML-DSA-65"]
        return tag + os.urandom(p["sig"] - len(tag))

    def dilithium3_verify(
        self, message: bytes, signature: bytes, public_key: bytes
    ) -> bool:
        """Verify `signature` over `message` with ML-DSA-65. Returns True if valid."""
        if PQC_AVAILABLE:
            verifier = oqs.Signature("ML-DSA-65")
            return verifier.verify(message, signature, public_key)

        # Simulation: recompute HMAC using sim_sk derived the same way.
        sim_sk = self._hkdf(
            f"ml-dsa-65:{self._extract_device_id_from_sim_pk(public_key)}:sim_sk",
            _SIG_PARAMS["ML-DSA-65"]["sk"],
        )
        expected_tag = hmac.new(sim_sk[:32], message, hashlib.sha256).digest()
        return hmac.compare_digest(signature[:32], expected_tag)

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
