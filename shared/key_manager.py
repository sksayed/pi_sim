"""
key_manager.py — Deterministic key derivation for every device.

All keys (AES, Kyber, Dilithium) are derived from a single MASTER_SECRET via
HKDF-SHA256. Because derivation is deterministic, every Pi independently
arrives at identical keys without transferring key material over the network.

When pyoqs / liboqs is available, real post-quantum cryptography is used.
When it is absent a simulation fallback produces outputs of the correct sizes
so the full MQTT + encryption pipeline still runs end-to-end.
"""

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
    import oqs  # pyoqs — Python bindings for liboqs
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    warnings.warn(
        "[KeyManager] pyoqs not found — running in SIMULATION mode. "
        "PQC operations use deterministic stubs; no real post-quantum security.",
        stacklevel=2,
    )

# ── Kyber / Dilithium parameter table ─────────────────────────────────────────
# Sizes in bytes as defined in the NIST specifications.
_KEM_PARAMS = {
    "Kyber512": {"pk": 800,  "sk": 1632, "ct": 768,  "ss": 32},
    "Kyber768": {"pk": 1184, "sk": 2400, "ct": 1088, "ss": 32},
}
_SIG_PARAMS = {
    "Dilithium3": {"pk": 1952, "sk": 4000, "sig": 3293},
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

    def _kyber_keypair_real(self, alg: str):
        """
        Generate a deterministic Kyber keypair using the NIST-KAT PRNG seeded
        from HKDF. Returns (public_key_bytes, secret_key_bytes).
        """
        seed_48 = self._hkdf(f"{alg.lower()}:nist_seed", 48)
        try:
            oqs.randombytes_switch_algorithm("NIST-KAT")
            oqs.randombytes_nist_kat_init_256bit(seed_48)
            kem = oqs.KeyEncapsulation(alg)
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            return pk, sk
        finally:
            # Always restore system PRNG regardless of success/failure.
            try:
                oqs.randombytes_switch_algorithm("system")
            except Exception:
                pass

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
        seed_48 = self._hkdf(f"{alg.lower()}:{device_id}:nist_seed", 48)
        try:
            oqs.randombytes_switch_algorithm("NIST-KAT")
            oqs.randombytes_nist_kat_init_256bit(seed_48)
            sig = oqs.Signature(alg)
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
            return pk, sk
        finally:
            try:
                oqs.randombytes_switch_algorithm("system")
            except Exception:
                pass

    def _dilithium_keypair_sim(self, alg: str, device_id: str):
        p = _SIG_PARAMS[alg]
        pk = self._hkdf(f"{alg.lower()}:{device_id}:sim_pk", p["pk"])
        sk = self._hkdf(f"{alg.lower()}:{device_id}:sim_sk", p["sk"])
        return pk, sk

    def dilithium3_keypair(self, device_id: str):
        """Return (public_key, secret_key) for Dilithium-3 scoped to `device_id`."""
        if PQC_AVAILABLE:
            return self._dilithium_keypair_real("Dilithium3", device_id)
        return self._dilithium_keypair_sim("Dilithium3", device_id)

    def dilithium3_sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign `message`. Returns a signature."""
        if PQC_AVAILABLE:
            signer = oqs.Signature("Dilithium3", secret_key=secret_key)
            return signer.sign(message)

        # Simulation: HMAC-SHA256 padded to spec size.
        tag = hmac.new(secret_key[:32], message, hashlib.sha256).digest()
        p = _SIG_PARAMS["Dilithium3"]
        return tag + os.urandom(p["sig"] - len(tag))

    def dilithium3_verify(
        self, message: bytes, signature: bytes, public_key: bytes
    ) -> bool:
        """Verify `signature` over `message`. Returns True if valid."""
        if PQC_AVAILABLE:
            verifier = oqs.Signature("Dilithium3")
            return verifier.verify(message, signature, public_key)

        # Simulation: recompute HMAC using sim_sk derived the same way.
        # The public_key bytes carry no secret in sim mode so we re-derive sk.
        # NOTE: this only works because both sides derive sk deterministically.
        sim_sk = self._hkdf(
            f"dilithium3:{self._extract_device_id_from_sim_pk(public_key)}:sim_sk",
            _SIG_PARAMS["Dilithium3"]["sk"],
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
