"""
Profile C — High-Assurance Fallback

Focus: maximum security resilience and conservative math.
Pairings:
  - FrodoKEM-640-AES + SLH-DSA (hash-based)

Important: SLH-DSA mechanism strings vary in liboqs builds. The default here
uses one common liboqs-python name. If it is not supported on your device,
run:
  python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"
and pick a suitable SLH_DSA_* variant.
"""

from __future__ import annotations

from client.research_base_client import ResearchProfileClient


class ProfileC_HighAssuranceFallback(ResearchProfileClient):
    DEVICE_ID = "profile-c"
    PROFILE_NAME = "C"
    ALG_KEM = "FrodoKEM-640-AES"
    ALG_SIG = "SLH_DSA_PURE_SHA2_128S"
    SECURITY_BITS = 256

    def sample_data(self, seq: int) -> str:
        return f"Profile C sample #{seq}: conservative telemetry"


if __name__ == "__main__":
    ProfileC_HighAssuranceFallback().run()

