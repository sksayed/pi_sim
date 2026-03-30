from __future__ import annotations

from client.research_base_client import ResearchProfileClient


class Profile7_ExtremeFallback(ResearchProfileClient):
    DEVICE_ID = "profile-7"
    PROFILE_NAME = "7"
    ALG_KEM = "FrodoKEM-640-AES"
    ALG_SIG = "SLH_DSA_PURE_SHA2_128S"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"Profile7_ExtremeFallback seq={seq}"


if __name__ == "__main__":
    Profile7_ExtremeFallback().run()

