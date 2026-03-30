from __future__ import annotations

from client.research_base_client import ResearchProfileClient


class Profile3_KemDiversity(ResearchProfileClient):
    DEVICE_ID = "profile-3"
    PROFILE_NAME = "3"
    ALG_KEM = "BIKE-L1"
    ALG_SIG = "ML-DSA-44"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"Profile3_KemDiversity seq={seq}"


if __name__ == "__main__":
    Profile3_KemDiversity().run()

