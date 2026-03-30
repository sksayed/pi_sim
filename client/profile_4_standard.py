from __future__ import annotations

from client.research_base_client import ResearchProfileClient


class Profile4_StandardizedCompliance(ResearchProfileClient):
    DEVICE_ID = "profile-4"
    PROFILE_NAME = "4"
    ALG_KEM = "ML-KEM-768"
    ALG_SIG = "ML-DSA-65"
    SECURITY_BITS = 192

    def sample_data(self, seq: int) -> str:
        return f"Profile4_StandardizedCompliance seq={seq}"


if __name__ == "__main__":
    Profile4_StandardizedCompliance().run()

