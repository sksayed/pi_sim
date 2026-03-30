"""
Profile B — Standardized Compliance

Focus: FIPS 203/204 enterprise-grade standardized algorithms.
Pairings:
  - ML-KEM-768 + ML-DSA-65

Optionally, you may later add BIKE-L1 + ML-DSA-44 as a second script under
Profile B (kept separate so each run logs cleanly).
"""

from __future__ import annotations

from client.research_base_client import ResearchProfileClient


class ProfileB_StandardizedCompliance(ResearchProfileClient):
    DEVICE_ID = "profile-b"
    PROFILE_NAME = "B"
    ALG_KEM = "ML-KEM-768"
    ALG_SIG = "ML-DSA-65"
    SECURITY_BITS = 192

    def sample_data(self, seq: int) -> str:
        return f"Profile B sample #{seq}: standardized telemetry"


if __name__ == "__main__":
    ProfileB_StandardizedCompliance().run()

