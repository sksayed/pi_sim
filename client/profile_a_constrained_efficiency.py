"""
Profile A — Constrained Efficiency

Focus: minimizing IoT overhead (\"floor\" of PQC costs).
Pairings:
  - ML-KEM-512 + Falcon-512

Note: If your liboqs build does not expose ML-KEM names, you may need to switch
ALG_KEM to \"Kyber512\". This profile is meant to be the lowest-overhead option.
"""

from __future__ import annotations

from client.research_base_client import ResearchProfileClient


class ProfileA_ConstrainedEfficiency(ResearchProfileClient):
    DEVICE_ID = "profile-a"
    PROFILE_NAME = "A"
    ALG_KEM = "ML-KEM-512"
    ALG_SIG = "Falcon-512"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"Profile A sample #{seq}: low-overhead telemetry"


if __name__ == "__main__":
    ProfileA_ConstrainedEfficiency().run()

