from __future__ import annotations

import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

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

