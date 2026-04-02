from __future__ import annotations

import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from client.research_base_client import ResearchProfileClient


class Profile1_BaselineFloor(ResearchProfileClient):
    DEVICE_ID = "profile-1"
    PROFILE_NAME = "1"
    ALG_KEM = "ML-KEM-512"
    ALG_SIG = "ML-DSA-44"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"Profile1_BaselineFloor seq={seq}"


if __name__ == "__main__":
    Profile1_BaselineFloor().run()

