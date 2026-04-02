from __future__ import annotations

import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from client.research_base_client import ResearchProfileClient


class Profile6_SignatureRobustness(ResearchProfileClient):
    DEVICE_ID = "profile-6"
    PROFILE_NAME = "6"
    ALG_KEM = "ML-KEM-768"
    ALG_SIG = "SLH_DSA_PURE_SHA2_128S"
    SECURITY_BITS = 192

    def sample_data(self, seq: int) -> str:
        return f"Profile6_SignatureRobustness seq={seq}"


if __name__ == "__main__":
    Profile6_SignatureRobustness().run()

