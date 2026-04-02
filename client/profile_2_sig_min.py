from __future__ import annotations

import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from client.research_base_client import ResearchProfileClient


class Profile2_SignatureMinimization(ResearchProfileClient):
    DEVICE_ID = "profile-2"
    PROFILE_NAME = "2"
    ALG_KEM = "ML-KEM-512"
    ALG_SIG = "Falcon-512"
    SECURITY_BITS = 128

    def sample_data(self, seq: int) -> str:
        return f"Profile2_SignatureMinimization seq={seq}"


if __name__ == "__main__":
    Profile2_SignatureMinimization().run()

