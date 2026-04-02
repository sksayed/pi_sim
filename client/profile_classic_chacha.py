from __future__ import annotations

import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from client.classic_research_client import ProfileClassicChaCha


if __name__ == "__main__":
    ProfileClassicChaCha().run()
