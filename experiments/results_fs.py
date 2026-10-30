"""Ownership helpers for results/ written under sudo.

Experiment runners often create files as root. Leaving them root/nobody-owned
breaks later `git pull` on the login user. Call `chown_results_to_invoker`
after creating or finishing a session directory.
"""

from __future__ import annotations

import os
import pwd
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = REPO_ROOT / "results"


def invoker_user() -> str | None:
    """Login user who invoked sudo, else the current non-root user."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    if os.geteuid() != 0:
        try:
            return pwd.getpwuid(os.geteuid()).pw_name
        except KeyError:
            return None
    return None


def chown_results_to_invoker(path: Path | None = None) -> None:
    """Recursively chown path (default: results/) back to the invoking user.

    No-op when not root or when the invoker cannot be determined.
    """
    if os.geteuid() != 0:
        return
    user = invoker_user()
    if not user:
        return
    target = path or RESULTS_ROOT
    if not target.exists():
        return
    subprocess.run(
        ["chown", "-R", f"{user}:{user}", str(target)],
        check=False,
    )


def ensure_results_dir(path: Path) -> Path:
    """mkdir -p and immediately hand ownership back to the invoker."""
    path.mkdir(parents=True, exist_ok=True)
    chown_results_to_invoker(path if path.is_relative_to(RESULTS_ROOT) else RESULTS_ROOT)
    # Also fix parents under results/ that mkdir may have created as root.
    chown_results_to_invoker(RESULTS_ROOT)
    return path
