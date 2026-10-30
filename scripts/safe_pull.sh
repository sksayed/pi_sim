#!/usr/bin/env bash
# Fix results/ ownership, stash local result conflicts, then git pull.
# Use this instead of bare `git pull` on experiment Pis.
set -euo pipefail
cd "$(dirname "$0")/.."

USER_NAME="$(id -un)"
if [[ -d results ]] && find results -xdev ! -user "$USER_NAME" -print -quit 2>/dev/null | grep -q .; then
  echo "[safe_pull] Fixing results/ ownership (needs sudo)..."
  sudo chown -R "$USER_NAME:$USER_NAME" results/
fi

# Stash tracked dirt + untracked paths under results/ that would block merge.
mapfile -t CONFLICTS < <(
  {
    git diff --name-only
    git ls-files --others --exclude-standard
  } | grep -E '^results/' | sort -u || true
)

if ((${#CONFLICTS[@]})); then
  stamp="$(date +%Y%m%d-%H%M%S)"
  echo "[safe_pull] Stashing ${#CONFLICTS[@]} local results path(s) → stash (safe-pull $stamp)"
  git stash push -u -m "safe-pull $stamp" -- "${CONFLICTS[@]}"
else
  echo "[safe_pull] No local results conflicts."
fi

echo "[safe_pull] git pull..."
git pull "$@"
echo "[safe_pull] Done. Prior local results (if any) are in: git stash list"
