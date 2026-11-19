#!/usr/bin/env bash
# Remove what ./install.sh added: the app menu entry, the `reconmind` command
# and ReconMind's .venv. Your reports, your .env and the model stay in this
# folder. With --tools, also remove the tools setup installed into
# ~/.local/share/reconmind (system packages from apt are left alone).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/reconmind"

rm -f "$APPS/reconmind.desktop" "$HOME/.local/bin/reconmind"
echo "Removed the app menu entry and the reconmind command."
if [ -d .venv ]; then rm -rf .venv; echo "Removed .venv."; fi
if [ "${1:-}" = "--tools" ] && [ -d "$DATA" ]; then
  rm -rf "$DATA"
  echo "Removed the tools in $DATA."
fi
echo "Reports, .env and models/ were kept."
