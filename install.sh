#!/usr/bin/env bash
# ReconMind installer for Ubuntu, Debian and Kali (WSL included).
#
#   git clone -b frontend https://github.com/r00tSud0/ReconMind.git ~/ReconMind
#   cd ~/ReconMind && ./install.sh
#
# What it does, after asking once:
#   1. system packages it needs to run (Python venv support, git, and the
#      window toolkit for the app window), with sudo
#   2. ReconMind's own Python environment in .venv with its pinned packages
#   3. the scanning tools and the ATT&CK model, through ReconMind setup
#      (python3 -m reconmind.setup --install)
#   4. an app menu entry, an icon and a `reconmind` command
# Running it again repairs anything missing. It never scans anything and never
# changes the allowed or blocked lab networks. ./uninstall.sh removes steps 4 and 2.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"
REPO="$(pwd)"
VENV="$REPO/.venv"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
BIN="$HOME/.local/bin"
ICON="$REPO/reconmind/web/static/img/reconmind-icon.png"
YES=0
[ "${1:-}" = "--yes" ] && YES=1

say() { printf '\n== %s\n' "$*"; }
fail() { printf '\nReconMind install stopped: %s\n' "$*" >&2; exit 1; }

[ -d "$REPO/reconmind" ] || fail "run this from the ReconMind folder."
[ "$(id -u)" -ne 0 ] || fail "run it as your normal user, not root. It asks for sudo itself."

# ---- 1. what this machine is ---------------------------------------------
. /etc/os-release 2>/dev/null || fail "/etc/os-release is missing, so this Linux is not supported yet."
case "${ID:-}" in
  ubuntu|debian|kali) ;;
  *) fail "${PRETTY_NAME:-this system} is not supported yet. Supported: Ubuntu, Debian and Kali." ;;
esac
case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) fail "only 64 bit Intel/AMD and ARM are supported." ;;
esac
# The distribution's own Python, because the window's GTK bindings (python3-gi)
# are built for it. Another python3 earlier on PATH would not load them.
PY=/usr/bin/python3
[ -x "$PY" ] || PY="$(command -v python3 || true)"
[ -n "$PY" ] || fail "python3 is missing. Install it with your package manager first."
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
  || fail "Python 3.10 or newer is needed; this system has $("$PY" -V 2>&1)."

# The app window: GTK WebKit for pywebview. 4.1 on current releases, 4.0 on older ones.
WEBKIT=""
for pkg in gir1.2-webkit2-4.1 gir1.2-webkit2-4.0; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then WEBKIT="$pkg"; break; fi
done
WANT=(python3-venv python3-pip git python3-gi python3-gi-cairo gir1.2-gtk-3.0)
[ -n "$WEBKIT" ] && WANT+=("$WEBKIT")
MISSING=()
for pkg in "${WANT[@]}"; do
  dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || MISSING+=("$pkg")
done

say "ReconMind will be installed for ${PRETTY_NAME:-Linux}"
echo "  Folder:            $REPO"
echo "  System packages:   ${MISSING[*]:-none needed}"
echo "  Python packages:   into $VENV"
echo "  Scanning tools and the ATT&CK model: through ReconMind setup, which shows its own plan"
echo "  App menu entry and the 'reconmind' command"
echo "ReconMind only scans lab networks you own or are allowed to test. Installing never scans anything."
if [ "$YES" -ne 1 ]; then
  read -r -p "Continue? Type y and press Enter: " answer
  [ "${answer:-}" = "y" ] || [ "${answer:-}" = "Y" ] || { echo "Nothing was installed."; exit 3; }
fi

# ---- 2. system packages ---------------------------------------------------
if [ "${#MISSING[@]}" -gt 0 ]; then
  say "Installing system packages (asks for your password)"
  sudo apt-get update
  sudo apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "${MISSING[@]}"
fi

# ---- 3. ReconMind's Python environment -------------------------------------
# --system-site-packages only so the window can use the system GTK bindings
# (python3-gi cannot come from pip); everything else is pinned in .venv.
if [ -x "$VENV/bin/python" ] && [ "$("$VENV/bin/python" -c 'import sys; print(sys.base_prefix)')" != "$("$PY" -c 'import sys; print(sys.base_prefix)')" ]; then
  say "Rebuilding .venv with the system Python"
  rm -rf "$VENV"
fi
if [ ! -x "$VENV/bin/python" ]; then
  say "Creating ReconMind's Python environment"
  "$PY" -m venv --system-site-packages "$VENV"
fi
say "Installing ReconMind's Python packages"
"$VENV/bin/python" -m pip install -q --disable-pip-version-check --upgrade pip
"$VENV/bin/python" -m pip install -q --disable-pip-version-check \
  -r requirements.txt -r requirements-web.txt pywebview==6.2.1

# ---- 4. tools and model -----------------------------------------------------
say "Installing the scanning tools and the ATT&CK model"
set +e
"$VENV/bin/python" -m reconmind.setup --install --yes
SETUP=$?
set -e

# ---- 5. menu entry, icon and command ----------------------------------------
say "Adding ReconMind to the app menu"
mkdir -p "$APPS" "$BIN"
cat > "$BIN/reconmind" <<EOF
#!/bin/sh
cd "$REPO" && exec "$VENV/bin/python" -m reconmind.desktop "\$@"
EOF
chmod 755 "$BIN/reconmind"
cat > "$APPS/reconmind.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=ReconMind
GenericName=Security assessment
Comment=Authorized lab reconnaissance and code scanning with AI reports
Exec=$BIN/reconmind
Path=$REPO
Icon=$ICON
Terminal=false
Categories=Security;Network;Development;
StartupWMClass=ReconMind
EOF
chmod 644 "$APPS/reconmind.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" >/dev/null 2>&1 || true

say "Done"
if [ "$SETUP" -eq 0 ]; then
  echo "Everything is installed."
else
  echo "ReconMind is installed, but some setup steps did not finish (see above)."
  echo "Open ReconMind and use System, then Repair setup, or run ./install.sh again."
fi
echo "Open ReconMind from the app menu, or run: reconmind"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "(The reconmind command works after you open a new terminal, or run $BIN/reconmind now.)" ;;
esac
exit 0
