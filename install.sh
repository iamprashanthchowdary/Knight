#!/bin/sh
# Knight one-time installer: adds the APT repo, then installs. After this,
# `apt install knight` works and `apt upgrade` pulls future releases.
#
#   curl -fsSL https://iamprashanthchowdary.github.io/Knight/install.sh | sh
#
set -e

REPO_URL="https://iamprashanthchowdary.github.io/Knight"
KEYRING="/usr/share/keyrings/knight-archive-keyring.gpg"
LIST="/etc/apt/sources.list.d/knight.list"

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

echo "Adding Knight repository ($REPO_URL) ..."
$SUDO mkdir -p /usr/share/keyrings
$SUDO curl -fsSL "$REPO_URL/knight-archive-keyring.gpg" -o "$KEYRING"
echo "deb [signed-by=$KEYRING] $REPO_URL stable main" | $SUDO tee "$LIST" >/dev/null

$SUDO apt-get update
$SUDO apt-get install -y knight

echo
echo "Installed. Next:"
echo "  1. point a site at your nginx log in /etc/knight/config.json"
echo "  2. sudo systemctl restart knight"
echo "  3. systemctl status knight   ·   curl -s 127.0.0.1:8090/v1/overview"
