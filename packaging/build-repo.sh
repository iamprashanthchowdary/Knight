#!/usr/bin/env bash
# Builds a SIGNED APT repository from the .deb(s) in dist/, so end users can
#   curl -fsSL <your-url>/install.sh | sh      (one time)
# and thereafter `apt install knight` / `apt upgrade` work.
#
#   ./packaging/build-repo.sh https://apt.your-domain.com
#
# Output: dist/apt/  — upload its CONTENTS to that URL (any static host: your
# own nginx, S3, Cloudflare R2, GitHub Pages...). The repo files are
# URL-relative, so the same tree works at any URL.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_URL="${1:-https://REPLACE-WITH-YOUR-URL}"
DIST="${ROOT}/dist"
APT="${DIST}/apt"
GNUPGHOME="${ROOT}/packaging/gpg" # isolated keyring — KEEP SECRET, back it up
SUITE="stable"
COMP="main"
ARCH="$(dpkg --print-architecture)"
KEY_EMAIL="ch.prashanthchowdary007@gmail.com"

if ! ls "${DIST}"/knight_*.deb >/dev/null 2>&1; then
	echo "!! no .deb in dist/ — run ./packaging/build-deb.sh first" >&2
	exit 1
fi

# 1. Signing key, in an isolated keyring. Generated once; reused for every
#    release so the repo's key never changes under clients.
mkdir -p "${GNUPGHOME}"
chmod 700 "${GNUPGHOME}"
export GNUPGHOME
if ! gpg --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec'; then
	echo ">> generating repo signing key (guard ${GNUPGHOME}: it's your private key) ..."
	gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 3072
Name-Real: Knight Repository
Name-Email: ${KEY_EMAIL}
Expire-Date: 0
%commit
EOF
fi
KEY_FPR="$(gpg --list-keys --with-colons "${KEY_EMAIL}" | awk -F: '/^fpr:/{print $10; exit}')"

# 2. Repo tree.
echo ">> assembling apt repo ..."
rm -rf "${APT}"
mkdir -p "${APT}/pool/${COMP}" "${APT}/dists/${SUITE}/${COMP}/binary-${ARCH}"
cp "${DIST}"/knight_*.deb "${APT}/pool/${COMP}/"

cd "${APT}"
dpkg-scanpackages --multiversion "pool/${COMP}" > "dists/${SUITE}/${COMP}/binary-${ARCH}/Packages"
gzip -9kf "dists/${SUITE}/${COMP}/binary-${ARCH}/Packages"

apt-ftparchive \
	-o APT::FTPArchive::Release::Origin=Knight \
	-o APT::FTPArchive::Release::Label=Knight \
	-o APT::FTPArchive::Release::Suite="${SUITE}" \
	-o APT::FTPArchive::Release::Codename="${SUITE}" \
	-o APT::FTPArchive::Release::Components="${COMP}" \
	-o APT::FTPArchive::Release::Architectures="${ARCH}" \
	release "dists/${SUITE}" > "dists/${SUITE}/Release"

# 3. Sign the Release (both InRelease clearsign + detached Release.gpg).
gpg --default-key "${KEY_FPR}" --batch --yes --clearsign -o "dists/${SUITE}/InRelease" "dists/${SUITE}/Release"
gpg --default-key "${KEY_FPR}" --batch --yes -abs -o "dists/${SUITE}/Release.gpg" "dists/${SUITE}/Release"

# 4. Public keyring clients trust (referenced via signed-by=).
gpg --export "${KEY_FPR}" > "${APT}/knight-archive-keyring.gpg"

# 5. End-user install script, templated with the repo URL.
sed "s|@REPO_URL@|${REPO_URL}|g" "${ROOT}/packaging/install.sh.tmpl" > "${APT}/install.sh"
chmod +x "${APT}/install.sh"

echo ">> repo ready: ${APT}"
echo "   key fingerprint: ${KEY_FPR}"
echo "   upload the CONTENTS of dist/apt/ to: ${REPO_URL}"
echo "   users then run:  curl -fsSL ${REPO_URL}/install.sh | sh"
