#!/usr/bin/env bash
# Builds a Debian/Ubuntu .deb for the Knight observe agent.
#
#   ./packaging/build-deb.sh [version] [arch]
#
# arch is a Debian architecture name (amd64, arm64, ...) and doubles as the Go
# GOARCH -- they happen to match for these two. Defaults to the host's arch.
# Cross-building needs no extra toolchain: CGO is disabled, so it's pure Go.
#
# Produces dist/knight_<version>_<arch>.deb — a static single-binary install
# with a systemd service and a dedicated 'knight' user. No build-time deps
# beyond the Go toolchain and dpkg-deb.
set -euo pipefail

VERSION="${1:-0.1.0}"
ARCH="${2:-$(dpkg --print-architecture)}" # e.g. amd64, arm64
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="knight"
STAGE="$(mktemp -d)"
OUT="${ROOT}/dist"
trap 'rm -rf "${STAGE}"' EXIT

echo ">> building static binary (CGO disabled) ..."
# Static, stripped binary so it runs on any Ubuntu with no shared-lib concerns.
# -X flags bake the package VERSION and current commit into the binary so
# `knight --version` matches what `dpkg -l`/`apt` report -- without these the
# binary always falls back to its "dev (unknown)" default, silently out of
# sync with the actual package version being installed.
COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
	go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
	-o "${STAGE}/knight" "${ROOT}/cmd/knight"

echo ">> assembling package tree ..."
install -Dm0755 "${STAGE}/knight"                       "${STAGE}/pkg/usr/bin/knight"
install -Dm0644 "${ROOT}/packaging/systemd/knight.service" "${STAGE}/pkg/lib/systemd/system/knight.service"
install -Dm0644 "${ROOT}/packaging/config.default.json"  "${STAGE}/pkg/usr/share/knight/config.default.json"
install -Dm0644 "${ROOT}/packaging/README.md"            "${STAGE}/pkg/usr/share/doc/knight/README.md"

# Maintainer scripts.
install -Dm0755 "${ROOT}/packaging/scripts/postinst" "${STAGE}/pkg/DEBIAN/postinst"
install -Dm0755 "${ROOT}/packaging/scripts/prerm"    "${STAGE}/pkg/DEBIAN/prerm"
install -Dm0755 "${ROOT}/packaging/scripts/postrm"   "${STAGE}/pkg/DEBIAN/postrm"

# Installed-Size in KiB (dpkg convention), for accurate apt reporting.
SIZE_KB="$(du -sk "${STAGE}/pkg/usr" "${STAGE}/pkg/lib" | awk '{s+=$1} END {print s}')"

cat > "${STAGE}/pkg/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: Prashanth Chowdary <ch.prashanthchowdary007@gmail.com>
Depends: adduser
Installed-Size: ${SIZE_KB}
Description: nginx traffic observability agent
 Knight tails nginx access logs and serves traffic analytics (status-code
 breakdowns, per-IP behaviour, per-endpoint health, failure drill-down
 reports) plus webhook/email alerting over a local JSON API for the Knight
 dashboard. It observes only -- it never blocks or modifies traffic.
EOF

echo ">> building .deb ..."
mkdir -p "${OUT}"
DEB="${OUT}/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "${STAGE}/pkg" "${DEB}" >/dev/null

echo ">> done: ${DEB}"
