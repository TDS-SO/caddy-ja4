#!/usr/bin/env bash
# Build the JA4-enabled Caddy binary ONCE, here (CI or a build box), for each
# target arch, and emit checksums. Host the outputs yourself; the installer
# downloads them — never run xcaddy on the user's VPS.
set -euo pipefail

MODULE="github.com/TDS-SO/caddy-ja4"
CADDY_VERSION="${CADDY_VERSION:-v2.9.1}"
OUT="${OUT:-dist}"

command -v xcaddy >/dev/null || {
    echo "installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
}

mkdir -p "$OUT"
for arch in amd64 arm64; do
    echo ">> building linux/$arch"
    GOOS=linux GOARCH="$arch" xcaddy build "$CADDY_VERSION" \
        --with "${MODULE}=." \
        --output "${OUT}/caddy-linux-${arch}"
done

( cd "$OUT" && sha256sum caddy-linux-* > caddy-ja4.sha256 )
echo ">> done:"
ls -la "$OUT"
cat "${OUT}/caddy-ja4.sha256"
