#!/bin/sh
# Builds the binaries used by the real client tests into ${REALCLIENT_BIN:-./bin}:
#
#   sing-box         patched server and sing-box client, from the SING_BOX_DIR working tree
#   sing-box-legacy  the same sing-box at SING_BOX_LEGACY_REF, before the patch
#   mihomo           Mihomo MIHOMO_VERSION
#   anytls-client    anytls-go ANYTLS_GO_VERSION reference client
#
# SING_BOX_LEGACY_REF must name a commit that still uses github.com/anytls/sing-anytls
# for the inbound; after the patch is committed, set it to the commit before.
set -eu

cd "$(dirname "$0")"
BIN=${REALCLIENT_BIN:-$(pwd)/bin}
SING_BOX_DIR=${SING_BOX_DIR:-$(cd ../../.. && pwd)/sing-box_mod}
SING_BOX_LEGACY_REF=${SING_BOX_LEGACY_REF:-HEAD}
MIHOMO_VERSION=${MIHOMO_VERSION:-v1.19.32}
ANYTLS_GO_VERSION=${ANYTLS_GO_VERSION:-v0.0.13}

mkdir -p "$BIN"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

module_dir() {
	(cd "$WORK" && go mod download -json "$1" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')
}

copy_module() {
	dir=$(module_dir "$1")
	[ -n "$dir" ] || { echo "cannot download $1" >&2; exit 1; }
	cp -R "$dir" "$2"
	chmod -R u+w "$2"
}

echo "sing-box: $SING_BOX_DIR (working tree)"
(cd "$SING_BOX_DIR" && go build -trimpath -o "$BIN/sing-box" ./cmd/sing-box)

echo "sing-box-legacy: $SING_BOX_DIR at $SING_BOX_LEGACY_REF"
mkdir "$WORK/legacy"
git -C "$SING_BOX_DIR" archive "$SING_BOX_LEGACY_REF" | tar -x -C "$WORK/legacy"
if grep -q 'github.com/sagernet/sing-anytls' "$WORK/legacy/go.mod"; then
	echo "$SING_BOX_LEGACY_REF already uses the patched library; set SING_BOX_LEGACY_REF" >&2
	exit 1
fi
(cd "$WORK/legacy" && go build -trimpath -o "$BIN/sing-box-legacy" ./cmd/sing-box)

echo "mihomo: $MIHOMO_VERSION"
# Mihomo's go.mod has replace directives, which go install does not allow.
copy_module "github.com/metacubex/mihomo@$MIHOMO_VERSION" "$WORK/mihomo"
(cd "$WORK/mihomo" && go build -trimpath \
	-ldflags "-X github.com/metacubex/mihomo/constant.Version=${MIHOMO_VERSION#v}" \
	-o "$BIN/mihomo" .)

echo "anytls-client: anytls-go $ANYTLS_GO_VERSION"
# anytls-go declares its module path as "anytls", so it cannot be installed by path.
copy_module "github.com/anytls/anytls-go@$ANYTLS_GO_VERSION" "$WORK/anytls-go"
(cd "$WORK/anytls-go" && go build -trimpath -o "$BIN/anytls-client" ./cmd/client)

echo "binaries in $BIN"
