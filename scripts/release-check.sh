#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

go_version="$(grep -m1 '^go ' go.mod | awk '{print $2}')"
export GOTOOLCHAIN="go$go_version"

./scripts/check.sh all

version_line="$(grep -n 'version  *= "' cmd/ssm/main.go | head -2 | head -1)"
version="$(printf '%s\n' "$version_line" | sed -E 's/.*version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"
if [ -z "$version" ]; then
	echo "could not determine source version" >&2
	exit 1
fi

asset_dir="$(mktemp -d)"
trap 'rm -rf "$asset_dir"' EXIT

for goos in linux darwin windows; do
	for goarch in amd64 arm64; do
		asset="ssm-${goos}-${goarch}"
		if [ "$goos" = windows ]; then
			asset+=".exe"
		fi
		GOOS="$goos" GOARCH="$goarch" go build \
			-buildvcs=false \
			-ldflags="-s -w -X main.version=$version" \
			-o "$asset_dir/$asset" ./cmd/ssm
	done
done

sh -n install.sh

echo "TODO: release builtins (source-version, release-notes, release-checksums, release-provenance) are still run by 'go run ./cmd/verify release'"
go run ./cmd/verify release
