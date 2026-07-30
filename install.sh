#!/bin/sh
set -eu

repo="${SSM_REPO:-Cd1s/ssm}"
prefix="${SSM_PREFIX:-/usr/local/bin}"
config_dir="${SSM_CONFIG_DIR:-$HOME/.config/ssm}"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

case "$os" in
  linux|darwin) ;;
  mingw*|msys*|cygwin*) os=windows ;;
  *) echo "unsupported os: $os" >&2; exit 1 ;;
esac

ext=""
[ "$os" = "windows" ] && ext=".exe"
asset="ssm-$os-$arch$ext"
latest_url="https://github.com/$repo/releases/latest"
url="https://github.com/$repo/releases/latest/download/$asset"
checksums_url="https://github.com/$repo/releases/latest/download/checksums.txt"
provenance="$asset.sigstore.json"
provenance_url="https://github.com/$repo/releases/latest/download/$provenance"

tmp="$(mktemp)"
checksums="$(mktemp)"
bundle="$(mktemp)"
trap 'rm -f "$tmp" "$checksums" "$bundle"' EXIT
resolved_release_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$latest_url")"
release_tag="${resolved_release_url#*/releases/tag/}"
release_tag="${release_tag%%[/?#]*}"
if ! printf '%s\n' "$release_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "resolved release identity is invalid" >&2
  exit 1
fi
curl -fsSL "$url" -o "$tmp"
curl -fsSL "$checksums_url" -o "$checksums"
curl -fsSL "$provenance_url" -o "$bundle"
expected="$(awk -v asset="$asset" '$2 == asset { print $1 }' "$checksums")"
if [ -z "$expected" ]; then
  echo "checksum for $asset not found" >&2
  exit 1
fi
case "$expected" in
  *'
'*)
    echo "multiple checksums found for $asset" >&2
    exit 1
    ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp" | awk '{ print $1 }')"
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi
if [ "$actual" != "$expected" ]; then
  echo "checksum mismatch for $asset" >&2
  exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI with attestation verification is required" >&2
  exit 1
fi
verify_identity() {
  identity="$1"
  verified="$(gh attestation verify "$tmp" \
    --bundle "$bundle" \
    --repo Cd1s/ssm \
    --cert-identity "$identity" \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    --predicate-type https://slsa.dev/provenance/v1 \
    --deny-self-hosted-runners \
    --format json \
    --jq "[.[] | .verificationResult | select(
      (.statement.subject | length) == 1 and
      .statement.subject[0].name == \"$asset\" and
      (.statement.subject[0].digest | keys) == [\"sha256\"] and
      ([.verifiedTimestamps[].timestamp] |
        (length > 0 and all(.[]; . >= \"2026-07-30T00:00:00Z\")))
    )] | length == 1")"
  [ "$verified" = "true" ]
}
tag_identity="https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/$release_tag"
main_identity="https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/heads/main"
if ! verify_identity "$tag_identity" 2>/dev/null && ! verify_identity "$main_identity"; then
  echo "release provenance does not match the reviewed identity set" >&2
  exit 1
fi
chmod 755 "$tmp"
mkdir -p "$prefix" "$config_dir"
staged="$(mktemp "$prefix/.ssm.XXXXXX.new")"
trap 'rm -f "$tmp" "$checksums" "$bundle" "$staged"' EXIT
install -m 755 "$tmp" "$staged"
mv -f "$staged" "$prefix/ssm"
staged=""
ln -sfn "$prefix/ssm" "$prefix/sshctl"
chmod 700 "$config_dir"
printf '%s\n' "$repo" > "$config_dir/update_repo"
chmod 600 "$config_dir/update_repo"
if [ ! -s "$config_dir/settings.json" ]; then
  cat > "$config_dir/settings.json" <<EOF
{"password_cache":"always","vim_keys":true,"auto_update":true,"auto_sync":true,"update_repo":"$repo"}
EOF
  chmod 600 "$config_dir/settings.json"
fi
"$prefix/ssm" --version
echo "installed $prefix/ssm and $prefix/sshctl"
