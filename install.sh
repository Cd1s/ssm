#!/bin/sh
set -eu

repo="${SSM_REPO:-Cd1s/ssm}"
requested_tag="${SSM_RELEASE_TAG:-}"
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

metadata_path="releases/latest"
if [ -n "$requested_tag" ]; then
  if ! printf '%s\n' "$requested_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "SSM_RELEASE_TAG must be one exact stable tag such as v2.0.0" >&2
    exit 1
  fi
  metadata_path="releases/tags/$requested_tag"
fi

ext=""
[ "$os" = "windows" ] && ext=".exe"
asset="ssm-$os-$arch$ext"
provenance="$asset.sigstore.json"
metadata_limit=1048576
checksums_limit=16384
bundle_limit=1048576
binary_limit=67108864

tmp="$(mktemp)"
checksums="$(mktemp)"
bundle_dir="$(mktemp -d)"
bundle="$bundle_dir/attestation.json"
release_metadata="$(mktemp)"
curl_status="$(mktemp)"
staged=""
cleanup() {
  rm -f "$tmp" "$checksums" "$bundle" "$release_metadata" "$curl_status"
  if [ -n "$staged" ]; then
    rm -f "$staged"
  fi
  rmdir "$bundle_dir" 2>/dev/null || :
}
trap cleanup EXIT
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for exact release manifest validation" >&2
  exit 1
fi
if ! command -v head >/dev/null 2>&1; then
  echo "head is required for bounded release downloads" >&2
  exit 1
fi
download_bounded() {
  download_url="$1"
  download_output="$2"
  download_limit="$3"
  download_description="$4"
  : > "$curl_status"
  if ! {
    if curl -fsSL --max-filesize "$download_limit" "$download_url"; then
      printf '0\n' > "$curl_status"
    else
      printf '%s\n' "$?" > "$curl_status"
    fi
  } | head -c "$((download_limit + 1))" > "$download_output"; then
    echo "failed to download bounded $download_description" >&2
    return 1
  fi
  download_size="$(wc -c < "$download_output" | tr -d '[:space:]')"
  if [ "$download_size" -gt "$download_limit" ]; then
    echo "$download_description exceeds $download_limit-byte limit" >&2
    return 1
  fi
  download_curl_exit=""
  if ! IFS= read -r download_curl_exit < "$curl_status"; then
    echo "failed to download bounded $download_description" >&2
    return 1
  fi
  case "$download_curl_exit" in
    ''|*[!0-9]*)
      echo "failed to download bounded $download_description" >&2
      return 1
      ;;
  esac
  if [ "$download_curl_exit" -ne 0 ]; then
    echo "failed to download bounded $download_description" >&2
    return 1
  fi
}
download_bounded \
  "https://api.github.com/repos/$repo/$metadata_path" \
  "$release_metadata" \
  "$metadata_limit" \
  "release metadata"
expected_assets='[
  "ssm-linux-amd64",
  "ssm-linux-arm64",
  "ssm-darwin-amd64",
  "ssm-darwin-arm64",
  "ssm-windows-amd64.exe",
  "ssm-windows-arm64.exe",
  "ssm-linux-amd64.sigstore.json",
  "ssm-linux-arm64.sigstore.json",
  "ssm-darwin-amd64.sigstore.json",
  "ssm-darwin-arm64.sigstore.json",
  "ssm-windows-amd64.exe.sigstore.json",
  "ssm-windows-arm64.exe.sigstore.json",
  "install.sh",
  "checksums.txt"
]'
if ! jq -e --argjson expected "$expected_assets" '
  type == "object" and
  (.tag_name | type == "string") and
  (.assets | type == "array") and
  (.assets | all(.[]; type == "object" and (.name | type == "string"))) and
  (([.assets[].name] | length) == ($expected | length)) and
  (([.assets[].name] | sort) == ($expected | sort))
' "$release_metadata" >/dev/null; then
  echo "latest release does not contain the exact supported 14-asset manifest" >&2
  exit 1
fi
release_tag="$(jq -er '.tag_name' "$release_metadata")"
if ! printf '%s\n' "$release_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "resolved release identity is invalid" >&2
  exit 1
fi
if [ -n "$requested_tag" ] && [ "$release_tag" != "$requested_tag" ]; then
  echo "resolved release identity does not match requested exact tag" >&2
  exit 1
fi
release_version="${release_tag#v}"
if [ -e "$prefix/ssm" ] || [ -L "$prefix/ssm" ]; then
  if [ ! -f "$prefix/ssm" ] || [ ! -x "$prefix/ssm" ]; then
    echo "existing SSM installation is not an executable regular file" >&2
    exit 1
  fi
  installed_output=""
  if ! installed_output="$("$prefix/ssm" --version 2>/dev/null)"; then
    echo "existing SSM version cannot be read safely" >&2
    exit 1
  fi
  installed_version="$(printf '%s\n' "$installed_output" | awk '$1 == "ssm" && NF == 2 && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ { print $2 }')"
  case "$installed_version" in
    ''|*'
'*)
      echo "existing SSM version is not one exact stable version" >&2
      exit 1
      ;;
  esac
  if ! awk -v current="$installed_version" -v selected="$release_version" 'BEGIN {
    split(current, c, "."); split(selected, s, ".")
    if (s[1] != c[1]) exit 1
    for (i = 1; i <= 3; i++) {
      if ((s[i] + 0) < (c[i] + 0)) exit 1
      if ((s[i] + 0) > (c[i] + 0)) exit 0
    }
    exit 0
  }'; then
    echo "existing SSM can be replaced only by the same or a newer release in its installed major; use ssm update --major --yes for migration" >&2
    exit 1
  fi
fi
url="https://github.com/$repo/releases/download/$release_tag/$asset"
checksums_url="https://github.com/$repo/releases/download/$release_tag/checksums.txt"
provenance_url="https://github.com/$repo/releases/download/$release_tag/$provenance"
download_bounded "$url" "$tmp" "$binary_limit" "$asset"
download_bounded "$checksums_url" "$checksums" "$checksums_limit" "checksums.txt"
download_bounded "$provenance_url" "$bundle" "$bundle_limit" "$provenance"
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
if ! verify_identity "$tag_identity"; then
  echo "release provenance does not match the selected release tag identity" >&2
  exit 1
fi
chmod 755 "$tmp"
mkdir -p "$prefix" "$config_dir"
staged="$(mktemp "$prefix/.ssm.new.XXXXXX")"
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
