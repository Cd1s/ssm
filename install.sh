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
url="https://github.com/$repo/releases/latest/download/$asset"
checksums_url="https://github.com/$repo/releases/latest/download/checksums.txt"

tmp="$(mktemp)"
checksums="$(mktemp)"
trap 'rm -f "$tmp" "$checksums"' EXIT
curl -fsSL "$url" -o "$tmp"
curl -fsSL "$checksums_url" -o "$checksums"
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
chmod 755 "$tmp"
mkdir -p "$prefix" "$config_dir"
install -m 755 "$tmp" "$prefix/ssm"
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
