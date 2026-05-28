#!/bin/sh
set -eu

repo="${SSM_REPO:-}"
if [ -z "$repo" ]; then
  echo "set SSM_REPO=owner/repo" >&2
  exit 2
fi
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

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp"
chmod 755 "$tmp"
mkdir -p "$prefix"
install -m 755 "$tmp" "$prefix/ssm"
ln -sfn "$prefix/ssm" "$prefix/sshctl"
mkdir -p "$config_dir"
if [ ! -s "$config_dir/settings.json" ]; then
  cat > "$config_dir/settings.json" <<EOF
{"password_cache":"always","vim_keys":true,"auto_update":true,"auto_sync":true,"update_repo":"$repo"}
EOF
  chmod 600 "$config_dir/settings.json"
fi
"$prefix/ssm" --version
echo "installed $prefix/ssm and $prefix/sshctl"
