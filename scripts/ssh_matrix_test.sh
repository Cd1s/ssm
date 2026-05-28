#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN="$ROOT/ssm-it"
TMP=$(mktemp -d)

cleanup() {
  if [ -f "$TMP/sshd.pid" ]; then
    kill "$(cat "$TMP/sshd.pid")" 2>/dev/null || true
  fi
  rm -rf "$TMP" "$BIN"
}
trap cleanup EXIT

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

require ssh
require ssh-keygen

SSHD=${SSHD:-$(command -v sshd 2>/dev/null || true)}
if [ -z "$SSHD" ] && [ -x /usr/sbin/sshd ]; then
  SSHD=/usr/sbin/sshd
fi
if [ -z "$SSHD" ]; then
  echo "missing required command: sshd" >&2
  exit 2
fi

go build -o "$BIN" ./cmd/ssm

ssh-keygen -q -t ed25519 -N '' -f "$TMP/client_key"
ssh-keygen -q -t ed25519 -N '' -f "$TMP/host_key"
cp "$TMP/client_key.pub" "$TMP/authorized_keys"

find_free_port() {
  for port in $(seq 22222 22322); do
    if ! (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then
      printf '%s\n' "$port"
      return 0
    fi
  done
  return 1
}

PORT=${SSM_TEST_SSH_PORT:-$(find_free_port)}
if [ -z "$PORT" ]; then
  echo "no free localhost SSH test port found" >&2
  exit 2
fi
cat > "$TMP/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $TMP/host_key
PidFile $TMP/sshd.pid
AuthorizedKeysFile $TMP/authorized_keys
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin yes
UsePAM no
StrictModes no
LogLevel ERROR
PrintMotd no
PrintLastLog no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

"$SSHD" -f "$TMP/sshd_config" -E "$TMP/sshd.log"
for _ in $(seq 1 50); do
  if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile="$TMP/smoke_known_hosts" -i "$TMP/client_key" -p "$PORT" root@127.0.0.1 true 2>/dev/null; then
    break
  fi
  sleep 0.1
done

mkdir -p "$TMP/home/.config/ssm"
printf 'test-master\n' > "$TMP/home/.config/ssm/master.pass"
chmod 600 "$TMP/home/.config/ssm/master.pass"

key_json=$(awk 'BEGIN{printf ""}{gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); printf "%s\\n", $0}' "$TMP/client_key")
cat > "$TMP/import.json" <<EOF
[{"alias":"local","host":"127.0.0.1","port":$PORT,"user":"root","auth_type":"key","private_key":"$key_json"}]
EOF

HOME="$TMP/home" SSM_UPDATE_REPO=off "$BIN" --master-pass-file "$TMP/home/.config/ssm/master.pass" import-json "$TMP/import.json" >/dev/null
ln -s "$BIN" "$TMP/sshctl"

run_sshctl() {
  HOME="$TMP/home" SSM_UPDATE_REPO=off "$TMP/sshctl" "$@"
}

expect_output() {
  local name=$1
  local want=$2
  shift 2
  local got
  got=$(run_sshctl run local "$@")
  if [ "$got" != "$want" ]; then
    echo "$name: got [$got], want [$want]" >&2
    exit 1
  fi
  echo "ok $name"
}

expect_output simple "simple" "printf simple"
expect_output single_quote "single quoted" "printf %s 'single quoted'"
expect_output double_quote "double quoted" 'printf "%s" "double quoted"'
expect_output nested_shell "nested:value" "SSM_MATRIX_VALUE=value sh -lc 'printf nested:\$SSM_MATRIX_VALUE'"
expect_output pipe_redirect "6" "printf abcdef | wc -c | tr -d ' '"

stdin_got=$(printf 'stdin-data' | run_sshctl run local "cat")
if [ "$stdin_got" != "stdin-data" ]; then
  echo "stdin: got [$stdin_got]" >&2
  exit 1
fi
echo "ok stdin"

set +e
run_sshctl run local "exit 7" >/dev/null
rc=$?
set -e
if [ "$rc" != "7" ]; then
  echo "exit_code: got [$rc], want [7]" >&2
  exit 1
fi
echo "ok exit_code"

expect_output long_running "done" "sleep 1; printf done"

pid_file="$TMP/persistent.pid"
run_sshctl run local "nohup sh -c 'sleep 3' >/dev/null 2>&1 & echo \$! > '$pid_file'"
if ! run_sshctl run local "test -s '$pid_file'"; then
  echo "persistent_script: pid file missing" >&2
  exit 1
fi
echo "ok persistent_script"

printf 'payload' > "$TMP/payload.txt"
run_sshctl put local "$TMP/payload.txt" "$TMP/uploaded.txt"
expect_output put_upload "payload" "cat '$TMP/uploaded.txt'"

set +e
missing_auth=$(HOME="$TMP/home" SSM_UPDATE_REPO=off "$BIN" --master-pass-file "$TMP/home/.config/ssm/master.pass" exec missing true 2>&1)
rc=$?
set -e
if [ "$rc" = "0" ] || ! printf '%s' "$missing_auth" | grep -q 'not found'; then
  echo "missing_connection: rc=$rc output=[$missing_auth]" >&2
  exit 1
fi
echo "ok missing_connection"

if [ ! -s "$TMP/home/.ssh/known_hosts" ]; then
  echo "known_hosts: no host key saved" >&2
  exit 1
fi
echo "ok known_hosts"

echo "ssh matrix passed"
