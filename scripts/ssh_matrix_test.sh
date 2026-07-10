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
require script

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
TEST_USER=${SSM_TEST_SSH_USER:-$(id -un)}
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
ready=0
for _ in $(seq 1 50); do
  if ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile="$TMP/smoke_known_hosts" -i "$TMP/client_key" -p "$PORT" "$TEST_USER"@127.0.0.1 true 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [ "$ready" != 1 ]; then
  echo "temporary sshd did not accept test user $TEST_USER" >&2
  cat "$TMP/sshd.log" >&2
  exit 1
fi

mkdir -p "$TMP/home/.config/ssm"
printf 'test-master\n' > "$TMP/home/.config/ssm/master.pass"
chmod 600 "$TMP/home/.config/ssm/master.pass"

host_created=$(HOME="$TMP/home" SSM_UPDATE_REPO=off "$BIN" --master-pass-file "$TMP/home/.config/ssm/master.pass" \
  host upsert local --host 127.0.0.1 --port "$PORT" --user "$TEST_USER" --key-file "$TMP/client_key" --json)
printf '%s' "$host_created" | grep -q '"action": "created"' || { echo "host create: $host_created" >&2; exit 1; }
ln -s "$BIN" "$TMP/sshctl"

run_sshctl() {
  HOME="$TMP/home" SSM_UPDATE_REPO=off "$TMP/sshctl" "$@"
}

host_unchanged=$(run_sshctl host upsert local --host 127.0.0.1 --port "$PORT" --user "$TEST_USER" --key-file "$TMP/client_key" --json)
printf '%s' "$host_unchanged" | grep -q '"action": "unchanged"' || { echo "host upsert retry: $host_unchanged" >&2; exit 1; }
printf '%s' "$host_unchanged" | grep -q '"sync_pending": true' || { echo "host sync state: $host_unchanged" >&2; exit 1; }
host_updated=$(run_sshctl host update local --group matrix --json)
printf '%s' "$host_updated" | grep -q '"action": "updated"' || { echo "host update: $host_updated" >&2; exit 1; }
host_show=$(run_sshctl host show local --json)
printf '%s' "$host_show" | grep -q '"auth": "key"' || { echo "host show: $host_show" >&2; exit 1; }
echo "ok host_crud"

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

# Multi-arg mode shell-quotes each argv (agent-friendly bash -c).
expect_output multi_arg_bash_c "hi there" bash -c 'printf %s "hi there"'
expect_output multi_arg_spaces "hello world" printf %s "hello world"
expect_output explicit_argv "hello world" --argv printf %s "hello world"

argv_plan=$(run_sshctl plan local --json --argv hostname)
printf '%s' "$argv_plan" | grep -q "'hostname'" || { echo "argv plan: $argv_plan" >&2; exit 1; }
echo "ok argv_plan"

# SSH-like shorthand: sshctl <alias> <command...> (no "run" keyword).
shorthand_got=$(run_sshctl local printf %s shorthand)
if [ "$shorthand_got" != "shorthand" ]; then
  echo "shorthand_run: got [$shorthand_got]" >&2
  exit 1
fi
echo "ok shorthand_run"

# --raw keeps classic OpenSSH space-join (breaks spaces in args on purpose).
raw_got=$(run_sshctl run local --raw printf %s "raw-ok")
if [ "$raw_got" != "raw-ok" ]; then
  echo "raw: got [$raw_got]" >&2
  exit 1
fi
echo "ok raw"

# -s reads remote script from stdin (heredoc / agent-safe, no quote hell).
script_got=$(run_sshctl run local -s <<'EOF'
printf %s "script-ok"
EOF
)
if [ "$script_got" != "script-ok" ]; then
  echo "script_stdin: got [$script_got]" >&2
  exit 1
fi
echo "ok script_stdin"

# -f normalizes BOM/CRLF, detects bash, exports secrets, and preserves args.
printf '\357\273\277#!/usr/bin/env bash\r\nprintf "%%s|%%s" "$1" "$TOKEN"\r\n' > "$TMP/remote_script.sh"
printf %s "token with 'single' and spaces" > "$TMP/token"
file_got=$(run_sshctl run local --secret TOKEN=@"$TMP/token" --shell auto -f "$TMP/remote_script.sh" -- "file arg")
if [ "$file_got" != "file arg|token with 'single' and spaces" ]; then
  echo "script_file: got [$file_got]" >&2
  exit 1
fi
echo "ok script_file"

script_plan=$(run_sshctl plan local --json --shell auto -f "$TMP/remote_script.sh" -- "file arg")
printf '%s' "$script_plan" | grep -q '"interpreter": "bash"' || { echo "script plan: $script_plan" >&2; exit 1; }
printf '%s' "$script_plan" | grep -q '"script_sha256"' || { echo "script plan digest: $script_plan" >&2; exit 1; }
if printf '%s' "$script_plan" | grep -Fq 'printf "%s|%s"'; then
  echo "script plan leaked body: $script_plan" >&2
  exit 1
fi
echo "ok script_plan"

printf '#!/bin/sh\nexit 9\n' > "$TMP/fail_script.sh"
set +e
script_fail=$(run_sshctl run local --json -f "$TMP/fail_script.sh")
script_fail_rc=$?
set -e
if [ "$script_fail_rc" != "9" ] || ! printf '%s' "$script_fail" | grep -q '"error": "remote_script_failed"'; then
  echo "script failure: rc=$script_fail_rc out=[$script_fail]" >&2
  exit 1
fi
echo "ok script_failure_code"

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

# put creates nested remote parents
printf 'nested' > "$TMP/nested.txt"
run_sshctl put local "$TMP/nested.txt" "$TMP/nested/dir/file.txt"
expect_output put_mkdir "nested" "cat '$TMP/nested/dir/file.txt'"

# get downloads to local path (creates local parents)
mkdir -p "$TMP/get-out"
run_sshctl get local "$TMP/uploaded.txt" "$TMP/get-out/deep/down.txt"
if [ "$(cat "$TMP/get-out/deep/down.txt")" != "payload" ]; then
  echo "get: unexpected content" >&2
  exit 1
fi
echo "ok get_download"

# env assign multi-arg
expect_output env_assign "bar" FOO=bar printenv FOO

# did-you-mean for typos
set +e
suggest_out=$(run_sshctl run locall true 2>&1)
suggest_rc=$?
set -e
if [ "$suggest_rc" = "0" ] || ! printf '%s' "$suggest_out" | grep -qi 'Did you mean'; then
  echo "suggest: rc=$suggest_rc out=[$suggest_out]" >&2
  exit 1
fi
if ! printf '%s' "$suggest_out" | grep -q 'error=alias_not_found'; then
  echo "suggest: missing structured error: [$suggest_out]" >&2
  exit 1
fi
echo "ok did_you_mean"

# check probe
check_out=$(run_sshctl check local)
printf '%s\n' "$check_out" | grep -q 'ok=1' || { echo "check: $check_out" >&2; exit 1; }
printf '%s\n' "$check_out" | grep -q 'hostname=' || { echo "check missing hostname: $check_out" >&2; exit 1; }
echo "ok check"

check_json=$(run_sshctl check local --json)
printf '%s' "$check_json" | grep -q '"ok": true' || { echo "check json: $check_json" >&2; exit 1; }
echo "ok check_json"

cat > "$TMP/run_shell.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export HOME="$TMP/home"
export SSM_UPDATE_REPO=off
exec "$TMP/sshctl" shell local
EOF
chmod 700 "$TMP/run_shell.sh"
printf 'exit\r' | script -qfec "$TMP/run_shell.sh" /dev/null >/dev/null
echo "ok shell"

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
