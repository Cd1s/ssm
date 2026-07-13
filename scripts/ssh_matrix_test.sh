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
printf '%s' "$host_created" | grep -q '"applied": true' || { echo "host candidate apply: $host_created" >&2; exit 1; }
printf '%s' "$host_created" | grep -q '"transaction_id": "tx_[0-9a-f]\{32\}"' || { echo "host transaction id: $host_created" >&2; exit 1; }
ln -s "$BIN" "$TMP/sshctl"

run_sshctl() {
  HOME="$TMP/home" SSM_UPDATE_REPO=off "$TMP/sshctl" "$@"
}

pending_status=$(run_sshctl --offline --json status)
printf '%s' "$pending_status" | grep -q '"pending_changes": true' || { echo "pending status: $pending_status" >&2; exit 1; }
printf '%s' "$pending_status" | grep -q '"pending_mutations": \[' || { echo "pending mutations: $pending_status" >&2; exit 1; }
printf '%s' "$pending_status" | grep -q '"alias": "local"' || { echo "pending alias: $pending_status" >&2; exit 1; }
if printf '%s' "$pending_status" | grep -Fq 'test-master'; then
  echo "pending status leaked secret" >&2
  exit 1
fi
echo "ok transaction_status"

set +e
unknown_key=$(run_sshctl run local --json true)
unknown_key_rc=$?
set -e
if [ "$unknown_key_rc" != "255" ] || ! printf '%s' "$unknown_key" | grep -q '"error": "host_key_unknown"'; then
  echo "first-use host key rejection: rc=$unknown_key_rc out=[$unknown_key]" >&2
  exit 1
fi
if [ -e "$TMP/home/.ssh/known_hosts" ]; then
  echo "first-use rejection unexpectedly created known_hosts" >&2
  exit 1
fi

new_key=$(run_sshctl host-key inspect local --json)
printf '%s' "$new_key" | grep -q '"classification": "new"' || { echo "new host key classification: $new_key" >&2; exit 1; }
printf '%s' "$new_key" | grep -q '"address": "127.0.0.1:' || { echo "new host key address: $new_key" >&2; exit 1; }
printf '%s' "$new_key" | grep -q '"port": ' || { echo "new host key port: $new_key" >&2; exit 1; }
observed_fingerprint=$(printf '%s\n' "$new_key" | sed -n 's/.*"observed_fingerprint": "\([^"]*\)".*/\1/p')
if [ -z "$observed_fingerprint" ]; then
  echo "new host key missing observed fingerprint: $new_key" >&2
  exit 1
fi

set +e
wrong_new_key=$(run_sshctl host-key accept local --fingerprint SHA256:not-the-observed-key --yes --json)
wrong_new_key_rc=$?
set -e
if [ "$wrong_new_key_rc" = "0" ] || [ -e "$TMP/home/.ssh/known_hosts" ]; then
  echo "new host wrong fingerprint mutated trust: rc=$wrong_new_key_rc out=[$wrong_new_key]" >&2
  exit 1
fi
printf '%s' "$wrong_new_key" | grep -q '"error": "fingerprint_mismatch"' || { echo "new host wrong fingerprint class: $wrong_new_key" >&2; exit 1; }

accepted_new_key=$(run_sshctl host-key accept local --fingerprint "$observed_fingerprint" --yes --json)
printf '%s' "$accepted_new_key" | grep -q '"accepted": true' || { echo "new host exact acceptance: $accepted_new_key" >&2; exit 1; }
echo "ok host_key_first_use_workflow"

host_unchanged=$(run_sshctl host upsert local --host 127.0.0.1 --port "$PORT" --user "$TEST_USER" --key-file "$TMP/client_key" --json)
printf '%s' "$host_unchanged" | grep -q '"action": "unchanged"' || { echo "host upsert retry: $host_unchanged" >&2; exit 1; }
printf '%s' "$host_unchanged" | grep -q '"sync_pending": true' || { echo "host sync state: $host_unchanged" >&2; exit 1; }
host_updated=$(run_sshctl host update local --group matrix --verify --json)
printf '%s' "$host_updated" | grep -q '"action": "updated"' || { echo "host update: $host_updated" >&2; exit 1; }
printf '%s' "$host_updated" | grep -q '"verification"' || { echo "host candidate verification: $host_updated" >&2; exit 1; }
host_show=$(run_sshctl host show local --json)
printf '%s' "$host_show" | grep -q '"auth": "key"' || { echo "host show: $host_show" >&2; exit 1; }
echo "ok host_crud"

vault_before=$(sha256sum "$TMP/home/.config/ssm/connections.enc" | awk '{print $1}')
BAD_PORT=$(find_free_port)
set +e
host_rejected=$(run_sshctl host update local --port "$BAD_PORT" --verify --json)
host_rejected_rc=$?
set -e
vault_after=$(sha256sum "$TMP/home/.config/ssm/connections.enc" | awk '{print $1}')
if [ "$host_rejected_rc" = "0" ] || [ "$vault_before" != "$vault_after" ]; then
  echo "host candidate rollback: rc=$host_rejected_rc before=$vault_before after=$vault_after out=[$host_rejected]" >&2
  exit 1
fi
printf '%s' "$host_rejected" | grep -q '"error": "verification_failed"' || { echo "host candidate error: $host_rejected" >&2; exit 1; }
printf '%s' "$host_rejected" | grep -q '"applied": false' || { echo "host candidate applied unexpectedly: $host_rejected" >&2; exit 1; }
echo "ok host_candidate_transaction"

set +e
missing_alias=$(run_sshctl run --json)
missing_alias_rc=$?
set -e
if [ "$missing_alias_rc" != "2" ] || ! printf '%s' "$missing_alias" | grep -q '"error": "missing_alias"'; then
  echo "missing alias json: rc=$missing_alias_rc out=[$missing_alias]" >&2
  exit 1
fi
echo "ok missing_alias_json"

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

cat > "$TMP/request.json" <<EOF
{
  "version": 1,
  "op": "run",
  "alias": "local",
  "argv": ["printf", "%s", "request ' exact with spaces"]
}
EOF
request_out=$(run_sshctl request --file "$TMP/request.json")
printf '%s' "$request_out" | grep -q '"mode": "argv"' || { echo "request mode: $request_out" >&2; exit 1; }
printf '%s' "$request_out" | grep -q "request ' exact with spaces" || { echo "request argv: $request_out" >&2; exit 1; }
echo "ok typed_request_argv"

cat > "$TMP/script_request.json" <<EOF
{
  "version": 1,
  "op": "run",
  "alias": "local",
  "script_file": "$TMP/remote_script.sh",
  "script_args": ["request file arg"],
  "shell": "auto",
  "secret_files": {"TOKEN": "$TMP/token"}
}
EOF
script_request_out=$(run_sshctl request --file "$TMP/script_request.json")
printf '%s' "$script_request_out" | grep -q '"preflight": "passed"' || { echo "request preflight: $script_request_out" >&2; exit 1; }
printf '%s' "$script_request_out" | grep -q "request file arg|token with 'single' and spaces" || { echo "request script: $script_request_out" >&2; exit 1; }
echo "ok typed_request_script"

printf 'printf touched > %q\nif then\n' "$TMP/preflight-touched" > "$TMP/invalid_script.sh"
set +e
syntax_fail=$(run_sshctl run local --json --preflight -f "$TMP/invalid_script.sh")
syntax_fail_rc=$?
set -e
if [ "$syntax_fail_rc" = "0" ] || [ -e "$TMP/preflight-touched" ]; then
  echo "script preflight side effect: rc=$syntax_fail_rc out=[$syntax_fail]" >&2
  exit 1
fi
printf '%s' "$syntax_fail" | grep -q '"error": "script_syntax_error"' || { echo "script preflight class: $syntax_fail" >&2; exit 1; }
echo "ok script_syntax_preflight"

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

host_key=$(run_sshctl host-key inspect local --json)
printf '%s' "$host_key" | grep -q '"classification": "trusted"' || { echo "host key inspect: $host_key" >&2; exit 1; }

old_sshd_pid=$(cat "$TMP/sshd.pid")
kill "$old_sshd_pid"
for _ in $(seq 1 50); do
  if ! kill -0 "$old_sshd_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
rm -f "$TMP/sshd.pid"
ssh-keygen -q -t ed25519 -N '' -f "$TMP/host_key_changed"
sed -i "s|^HostKey .*|HostKey $TMP/host_key_changed|" "$TMP/sshd_config"
"$SSHD" -f "$TMP/sshd_config" -E "$TMP/sshd.log"

set +e
changed_key_run=$(run_sshctl run local --json true)
changed_key_run_rc=$?
set -e
if [ "$changed_key_run_rc" != "255" ] || ! printf '%s' "$changed_key_run" | grep -q '"error": "host_key_mismatch"'; then
  echo "changed host key rejection: rc=$changed_key_run_rc out=[$changed_key_run]" >&2
  exit 1
fi

changed_key=$(run_sshctl host-key inspect local --json)
printf '%s' "$changed_key" | grep -q '"classification": "mismatch"' || { echo "changed host key classification: $changed_key" >&2; exit 1; }
printf '%s' "$changed_key" | grep -q '"known_fingerprints":' || { echo "changed host key known fingerprints: $changed_key" >&2; exit 1; }
changed_fingerprint=$(printf '%s\n' "$changed_key" | sed -n 's/.*"observed_fingerprint": "\([^"]*\)".*/\1/p')
if [ -z "$changed_fingerprint" ]; then
  echo "changed host key missing observed fingerprint: $changed_key" >&2
  exit 1
fi

known_before=$(sha256sum "$TMP/home/.ssh/known_hosts" | awk '{print $1}')
set +e
wrong_key=$(run_sshctl host-key accept local --fingerprint SHA256:not-the-observed-key --yes --json)
wrong_key_rc=$?
set -e
known_after=$(sha256sum "$TMP/home/.ssh/known_hosts" | awk '{print $1}')
if [ "$wrong_key_rc" = "0" ] || [ "$known_before" != "$known_after" ]; then
  echo "host key fingerprint guard: rc=$wrong_key_rc before=$known_before after=$known_after out=[$wrong_key]" >&2
  exit 1
fi
printf '%s' "$wrong_key" | grep -q '"error": "fingerprint_mismatch"' || { echo "host key mismatch class: $wrong_key" >&2; exit 1; }
echo "ok host_key_fingerprint_guard"

accepted_changed_key=$(run_sshctl host-key accept local --fingerprint "$changed_fingerprint" --yes --json)
printf '%s' "$accepted_changed_key" | grep -q '"accepted": true' || { echo "changed host key exact acceptance: $accepted_changed_key" >&2; exit 1; }
run_sshctl run local true
echo "ok host_key_changed_workflow"

cat > "$TMP/import.json" <<EOF
[{"alias":"danger","host":"127.0.0.1","port":$PORT,"user":"$TEST_USER","private_key_path":"$TMP/client_key"}]
EOF
vault_before=$(sha256sum "$TMP/home/.config/ssm/connections.enc" | awk '{print $1}')
set +e
import_out=$(HOME="$TMP/home" SSM_UPDATE_REPO=off "$BIN" --master-pass-file "$TMP/home/.config/ssm/master.pass" import-json "$TMP/import.json" 2>&1)
import_rc=$?
set -e
vault_after=$(sha256sum "$TMP/home/.config/ssm/connections.enc" | awk '{print $1}')
if [ "$import_rc" = "0" ] || [ "$vault_before" != "$vault_after" ]; then
  echo "guarded import: rc=$import_rc before=$vault_before after=$vault_after out=[$import_out]" >&2
  exit 1
fi
echo "ok guarded_import"

set +e
edit_out=$(HOME="$TMP/home" SSM_UPDATE_REPO=off "$BIN" --master-pass-file "$TMP/home/.config/ssm/master.pass" edit local 2>&1)
edit_rc=$?
set -e
if [ "$edit_rc" = "0" ] || ! printf '%s' "$edit_out" | grep -q 'Unknown command'; then
	echo "removed edit command: rc=$edit_rc out=[$edit_out]" >&2
	exit 1
fi
echo "ok removed_tui_command"

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
