# Release Notes Draft

## v1.3.0

### Typed agent interface

- Add `sshctl request [--file <json>|-]` with strict schema version 1 and unknown-field rejection. A run request must select exactly one of `argv`, `shell_command`, or `script_file`.
- Preserve literal arguments and script arguments as JSON arrays so the local shell cannot reinterpret agent-generated values. Request secrets are file paths only and remain redacted.
- Identify every execution with `mode`, `transport`, and optional `preflight` metadata. Global `sshctl --json ...` now keeps argument, unlock, alias, and sync failures to one JSON value.
- Fix `sshctl run --json` without an alias: it now returns structured `missing_alias` instead of treating `--json` as a host name.

### Verified mutations and safer legacy boundaries

- Add `--verify` for host add/update/upsert. SSM checks the in-memory candidate with `hostname; uname -sr` and saves only after success; failure returns `verification_failed`, `applied:false`, and leaves the encrypted vault unchanged.
- Require `--verify` when a host mutation uses `--push`. A push failure reports `sync_push_failed` while preserving the verified local change as pending.
- Default typed host add/update/upsert requests to candidate verification.
- Remove the destructive `import-json` default. Callers must choose `--merge`, or explicitly authorize full replacement with `--replace --yes`.
- Fail every TUI-only path immediately when no terminal is available, including vault creation/unlock, add/edit, key entry, and interactive login/register.

### Script and host-key hardening

- Add remote script syntax preflight using the same selected interpreter with `-n`; classify parse failures as `script_syntax_error` before executing the body. Typed script requests enable it by default.
- Add `sshctl host-key inspect` to observe the current algorithm/fingerprint without sending credentials and report `trusted`, `new`, or `mismatch` against `known_hosts`.
- Add fingerprint-bound `sshctl host-key accept ... --fingerprint SHA256:... --yes`. A mismatched or changed fingerprint does not install the new key.
- Report connection reuse scope explicitly as `process`, and document that exit 255 alone is not a failure category because a remote process can return it.

### Validation

- Strict request parsing, exact argv/secret-file handling, import mode guards, verify/push option guards, and global JSON parsing tests.
- In-process SSH coverage for script syntax preflight and host-key inspect/accept with wrong-fingerprint immutability.
- Real OpenSSH matrix covers candidate-vault rollback, typed argv/script requests, syntax-error no-side-effect behavior, host-key fingerprint guards, guarded import, and non-TTY TUI rejection.

## v1.2.0

### Agent-safe host management

- Add `sshctl host list/show/add/update/upsert/remove` (also `ssm host`) with stable JSON, strict validation, exact-alias semantics, and retry-safe `upsert` (`changed:false` on a no-op retry).
- Read SSH passwords and new private keys only from `--password-file` / `--key-file`; validate private keys before vault writes and never return credential material in JSON.
- Prevent accidental overwrite of unrelated/shared saved keys. `remove --prune-key` deletes a key only after its last host reference is gone.
- Stage host changes locally with `sync_pending:true`; verification happens before an explicit `sshctl push`, whose failures are observable.
- Stop before mutation when a configured remote refresh fails (`sync_pull_failed`); `--offline` is an explicit stale-state override.

### Script and quote reliability

- `-s`, `-f`, and `--scripts` now send bodies through SSH stdin to a fixed shell runner instead of embedding generated text in the SSH exec command.
- Normalize UTF-8 BOM and CRLF, reject NUL and scripts over 16 MiB, select `sh/bash/dash/ash/ksh/zsh` from shebang or `--shell`, and pass arguments after `--` with exact POSIX quoting.
- Script plan/JSON output reports `interpreter`, `stdin_bytes`, and `script_sha256` without exposing the body. Failures distinguish `interpreter_not_found` from `remote_script_failed`.
- Add explicit `--argv` mode so even a single argument is treated literally; legacy single-string shell behavior remains compatible.
- Validate `--secret` environment names and export script secrets into the interpreter environment while keeping plan/trace redacted.
- Return structured `invalid_arguments` JSON with exit 2 when `--json` parsing fails, instead of mixing machine output with a usage page.

### Validation

- `go test ./...`, `go test -race ./...`, `go vet ./...`, and cross-platform builds.
- Real local-shell runner test covers BOM/CRLF, nested single/double quotes, exact args, and secret export.
- Isolated encrypted-vault CLI smoke covers host create, unchanged upsert, partial update, show, remove, and JSON errors.

## v1.1.0

### Agent fleet features (items 1–8)

1. **Connection reuse** — SSH clients are pooled by `user@host:port` (new session per command). Disable with `--no-reuse` or `SSM_REUSE=0`.
2. **`sshctl run --json`** — machine-readable result: `ok`, `exit`, `stdout`/`stderr` (when captured), `remote_command`, `latency_ms`, `error`, `risk`.
3. **Alias redirects** — `sshctl redirect set old new` stores soft-links in `~/.config/ssm/redirects.json` so migrated automation keeps working.
4. **`sshctl map` parallel fleet** — run one command across many aliases/globs with bounded workers (`-j` / `--jobs`); **multi-script** via `--scripts a.sh,b.sh` (host×script jobs in parallel). Failures on one target do not drop others.
5. **`sshctl plan` / `run --plan`** — dry-run: show redacted `remote_command` + risk tag (`low|medium|high`) without dialing.
6. **Secrets** — `--secret NAME=value` or `NAME=@file` inject as remote env assigns; values redacted from plan/trace/`remote_command`.
7. **Directory put/get** — recursive trees via tar-over-SSH (falls back to walk+file for upload).
8. **`sshctl doctor [alias] [--deep] [--json]`** — vault/sync/redirects/reuse + check probe + optional deep remote health signals.

### Also

- Map/plan support `--json` for agent parsing.
- README (zh/en) and agent skill updated for fleet usage.

### Validation

- `go test ./...` and race on concurrent packages
- Live smoke: plan, run --json, map (real+missing), redirect, dir put/get, doctor on `limee-hk`

## v1.0.10

### Agent triage (from Hermes field report)

- Structured connection errors on stderr: `ssm: error=<code> alias=... address=...` plus `ssm: hint=...`.
  Codes: `alias_not_found`, `dial_timeout`, `dial_refused`, `dial_network`, `host_key_mismatch`, `auth_failed`, `no_auth_configured`, `session_failed`, …
- Connection-layer failures exit **255** (OpenSSH-like), distinct from remote process exit status.
- `sshctl check <alias> [--json]` / `ssm check`: dial + `hostname; uname -sr` probe for first-step triage.
- `--timeout 10s` / `SSM_TIMEOUT` / `SSM_DIAL_TIMEOUT` for dial timeout (avoid hanging agents).
- Alias-not-found always emits `did_you_mean` + migration hint.
- Host-key / dial errors include recovery hints and explicitly state when the failure is **not** a quote bug.
- Skill documents four-bucket triage: quote vs alias vs network/host-key vs remote OS.

### Validation

- `go test ./...`
- Live `sshctl check` / structured errors against a real host.

## v1.0.9

### Agent UX (from real-host testing)

- Add `sshctl get` / `ssm get` to download remote files (creates local parent dirs; atomic temp+rename).
- `sshctl put` now `mkdir -p` remote parent directories so nested uploads work.
- Multi-arg leading `NAME=value` tokens become remote env assignments (no more `FOO=bar: command not found` without `--raw`).
- Missing aliases print `Did you mean: ...` suggestions (typo-friendly for agents).
- `sshctl list --json` for machine-readable inventory.
- `--trace` / `-v` / `SSM_TRACE=1` print the exact remote command line for quote debugging.

### Validation

- `go test ./...`
- Live checks against a real host: run/put/get/env/suggest/heredoc paths.

## v1.0.8

### Agent / quoting UX

- Multi-argument `sshctl run` / `ssm exec` now shell-quotes each argv before remote join, so agent-style calls like `sshctl run host bash -c 'echo hi'` and args with spaces work without nested-quote gymnastics.
- Single-argument commands still pass through as a remote shell script (existing behavior, OpenSSH-like).
- Add `-s` / `--script` (stdin script, heredoc-friendly) and `-f` / `--file` (local script file) for complex remote work without quote hell.
- Add `--raw` for classic space-join with no quoting (OpenSSH compatibility).
- Add `--` end-of-options support.
- SSH-like shorthand: `sshctl <alias> <command...>` runs a command; `sshctl <alias>` opens a shell. Known subcommands still take precedence.
- `sshctl exec` and `ssm run` are aliases of `run` / `exec`.
- Update agent skill and READMEs to recommend multi-arg and `-s` first.

### Validation

- `go test ./...`
- `go test -race ./...`
- `go build ./cmd/ssm`
- `scripts/ssh_matrix_test.sh` (multi-arg, shorthand, `--raw`, `-s`, `-f`)

## v1.0.7

### Cleanup

- Remove agent-only development manuals and OpenSpec scaffolding from the public repository.
- Keep the public `agent-ssm` skill and Claude marketplace metadata.

### Validation

- Confirmed no remaining references to `AGENTS`, `OpenSpec`, `openspec`, `REVIEW_FINDINGS`, or `.codex`.
