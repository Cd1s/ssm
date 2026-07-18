# Release Notes Draft

## Unreleased

### Fast agent execution

- Keep one-shot literal commands on the direct `sshctl --json run <alias> --argv ...` path; typed request files remain the safer path for dynamic argv, scripts, secrets, and mutations.
- Add `sshctl run <alias> --stream`, a headless NDJSON argv stream that syncs and decrypts once, reuses the SSH connection across commands, refreshes inventory every 30 seconds by default, and stops rather than using stale data after a refresh failure.
- Reuse the already-validated decrypted vault for the command's first load, removing the duplicate Argon2 decrypt previously performed immediately after unlock while allowing later same-process loads to observe intervening saves.
- Open the actual pooled SSH session directly instead of opening and closing a probe channel first. Serialize dials per destination rather than globally, allowing different fleet targets to establish SSH connections concurrently.

### Validation

- Add strict stream parsing/error tests and an in-process SSH regression proving that two commands use one connection and exactly two command sessions.

## v1.4.2

### Push unlock fix

- Load the vault passphrase from the configured private file before both `ssm push` and `sshctl push` read the encrypted local vault.
- Preserve pre-unlock validation for invalid push arguments and keep scoped/all transaction semantics unchanged.
- Add a subprocess regression test that performs a push using only a real `master.pass` file, without pre-populating process-global credentials.

### Validation

- Formatting, unit tests, race tests, vet, golangci-lint, vulnerability scanning, build, and the real OpenSSH matrix pass.

## v1.4.1

### Consistent non-interactive help

- Add command-specific, pre-unlock help for request, push, put, get, run, map, host, host-key, doctor, status, sync, pull, and redirect, including nested host operations.
- Keep help and version paths free of vault unlocks, network calls, and secret access while preserving one-value JSON errors for invalid invocations.

### Smaller agent and code surface

- Reduce the agent SSM skill to its decision rules and security boundaries; command help and the request schema are now the authoritative detail sources.
- Remove 13 unreachable legacy helpers and the unused ring buffer. Bubble Tea, Lip Gloss, TUI entry points, interactive shells, and terminal prompts remain absent.

### Security maintenance

- Raise the supported toolchain to Go 1.25.12 and update the existing `x/crypto`, `x/sys`, and `x/term` modules, fixing all vulnerabilities reachable in the prior build according to `govulncheck`.
- Add a pinned vulnerability scan to CI.

### Validation

- Unit, shuffled, race, vet, golangci-lint, staticcheck, dead-code, build, vulnerability, skill/schema, and real OpenSSH matrix checks pass without skipped tests.
- The complete lint baseline from v1.2.0 is clean; file and process safety annotations are limited to explicit user paths or test-owned temporary paths.

## v1.4.0

### Transactional inventory sync

- Give each changed host mutation a stable transaction ID and expose a secret-free pending mutation list through `status --json`.
- Add `push --only <transaction-id>` with an exact alias/operation preflight so unrelated local changes remain pending.
- Add deliberate `push --all`; retain bare push only as a compatibility push-all path. Transaction journals stay inside the encrypted local vault, while the sync service continues to receive only an encrypted inventory blob.

### Explicit SSH host trust

- Reject both first-use and changed host keys during normal run/check operations; no key is auto-saved or auto-replaced.
- Expand `host-key inspect --json` with address/port, observed and known fingerprints, `new|mismatch|trusted` classification, and safe guidance.
- Require the exact re-observed SHA-256 fingerprint plus `--yes` for acceptance. Remove automatic `ssh-keygen -R`/`ssh-keyscan` recovery advice.

### Atomic, observable, resumable put

- Stream regular files into private sibling temporary files, verify remote byte count, and atomically rename only after completion. Optional `--sha256` performs end-to-end digest verification; `--timeout` reports a stable timeout stage and byte count.
- Return structured transfer stage, bytes sent, integrity, atomicity, and resume status. Distinguish local read, SSH dial/auth, remote write, timeout, integrity, capability, partial-state, and publish failures.
- Add explicit regular-file-only `--resume=v1` and typed request support. Resume state is mode 0600 and bound to protocol version, destination hash, local size, and full digest; local and remote prefix digests must match before append.
- Preserve verified partial state across interruption, report reused versus sent bytes, verify full SHA-256 before atomic publish, reject changed/corrupt/ambiguous state, and opportunistically expire same-target v1 state older than seven days. Directory uploads remain non-resumable.

### Agent-safe contract and diagnostics

- Normalize machine failures around stable `ok/error/message/hint/exit/stage` fields while preserving a remote program's own exit 255 as a remote failure rather than assuming transport failure.
- Make alias drift, sync freshness/offline state, conflicts, and exact candidate selection explicit; never auto-select suggestions or silently fall back offline.
- Consolidate README, CLI help, request schema, and the `agent-ssm` skill around global `--json`, `request --file`, literal `argv`, file-backed `script_file`, and path-only `secret_files`.
- Mark one-string shell commands as compatibility-only with quoting/expansion warnings, and add troubleshooting for alias, sync, host-key, remote-process, and transfer failures.

### Validation

- Unit and integration coverage for scoped push isolation, secret-free transaction status, first-use/changed host-key rejection, wrong-fingerprint immutability, atomic upload cleanup, SHA-256 mismatch, missing verification tooling, and resume state validation.
- Real OpenSSH matrix forces upload timeouts and mid-transfer disconnects, resumes only a verified prefix with exact byte accounting, rejects corrupt partials, handles changed sources and shell-metacharacter paths, and verifies final digests.
- Release gates: formatting, tests, race tests, vet, build, SSH matrix, request/skill artifact validation, and diff checks.

## v1.3.0

### Non-interactive CLI only

- Remove the Bubble Tea/Lip Gloss TUI, interactive connection manager, shell entry points, and their dependencies.
- Require explicit commands and file-backed credentials for vault creation/unlock and sync login/register; no command waits for terminal input.
- Keep connection management through `sshctl host` and versioned typed requests. Uploads now stream to a sibling temporary file and atomically rename on success, preserving an existing destination after interrupted or failed transfers.

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
- Replace former add/edit/key-entry paths with explicit host CLI/request operations and file-backed credential inputs.

### Script and host-key hardening

- Add remote script syntax preflight using the same selected interpreter with `-n`; classify parse failures as `script_syntax_error` before executing the body. Typed script requests enable it by default.
- Add `sshctl host-key inspect` to observe the current algorithm/fingerprint without sending credentials and report `trusted`, `new`, or `mismatch` against `known_hosts`.
- Add fingerprint-bound `sshctl host-key accept ... --fingerprint SHA256:... --yes`. A mismatched or changed fingerprint does not install the new key.
- Report connection reuse scope explicitly as `process`, and document that exit 255 alone is not a failure category because a remote process can return it.

### Validation

- Strict request parsing, exact argv/secret-file handling, import mode guards, verify/push option guards, and global JSON parsing tests.
- In-process SSH coverage for script syntax preflight and host-key inspect/accept with wrong-fingerprint immutability.
- Real OpenSSH matrix covers candidate-vault rollback, typed argv/script requests, syntax-error no-side-effect behavior, host-key fingerprint guards, and guarded import.

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
