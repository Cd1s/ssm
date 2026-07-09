# Release Notes Draft

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

## v1.0.6

### Fixes

- Polish the public `agent-ssm` skill with shorter safety-first instructions, install docs, marketplace metadata, and dry-run validation prompts.
- Remove host-identifying review notes and replace real-looking skill examples with documentation-reserved addresses.

### Validation

- Luban skill repository check for `skills/agent-ssm` reports `FAIL: 0`.

## v1.0.5

### Fixes

- Make interactive `ssm login` and `ssm register` fail visibly if `cloud.json` cannot be saved.

### Validation

- `go test ./...`
- `go test -race ./...`
- `go build ./cmd/ssm`
- `scripts/ssh_matrix_test.sh`

## v1.0.4

### Fixes

- Reject empty and oversized cloud pull responses before writing `connections.enc`.
- Preserve enabled-by-default settings when older or partial `settings.json` files omit boolean fields.
- Route master-pass file and cloud password-file read errors through the shared secret redactor.
- Lock SSH session closed-state updates and make the transition idempotent for multi-session shutdown paths.
- Return `known_hosts` directory creation errors instead of discarding them during host-key save.

### Validation

- `go test ./...`
- `go test -race ./...`
- `go build ./cmd/ssm`
- `scripts/ssh_matrix_test.sh`

## v1.0.3

### Fixes

- Verify `ssm update` and installer downloads against `checksums.txt` before replacing binaries.
- Make manual GitHub release runs require an explicit semver tag and build every asset with that prepared version.
- Use unique temporary files during update replacement to avoid stale `.new` file collisions.
- Write vault, cloud, settings, sync cache, and sync server blobs through private unique temp files before atomic rename.
- Reject fractional or out-of-range JSON import ports and negative `--expect-count` values.
- Fail cloud sync requests locally when the bearer token is missing, and fall back to status text for empty server errors.
- Add regression coverage for empty sync bearer tokens and oversized opaque blob rejection.
- Redact sensitive fields and private-key blocks consistently in CLI error output and panic messages.

### Validation

- `go test ./...`
- `go test -race ./...`
- `go build ./cmd/ssm`
- `scripts/ssh_matrix_test.sh`

## v1.0.2

### Fixes

- Fix GitHub Actions release workflow discovery by adding `workflow_dispatch` and making CI run on the default branch.
- Make JSON imports deterministic for map-shaped inputs and correctly handle `{"servers": {...}}` before treating JSON as a bare host map.
- Reject `auth_type=password` imports when the password is empty, preventing unusable no-auth connections.
- Normalize cloud sync server URLs with trailing slashes across login, register, status, push, pull, and remote hash requests.
- Route cloud HTTP requests through a timeout client for a clearer, testable network boundary.
- Compare sync bearer token hashes with constant-time comparison.

### Validation

- `go test ./...`
- `go test -race ./...`
- `go build ./cmd/ssm`
- `scripts/ssh_matrix_test.sh`

## v1.0.1

### Fixes

- Reject malformed `known_hosts` files instead of silently falling back to trust-on-first-use.
- Return a clear SSH authentication error when a stored connection has no password or key configured.
- Guard `sshctl put` remote uploads so `chmod` only runs after the remote write succeeds.
- Create the SSM config directory before saving `cloud.json` during noninteractive login/register flows.
- Make vault merge output deterministic while preserving the existing rule that remote entries win name conflicts.
- Allow update checks to be explicitly disabled with `SSM_UPDATE_REPO=off`, `none`, or `disabled`.

### Validation

- Added Go tests for SSH auth/host-key/upload helpers, cloud config persistence, deterministic vault merge, sync server request validation, and update disabling.
- Added `scripts/ssh_matrix_test.sh` covering `sshctl run` quoting, stdin, non-zero exit codes, long-running commands, persistent background scripts, `sshctl put`, `sshctl shell`, missing connection errors, and known_hosts creation against an isolated local sshd.
