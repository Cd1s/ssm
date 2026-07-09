# Release Notes Draft

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
