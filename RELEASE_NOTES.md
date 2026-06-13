# Release Notes Draft

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
