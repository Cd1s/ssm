# Release Notes Draft

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
- Added `scripts/ssh_matrix_test.sh` covering `sshctl run` quoting, stdin, non-zero exit codes, long-running commands, persistent background scripts, `sshctl put`, missing connection errors, and known_hosts creation against an isolated local sshd.

### Release Checklist

- [x] `go test ./...`
- [x] `go test -race ./...`
- [x] `go build ./cmd/ssm`
- [x] `scripts/ssh_matrix_test.sh`
- [x] Choose version tag: `v1.0.1`
- [ ] Push tag: `git tag v1.0.1 && git push origin v1.0.1`
