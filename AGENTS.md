# Repository Guidance

## Project Shape

- Go CLI/TUI project for `ssm` and `sshctl`.
- Main package: `cmd/ssm`.
- Internal packages:
  - `internal/config`: encrypted vault/config/settings file paths and persistence.
  - `internal/vault`: Argon2id + AES-GCM encryption.
  - `internal/cloud`: sync client for encrypted vault blobs.
  - `internal/syncserver`: HTTP sync server.
  - `internal/ssh`: SSH exec, shell, session manager, and file upload.
  - `internal/tui`: Bubble Tea UI models.
  - `internal/update`: GitHub release updater.

## Commands

- Test: `go test ./...`
- Build: `go build ./cmd/ssm`
- SSH matrix: `scripts/ssh_matrix_test.sh` when `sshd`, `ssh`, and `ssh-keygen` are available
- Project build: `make build`
- Format: `gofmt -w <changed-go-files>`
- Full local check if `golangci-lint` is available: `make check`

## Review And Change Notes

- Treat vault contents, sync tokens, private keys, and passwords as secrets. Do not print them in errors, logs, tests, or docs.
- `sshctl` defaults to `~/.config/ssm/master.pass` through `SSM_MASTER_PASS_FILE`/global arg handling; preserve noninteractive behavior.
- Sync server stores opaque encrypted blobs only. Avoid changes that require the server to decrypt vault data.
- Local and remote vault merge currently resolves duplicate connection/key names by letting the remote value overwrite the local value in `config.MergeVaults`.
- Auto-update replaces the current executable from GitHub releases; tests should not hit the network.
- Disable update checks in headless tests with `SSM_UPDATE_REPO=off`.
- SSH host-key behavior writes new host keys to `~/.ssh/known_hosts` and treats changed keys as a failure requiring user confirmation.
- Use `0600` for secret files and `0700` for config/data directories.
- OpenSpec workflow lives in `openspec/changes/improve-review-debug-feature-workflow`; keep `openspec/config.yaml` and this file aligned when changing review, bug investigation, or feature-extension guidance.

## Current Baseline

- On 2026-05-28 in this workspace, `go test ./...` passes.
- On 2026-05-28 in this workspace, `go build ./cmd/ssm` passes.
