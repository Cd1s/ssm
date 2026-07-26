# Verification manifest and BC-10 migration

Status: implemented by GitHub Issue #18

The checked-in Go manifest at `cmd/verify` is the sole owner of verification
profile membership, ordering, actions, prerequisites, pinned tool versions,
and required-versus-conditional status. Its stable review surface is:

```sh
go run ./cmd/verify list
```

The output is deterministic JSON. Commands are represented as executable and
argument arrays, with separate environment entries. `{temp}`, `{exe}`, and
`{version}` are explicit cross-platform substitutions; commands are not joined
into a host shell string.

## BC-10 old-to-new membership

The old `make check` was a mutating three-command subset:

| Order | Old action | Effect | New owner |
| --- | --- | --- | --- |
| 1 | `gofmt -w .` | Rewrote tracked Go source. | `ci/format`: `gofmt -l .`, requiring empty output. |
| 2 | `golangci-lint run ./...` | Used whichever lint version was on `PATH`. | `ci/lint`: official golangci-lint 2.11.4 with `--new-from-rev=v1.2.0`. |
| 3 | `go build -ldflags="-s -w -X main.version=dev" -o ssm ./cmd/ssm` | Wrote `ssm` in the repository root. | `ci/build`: builds with VCS stamping disabled into profile-owned temporary storage. |

`make check` is now exactly one adapter:

```sh
go run ./cmd/verify ci
```

The old GitHub CI membership and its new manifest entries are:

| Order | Old CI action | New `ci` check |
| --- | --- | --- |
| 1 | `test -z "$(gofmt -l .)"` | `format` |
| 2 | golangci-lint action 2.11.4, with event-dependent new-issue arguments | `lint`, pinned to 2.11.4 and one reviewed `--new-from-rev=v1.2.0` action |
| 3 | `go vet ./...` | `vet` |
| 4 | `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...` | `vulnerability` |
| 5 | `go build ./cmd/ssm` | `build`, with a temporary output |
| 6 | `go test ./...` | `unit` |
| 7 | `go test -race ./...` | `race` |
| 8 | `jq empty skills/agent-ssm/test-prompts.json` | `agent-prompts-json` |
| 9 | `jq empty skills/agent-ssm/references/request-v1.schema.json` | `request-schema-json` |
| 10 | `bash -n scripts/ssh_matrix_test.sh` | `ssh-matrix-shell-syntax` |
| 11 | `scripts/ssh_matrix_test.sh` after explicit OpenSSH setup | `ssh-matrix` |

GitHub CI installs its OS and official prebuilt lint prerequisites visibly in
workflow YAML, declares read-only repository permissions, and invokes only
`go run ./cmd/verify ci`. The driver does not install packages or acquire
permissions.

## Profiles

`fast` is a convenience-only local loop, in this order:

1. `format`
2. `vet`
3. `unit`

It is deliberately not merge-equivalent and not release-equivalent.

`ci` is the ordered 11-check profile in the table above. Official GitHub CI is
Linux and prepares every live-matrix prerequisite, so the existing SSH gate
remains required in that environment. A local non-Linux machine, or a local
machine missing a declared live-matrix tool, reports `ssh-matrix` as
`unavailable`; it does not report that check as passed.

`release` begins with the exact `ci` sequence and then adds, in order:

1. source release-version validation;
2. temporary builds named `ssm-linux-amd64`, `ssm-linux-arm64`,
   `ssm-darwin-amd64`, `ssm-darwin-arm64`, `ssm-windows-amd64.exe`, and
   `ssm-windows-arm64.exe`;
3. updater selection tests for those same six names;
4. a non-empty `RELEASE_NOTES.md` section matching the source version;
5. in-memory SHA-256 computation for the six assets and `install.sh`;
6. updater checksum selection, mismatch, and no-replacement failure tests;
7. named `migration-extension` and `provenance-extension` seams.

The extension seams are conditionally unavailable until their owning later
tickets supply real actions. They are reported as `unavailable`, never
`passed`, and make the profile summary `passed_with_unavailable`. Consequently,
the initial profile is not a claim that all v2 migration or provenance release
blockers are complete.

No profile merges, tags, installs, replaces an executable, calls a publication
API, creates or uploads a release, or writes release artifacts into the
repository. GitHub release publication remains explicit in `release.yml` and
outside this verification driver.

## Prerequisites and runtime

Required prerequisites are listed in the manifest:

- a Git worktree;
- Go and gofmt 1.25.12;
- the official golangci-lint 2.11.4 prebuilt;
- `jq` and `bash`;
- a cold-cache network path for the pinned govulncheck module, or a populated
  Go module cache.

The live SSH matrix is conditional locally on Linux, `bash`, `ssh`,
`ssh-keygen`, `sshd`, `script`, and `sha256sum`. It uses only a temporary test
home, temporary keys, a temporary OpenSSH server, and a temporary binary. It
does not read the user's vault, master password, sync configuration, tokens,
private keys, or decrypted inventory.

Expected runtime depends on caches and host speed:

- `fast` runs one ordinary test suite and is normally the shortest loop;
- `ci` adds lint, vulnerability, race, and the live OpenSSH matrix and should
  be expected to take several minutes on a cold machine;
- `release` repeats no `ci` membership, but adds six cross-builds and focused
  updater/release checks, so it is longer than `ci`.

Coverage may be observed with normal Go tooling during development, but no
profile enforces a percentage threshold. Required public scenarios remain the
gate.
