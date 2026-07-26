# Verification manifest and BC-10 migration

Status: implemented by GitHub Issue #18

The checked-in Go manifest at `cmd/verify` is the sole owner of verification
profile membership, ordering, exact actions, prerequisites, pinned tool
versions, required-versus-conditional status, required execution contexts, and
named future extensions. Its stable review surface is:

```sh
go run ./cmd/verify list
```

The output is deterministic JSON and is snapshot-tested in full. Commands are
represented as executable and argument arrays, with separate environment
entries. `{temp}`, `{exe}`, `{goroot}`, and `{version}` are explicit
cross-platform substitutions; commands are not joined into a host shell
string. Linux, macOS, and Windows path semantics are table-tested without
pretending to execute a foreign operating-system binary.

Runtime authority comes from the separate, manually reviewed policy in
`cmd/verify/security_policy.go`. It duplicates the exact allowed builtin names,
executables, argument vectors, environment, and output expectations; it is
deliberately not generated from the manifest constructors. Changing a
constructor and the JSON golden together therefore does not authorize a new
tag, publish, upload, release, install, repository-output, mutating Go, or
arbitrary command.

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

GitHub CI installs and asserts its OS, OpenSSH, shell, JSON, hashing, and
official prebuilt lint prerequisites visibly in workflow YAML, declares
read-only repository permissions, and invokes only `go run ./cmd/verify ci`.
The driver does not install packages or acquire permissions.

## Profiles

`fast` is a convenience-only local loop, in this order:

1. `format`
2. `vet`
3. `unit`

It is deliberately not merge-equivalent and not release-equivalent.

`ci` is the ordered 11-check profile in the table above. `ssh-matrix` is
conditional locally and explicitly required in the `github_actions_linux`
context. Official GitHub CI prepares and asserts every live-matrix
prerequisite, including `/run/sshd`, `/usr/sbin/sshd`, and the SFTP subsystem
path. Absence of any declared prerequisite there fails the profile. A local
non-Linux machine, or a local machine missing a declared live-matrix
prerequisite, reports `ssh-matrix` as `unavailable` and the profile as
`completed_with_unavailable`; neither is represented as passed.

The executable `release` check list begins with the exact `ci` sequence and
then adds, in order:

1. source release-version validation;
2. temporary builds named `ssm-linux-amd64`, `ssm-linux-arm64`,
   `ssm-darwin-amd64`, `ssm-darwin-arm64`, `ssm-windows-amd64.exe`, and
   `ssm-windows-arm64.exe`;
3. updater selection tests for those same six names;
4. a non-empty `RELEASE_NOTES.md` section matching the source version;
5. in-memory SHA-256 computation for the six assets and `install.sh`;
6. updater checksum selection, mismatch, and no-replacement failure tests.

The release profile separately exposes metadata named `migration-extension`
and `provenance-extension`. These are not executable Ticket #18 checks and do not
appear in check results as passed, failed, or unavailable. Their manifest
metadata says `required_before: initial_v2_release`, preserving the future
migration/provenance seams required by Issue #18 while honoring ADR 0003 and
Decisions 12–13: the initial v2 release remains blocked until later tickets add
and pass those real gates.

Accordingly, the exact command

```sh
go run ./cmd/verify release
```

returns zero only when all executable Ticket #18 release-preflight checks pass.
Its terminal summary is `preflight_passed`, and its profile purpose and
equivalence explicitly say that this is not a claim of initial-v2 release
readiness. When later tickets implement either extension, they must promote it
from metadata into a required executable check before the initial v2 release.

No profile merges, tags, installs, replaces an executable, calls a publication
API, creates or uploads a release, or writes release artifacts into the
repository. GitHub release publication remains explicit in `release.yml` and
outside this verification driver.

## Prerequisites and runtime

Required prerequisites are listed in the manifest:

- a Git worktree with no non-ignored untracked paths when execution starts;
- Go 1.25.12 and the gofmt executable from that same resolved toolchain;
- the official golangci-lint 2.11.4 prebuilt;
- `jq` and `bash`;
- a cold-cache network path for the pinned govulncheck module, or a populated
  Go module cache.

Files declared `tracked` are verified through Git, not merely by filesystem
presence. Before running any action, verification uses Git name/status metadata
to reject every non-ignored untracked path. It never opens, follows, or hashes
untracked or ignored file contents. Ignored files such as
`master.pass`, `cloud.json`, tokens, and private keys remain untouched and
unread.

The before/after snapshot covers the HEAD object and symbolic name; all local
heads, tags, and remote refs; index entries, flags, and staged diff; tracked
worktree content diff; and non-ignored untracked names. This detects allow-empty
commits, ref/tag changes, index changes, further edits to already-dirty tracked
files, and created or removed non-ignored untracked names without reading their
contents.

The live SSH matrix is conditional locally on Linux and its complete audited
external-tool list: `awk`, `bash`, `cat`, `chmod`, `cp`, `dd`, `dirname`,
`find`, `go`, `grep`, `head`, `id`, `ln`, `mkdir`, `mktemp`, `nohup`,
`printenv`, `rm`, `script`, `sed`, `seq`, `sh`, `sha256sum`, `sleep`, `ssh`,
`ssh-keygen`, `sshd`, `tr`, and `wc`. `jq` is a JSON-artifact prerequisite,
not an SSH-matrix prerequisite. Bash builtins such as `cd`, `command`, `echo`,
`kill`, `printf`, `pwd`, `set`, `test`, `trap`, and `true` are not
misrepresented as external tools. The manifest and official Linux CI also
assert readable `/dev/null` and `/dev/zero`, `/run/sshd`, the server binary,
and the SFTP subsystem path. Tests keep the script declarations, manifest, and
workflow assertions in exact parity.

The matrix uses only a temporary test home, temporary keys, a temporary
OpenSSH server, and a temporary binary. It does not read the user's vault,
master password, sync configuration, tokens, private keys, or decrypted
inventory. Failure to remove any profile temporary directory makes the profile
failed and nonzero.

The supported six-platform release target table is owned by
`internal/releaseasset`. Manifest asset builds, checksum verification, and the
production updater selector consume that same table/name function; a direct
parity test also compares every manifest output with the updater selector.

Focused tests execute representative production actions without recursively
running a full profile inside the verifier's own test suite. The CI
representative runs real format, temporary build, and unit command paths in a
test-owned Git repository. The release representative runs the real source
version and release-note builtins, all six shared-name cross-builds, and the
checksum builtin in another test-owned repository; foreign binaries are built
but never executed. Repository snapshot enforcement surrounds both. The real
top-level `ci` and `release` executions remain the coverage for lint,
vulnerability, race, JSON, shell, live SSH, updater selection, and updater
failure-path actions.

Expected runtime depends on caches and host speed:

- `fast` runs one ordinary test suite and is normally the shortest loop;
- `ci` adds lint, vulnerability, race, and the live OpenSSH matrix and should
  be expected to take several minutes on a cold machine;
- `release` repeats no `ci` membership, but adds six cross-builds and focused
  updater/release checks, so it is longer than `ci`.

Coverage may be observed with normal Go tooling during development, but no
profile enforces a percentage threshold. Required public scenarios remain the
gate.
