# Verification manifest and BC-10 migration

Status: implemented by GitHub Issues #18 and #28

The checked-in Go manifest at `cmd/verify` is the sole owner of verification
profile membership, ordering, exact actions and preparation actions,
prerequisites, pinned tool versions, required-versus-conditional status,
required execution contexts, and named future extensions. Its stable review
surface is:

```sh
go run ./cmd/verify list
```

The output is deterministic JSON and is snapshot-tested in full. Commands are
represented as executable and argument arrays, with separate environment
entries. `{temp}`, `{exe}`, `{goroot}`, and `{version}` are explicit
cross-platform substitutions; commands are not joined into a host shell
string. Linux, macOS, and Windows path semantics are table-tested without
pretending to execute a foreign operating-system binary.

The lint entry also owns its preparation as manifest data: the source
repository working directory, `{temp}/lint.patch` output, required
`v1.2.0` commit-resolving tag/ref, and the reviewed `lint-patch` builtin.
That builtin builds verifier-controlled temporary object and index views,
hashes safely opened tracked worktree files with `hash-object --no-filters`,
and diffs two temporary trees. It never asks source-worktree clean/process
filters to produce the lint patch. Missing or non-commit baselines fail as a
prerequisite before lint executes.

Runtime authority comes from the separate, manually reviewed policy in
`cmd/verify/security_policy.go`. It duplicates the exact allowed builtin names,
preparation records, executables, argument vectors, environment, output paths,
working directories, and output expectations; it is deliberately not
generated from the manifest constructors. Changing a constructor and the JSON
golden together therefore does not authorize a new tag, publish, upload,
release, install, repository-output, mutating Go, or arbitrary command. A
second independent guard permits manifest action environment additions only
for the reviewed `GOOS` and `GOARCH` release matrix; credential-like and
otherwise unreviewed keys are rejected.

## BC-10 old-to-new membership

The old `make check` was a mutating three-command subset:

| Order | Old action | Effect | New owner |
| --- | --- | --- | --- |
| 1 | `gofmt -w .` | Rewrote tracked Go source. | `ci/format`: `gofmt -l .`, requiring empty output. |
| 2 | `golangci-lint run ./...` | Used whichever lint version was on `PATH`. | `ci/lint`: official golangci-lint 2.11.4 with a verifier-created `v1.2.0`-to-current tracked patch. |
| 3 | `go build -ldflags="-s -w -X main.version=dev" -o ssm ./cmd/ssm` | Wrote `ssm` in the repository root. | `ci/build`: builds with VCS stamping disabled into profile-owned temporary storage. |

`make check` is now exactly one adapter:

```sh
go run ./cmd/verify ci
```

The old GitHub CI membership and its new manifest entries are:

| Order | Old CI action | New `ci` check |
| --- | --- | --- |
| 1 | `test -z "$(gofmt -l .)"` | `format` |
| 2 | golangci-lint action 2.11.4, with event-dependent new-issue arguments | `lint`, pinned to 2.11.4 and one reviewed `--new-from-patch {temp}/lint.patch` action |
| 3 | `go vet ./...` | `vet` |
| 4 | `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...` | `vulnerability` |
| 5 | `go build ./cmd/ssm` | `build`, with a temporary output |
| 6 | `go test ./...` | `unit` |
| 7 | `go test -race -timeout=15m ./...` | `race` |
| 8 | `jq empty skills/agent-ssm/test-prompts.json` | `agent-prompts-json` |
| 9 | `jq empty skills/agent-ssm/references/request-v1.schema.json` | `request-schema-json` |
| 10 | `bash -n scripts/ssh_matrix_test.sh` | `ssh-matrix-shell-syntax` |
| 11 | `scripts/ssh_matrix_test.sh` after explicit OpenSSH setup | `ssh-matrix` |

GitHub CI installs and asserts its OS, OpenSSH, shell, JSON, hashing, and
official prebuilt lint prerequisites visibly in workflow YAML, declares
read-only repository permissions, disables checkout credential persistence,
and invokes only `go run ./cmd/verify ci` in the Linux merge job. A separate
native Windows job first invokes the explicit security-critical
`TestWindowsNativeReplacementSecurity` suite without assuming elevated hosted
runner privileges, then unconditionally invokes `go run ./cmd/verify fast`
with `always()` for the complete native Go test suite even when the focused
suite fails. The focused suite always covers restricted-token
owner/group/DACL preservation and optional full-tier fallback; it covers
full-descriptor/SACL preservation when the host proves that capture, apply,
and verification are available. It also covers privilege restoration and
descriptor freeing, exclusive update/cleanup locking, file-ID revalidation,
hard-link/reparse rejection, non-delete-sharing source handles and exact-object
handle renames, fail-closed canonical-name substitution while a hostile handle
withholds delete sharing, exact-object recovery after handle release, late
target/stage hard-link recovery after link removal, explicit owner-only
protected lock/state DACLs, rejection of valid-CRC forged, inherited/writable,
and wrong-owner control state, descriptor-bound versioned state and legacy
record rejection, same-File-ID descriptor mutation rejection, compiled startup
refusal while hostile sharing blocks prepared recovery, completed and
unexplained stale rollback states, concurrent updaters, ordinary rollback, and
rollback-failure evidence and retry.
The same focused native suite classifies absent, verified-new, and
attacker-canonical dual refusal as `update_recovery_required`, exercises
startup human, JSON, and compact NDJSON rendering, proves successful recovery
restores the exact original and clears state, and compares `FileIdInfo`,
SHA-256, descriptor binding, bytes, and mode for every ordinary injected
failure. The inherited `unit` action keeps these machine-policy and compiled
contract tests in both the `ci` and `release` profiles; no publishing action or
workflow permission changes are required.

Tests
that execute a Unix remote shell or compare Bash script behavior are selected
only on Unix; portable parsing, planning, host-key, environment-isolation, and
security tests remain active on Windows.
The complete reviewed workflow is checked in as a test golden, with semantic
assertions for both jobs, exact setup action versions, exact adapter
invocations, job permissions, and checkout credential handling. The driver
does not install packages or acquire permissions.

## Profiles

`fast` is a convenience-only local loop, in this order:

1. `format`
2. `vet`
3. `unit`

It is deliberately not merge-equivalent and not release-equivalent.

`ci` is the ordered 11-check profile in the table above. `race` is conditional
on a natively supported OS/architecture, `CGO_ENABLED=1`, and an available C
compiler, and is explicitly required in the `github_actions_linux` context.
Its reviewed command sets Go's suite timeout to 15 minutes so the complete
race suite is not cut off by Go's 10-minute default.
It is truthfully unavailable on unsupported native tuples such as
Windows/arm64; cross-compilation is not treated as runtime race evidence.
`ssh-matrix` is
conditional locally and explicitly required in the `github_actions_linux`
context. Official GitHub CI prepares and asserts every live-matrix
prerequisite, including `/run/sshd`, one selected SSHD executable, and the SFTP
subsystem path. SSHD selection is an ordered alternative: an explicitly set
`SSHD` must be an executable regular file; otherwise an executable PATH
`sshd` is selected; otherwise executable regular file `/usr/sbin/sshd` is the
fallback. Any one is sufficient, and an invalid explicit override fails
without falling through. Official Linux CI selects, asserts, and exports that
same executable before running the profile. A local non-Linux machine, or a
local machine missing a declared live-matrix prerequisite, reports
`ssh-matrix` as `unavailable` and the profile as
`completed_with_unavailable`; neither is represented as passed.

The executable `release` check list begins with the exact `ci` sequence and
then adds, in order:

1. source release-version validation using the release workflow's exact
   ASCII-digit `X.Y.Z` grammar;
2. temporary builds named `ssm-linux-amd64`, `ssm-linux-arm64`,
   `ssm-darwin-amd64`, `ssm-darwin-arm64`, `ssm-windows-amd64.exe`, and
   `ssm-windows-arm64.exe`;
3. updater selection tests for those same six names;
4. a non-empty `RELEASE_NOTES.md` section matching the source version;
5. `sh -n install.sh`, because the release workflow publishes that installer;
6. in-memory SHA-256 computation for the six assets and `install.sh`;
7. synthetic, test-owned keyless provenance generation and verification for
   every temporary release asset;
8. pinned certificate and statement identity, exact one-subject/one-SHA-256
   digest binding, and byte-preserving provenance failure tests through the
   updater's production verifier core;
9. updater checksum selection, mismatch, and no-replacement failure tests.

No separate check called “release source policy” is added. The live Issue #18
acceptance text names the current source/version check, and the accepted
architecture audit names source/tag version matching; neither defines a
distinct source-policy phrase or bounded rule. The existing release workflow's
remote-tag identity check also requires a selected tag, while this ticket's
non-publishing `verify release` interface has no tag input. Inventing a new
trust rule here would conflict with the audit's explicit non-goal of changing
updater trust or release signing. The exact ASCII `X.Y.Z` source-version gate
therefore remains the authoritative bounded source check for Issue #18.

The release profile still exposes `migration-extension` metadata. BC-9
promotes the former `provenance-extension` metadata to two required executable
checks: `release-provenance` and `provenance-failure-paths`. Their generated
roots, certificates, signed statements, and executable subjects are
test-owned and remain inside verifier-controlled temporary storage. The
initial v2 release remains blocked on the separate migration extension.

Accordingly, the exact command

```sh
go run ./cmd/verify release
```

returns zero only when all executable release-preflight checks, including the
BC-9 provenance gates, pass.
Its terminal summary is `preflight_passed`, and its profile purpose and
equivalence explicitly name required pinned-provenance verification. This is
still not a claim of initial-v2 readiness until the remaining migration
extension is promoted.

No approved top-level action merges, tags, installs, replaces an executable,
creates or uploads a release, or writes release artifacts into the repository.
Verification children receive no inherited publication credentials or user
configuration that could supply publication authority. GitHub release
publication remains explicit in `release.yml` and outside this verification
driver. That workflow defaults to `contents: read`; its credential-free
preflight checkout runs the actual `go run ./cmd/verify release` profile.
Tag-triggered publication reads `GITHUB_REF_NAME` as quoted data, requires the
workflow identity to contain that exact tag, and requires the tag to match the
exact `vMAJOR.MINOR.PATCH` grammar before the step writes any release outputs.
Builds depend on that preflight and use the same six exact names and
`-buildvcs=false` flags. The build job alone has explicit identity-token,
attestation, and artifact-metadata write permission. It attests each exact
build output before uploading the binary and adjacent bundle together. Only
the final `publish` job has `contents: write`, and it depends on both preflight
and build. Exact checksum inputs, provenance subjects and names, release-note
extraction, published files, permissions, and job dependencies are covered by
semantic tests and a complete workflow golden.

## Prerequisites and runtime

Required prerequisites are listed in the manifest:

- a Git worktree with no non-ignored untracked paths when execution starts;
- a fully populated, non-sparse stage-0 index containing only regular
  `100644` or `100755` tracked files (tracked symlinks, gitlinks, unmerged
  stages, sparse `skip-worktree` state, missing paths, and nonregular paths
  fail with distinct layout diagnostics);
- source local/worktree Git configuration with no includes or executable
  command authority: fsmonitor, clean/process/smudge filters, external
  diff/textconv/merge commands, hooks paths, credential helpers/askpass,
  SSH/proxy commands, extra headers, URL rewrites, and push URLs fail closed;
- Go 1.25.12 and the gofmt executable from that same resolved toolchain;
- the official golangci-lint 2.11.4 prebuilt;
- the `v1.2.0` lint baseline tag/ref resolving to a commit for profiles that
  include lint;
- `jq` and `bash`;
- the repository modules and govulncheck module available through a reviewed
  unauthenticated public Go resolution policy or the reusable verifier cache.

Files declared `tracked` are verified through Git, not merely by filesystem
presence. Verification enumerates index modes and every tracked worktree path,
then safely copies the current regular-file contents into a private
profile-owned action workspace. This preserves safe tracked working-tree
modifications. On Unix, execute permission comes from the safely opened
working-tree source, preserving both dirty additions and dirty removals rather
than restoring the index mode. Windows has no corresponding working-tree
execute bit and does not invent one. The verifier does not use an archive that
would silently substitute index or HEAD content. The action workspace
contains no `.git` entry, non-ignored untracked paths are rejected before
copying, and ignored local files are never copied. Every command and builtin
executes from that workspace, so repository-local checkout credentials and
Git config are not visible to actions. The created profile root is resolved,
privacy-restricted, and rejected (with cleanup) if it is inside or aliases the
source repository, including through symlinks or Windows reparse points.
Action and action-prerequisite environments set an explicit Git discovery
ceiling at the private profile root, so a workspace cannot discover any parent
repository.

A symlink or reparse point in any tracked path component, or a tracked leaf
that is missing or not a regular file, fails the profile. Unix uses
descriptor-relative `openat` with `O_NOFOLLOW` and nonblocking leaf opens;
Windows uses `NtCreateFile` with `OBJ_DONT_REPARSE`; other targets without a
truthful no-follow primitive fail closed. Native Windows CI tests ordinary
files, leaf and parent reparse points, nonregular leaves, cleanup, and handle
lifetime. The source-version, release-note, checksum, and workspace-copy
readers use the same no-follow regular-file handles instead of a
check-then-open sequence.

Verification separately uses Git name/status metadata to reject every
non-ignored untracked path. It never opens, follows, or hashes untracked or
ignored file contents. Ignored files such as `master.pass`, `cloud.json`,
tokens, and private keys remain untouched and unread.

The original repository is revalidated and snapshotted immediately before and
after every action, and once more at profile completion. The action workspace
is independently snapshotted around each action; any retained file, path,
content, type, permission, or modification-time mutation fails before the next
action runs.
This is mutation detection around trusted verification actions, not a
read-only mount or universal OS sandbox. A hostile process that mutates and
perfectly restores state wholly between observations is outside this control;
the verifier makes no stronger claim.

The repository snapshot covers the HEAD object and symbolic name; every ref
returned by unrestricted `git for-each-ref --sort=refname`, including notes,
stash, and custom namespaces; stage entries, assume-unchanged/skip-worktree and
fsmonitor-clean flags, resolve-undo records, raw main/shared-index hashes, and
staged diff; tracked worktree content diff; and non-ignored untracked names.
This detects allow-empty commits, any ref change, index extension/flag changes,
further edits to already-dirty tracked files, and created or removed
non-ignored untracked names without reading their contents.

Every verification subprocess, including Git metadata and prerequisite probes,
receives a minimal explicit environment rather than the caller's environment.
Every source-repository Git command goes through one hardened boundary. Before
each capable operation it inspects common and linked-worktree configuration
with `--no-includes`, rejects command-bearing authority, isolates system/global
configuration, and disables optional locks, fsmonitor, hooks, credential
prompting, and helpers as applicable.
Each profile owns temporary HOME, XDG config/data/state/cache, temp, and linter
cache directories. A dedicated reusable verifier-owned Go build/module/GOPATH
cache lives outside the repository. Unix cache components are restricted and
verified as mode `0700`; Windows cache components receive and verify a
protected, inheritable DACL containing exactly one full-control ACE for the
current process user. Existing expected components are repaired and
reverified on every run, and an ACL/mode setup or verification error fails
closed. A Windows cache on a different volume remains valid when it is outside
the repository. Repeated developer runs therefore remain warm without
exposing caller configuration or credential directories. Git system/global
config and credential prompts are disabled;
`GOENV` is disabled. Go resolution is fixed to
`GOPROXY=https://proxy.golang.org,direct`, `GOSUMDB=sum.golang.org`, and empty
private/no-proxy/no-sumdb patterns; caller `GOPROXY`, `GOPRIVATE`,
`GONOPROXY`, `GONOSUMDB`, `GOENV`, and other module settings are not inherited.
The reviewed inherited set is limited to PATH, necessary Windows runtime
values, locale/timezone, certificate paths, and the validated SSHD override.
Variables such as GitHub/GH tokens, Git credential
injection, SSH agent sockets, cloud credentials, netrc, registry credentials,
cookies, API keys, and unknown caller variables are not inherited.

Every Go-dependent action declares the machine-readable
`repository-modules=go-mod-download` prerequisite. The verifier evaluates each
unique prerequisite once in the action workspace and reusable cache before its
action. A cold offline cache therefore fails as an unavailable prerequisite;
the same cache succeeds offline after deterministic population. Govulncheck's
pinned module has its own deterministic download prerequisite.

This is a no-inherited-publication-authority boundary, not a universal network
or filesystem sandbox. Unauthenticated network reads needed for Go modules and
govulncheck, plus the loopback live SSH matrix, remain permitted. Repository
tests still execute as trusted checked-in verification code, but receive
neither caller credentials nor caller user configuration.

The live SSH matrix is conditional locally on Linux and its complete audited
external-tool list: `awk`, `bash`, `cat`, `chmod`, `cp`, `dd`, `dirname`,
`find`, `go`, `grep`, `head`, `id`, `ln`, `mkdir`, `mktemp`, `nohup`,
`printenv`, `rm`, `script`, `sed`, `seq`, `sh`, `sha256sum`, `sleep`, `ssh`,
`ssh-keygen`, `touch`, `tr`, and `wc`. The selected SSHD executable is represented by
the alternatives prerequisite rather than falsely appearing as a conjunctive
PATH tool. `jq` is a JSON-artifact prerequisite, not an SSH-matrix
prerequisite. Bash builtins such as `cd`, `command`, `echo`, `kill`, `printf`,
`pwd`, `set`, `test`, `trap`, and `true` are not misrepresented as external
tools. The manifest and official Linux CI also assert readable `/dev/null` and
`/dev/zero`, `/run/sshd`, the selected server executable, and the SFTP
subsystem path. Tests keep the script declarations, manifest alternatives,
and workflow selection in exact parity.

The matrix uses only a temporary test home, temporary keys, a temporary
OpenSSH server, and a temporary binary. The daemon is started by retrying
actual localhost binds, eliminating the free-port-probe/start gap. Timeout and
resume cases use a fixture-owned throttled remote reader and one-second
deadlines with payloads larger than SSH channel buffering, rather than
scheduler-sensitive 1–2 ms timing. It does not read the user's vault, master
password, sync configuration, tokens, private keys, or decrypted inventory.
Failure to remove any profile temporary directory makes the profile failed and
nonzero. The CLI derives its context from interrupt/termination signals and
threads it through actions, prerequisites, Git probes, and snapshots. Each
subprocess owns only its descendants. On Linux, each command starts through a
dedicated supervisor that becomes a child subreaper and verifies pidfd support
before launching the target. A startup pipe handshake confirms that ownership is
established. On cancellation or normal root completion, the supervisor uses
stable pidfds to terminate its direct children, reaps them, and repeats until
the kernel reports that no adopted generation remains. The verifier process
itself never becomes a subreaper. Windows assigns the suspended root to a
kill-on-close Job Object before resuming it; a separate stable root-process
handle triggers Job termination and waiting before inherited output pipes are
allowed to hold command completion open. Darwin and other Unix targets fail
closed before target launch because this implementation cannot guarantee exact
ownership with a stable process identity there. Cleanup finishes before the
final bounded repository/workspace snapshot and temporary-directory removal.

The supported six-platform release target table is owned by
`internal/releaseasset`. Manifest asset builds, checksum verification, and the
production updater selector consume that same table/name function; direct
parity tests compare every manifest output and release-workflow matrix,
checksum list, and publication input with the updater selector.

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
