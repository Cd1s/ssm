# Review Findings

This document records the review evidence for the OpenSpec change
`improve-review-debug-feature-workflow`.

## Fixed Bugs And Risks

### Manual release workflow could publish a non-version build

- Area: `.github/workflows/release.yml`
- Symptom: a `workflow_dispatch` run derived the binary version from `GITHUB_REF_NAME`, which is a branch name for manual runs rather than a release tag.
- Risk: release assets could be built with a non-semver version or attached to an unintended release target, making updates hard to audit.
- Fix: manual release now requires an explicit `vMAJOR.MINOR.PATCH` tag input, validates existing tags point at the current commit, shares a single prepared version with every matrix build, and passes `tag_name`/`target_commitish` to release creation.
- Regression coverage: workflow shell syntax is simple bash, release assets are constrained to platform binary globs, and final validation will use a real GitHub release run.

### Update download replaced binaries without checksum verification

- Area: `internal/update`, `install.sh`, `.github/workflows/release.yml`
- Symptom: `ssm update` downloaded a release asset and replaced the current executable without checking it against `checksums.txt`; `install.sh` also installed the downloaded asset without verification.
- Risk: a truncated or tampered release asset could be installed if the HTTP request succeeded.
- Fix: update downloads `checksums.txt`, extracts the current platform asset hash, streams the binary through SHA-256 verification, and only renames the new executable after the checksum matches. The installer performs the same checksum check before install, and release checksums now include only binary assets.
- Regression coverage: `TestDownloadVersionVerifiesChecksumBeforeReplace`, `TestDownloadVersionReplacesAfterChecksumMatch`, `TestChecksumForAsset`, `TestCopyAndVerifyRejectsChecksumMismatch`; `bash -n install.sh`.

### Update replacement used a fixed temporary filename

- Area: `internal/update`
- Symptom: update wrote to `<current executable>.new`.
- Risk: concurrent updates or stale temp files could collide with each other and make failures harder to diagnose.
- Fix: update now writes to a unique temp file in the executable directory and removes it on every failed path.
- Regression coverage: `TestDownloadVersionVerifiesChecksumBeforeReplace`, `TestDownloadVersionReplacesAfterChecksumMatch`.

### Vault and sync writes used fixed or direct file replacement paths

- Area: `internal/config`, `internal/cloud`, `internal/syncserver`, `cmd/ssm`
- Symptom: several secret-bearing files were written directly or through fixed `.tmp` paths: local vault saves, cloud pulls, remote ETag cache, settings, password cache, sync server user data, sync blobs, and cloud merge rollback.
- Risk: interrupted writes could leave partial files, fixed temp names could collide, and permission handling was spread across call sites.
- Fix: local secret/config writes now use a shared `config.WritePrivateFile` helper with `0700` directories, unique temporary files, `0600` file mode, rename-on-success, and cleanup on failure. Sync server opaque blob/user writes use the same pattern locally without decrypting blob contents.
- Regression coverage: `TestSaveWritesVaultAtomicallyWithPrivatePermissions`, `TestSettingsAndPasswordCacheUsePrivateFiles`, `TestPullWritesVaultAndRemoteETagPrivately`, `TestServerStoresPrivateFiles`.

### JSON imports accepted invalid ports and negative expected counts

- Area: `cmd/ssm import-json`
- Symptom: JSON numeric ports such as `22.5` were truncated to `22`, out-of-range ports could be saved, and `--expect-count=-1` disabled the count guard.
- Risk: headless imports could silently create unusable SSH entries or bypass an operator's import-size sanity check.
- Fix: import ports must now be integer values in the TCP range `1..65535`, and `--expect-count` must be non-negative.
- Regression coverage: `TestParsePortRejectsFractionalAndOutOfRangeValues`, `TestParseImportJSONArgsRejectsNegativeExpectCount`.

### Global master password flag parsing lacked direct unit coverage

- Area: `cmd/ssm`, `sshctl`
- Symptom: `--master-pass-file` parsing is shared by `ssm` and `sshctl`, but the headless noninteractive path had no focused unit test.
- Risk: future argument parsing changes could break `SSM_MASTER_PASS_FILE`/global flag behavior required by agent workflows.
- Fix: added focused tests for extracting `--master-pass-file` and rejecting missing paths without changing command behavior.
- Regression coverage: `TestParseGlobalArgsExtractsMasterPassFile`, `TestParseGlobalArgsRejectsEmptyMasterPassFile`.

### Cloud client accepted missing bearer tokens

- Area: `internal/cloud`
- Symptom: sync requests could be constructed with an empty token and sent as `Authorization: Bearer `.
- Risk: misconfigured headless clients produced lower-signal server errors and made token setup harder to diagnose.
- Fix: push, pull, remote hash, and verification requests now fail locally with a secret-safe "cloud token is not configured" error before constructing authenticated requests.
- Regression coverage: `TestCloudRequestsRequireToken`.

### Cloud client could return empty server error messages

- Area: `internal/cloud`
- Symptom: an error response such as `{"error":""}` returned an empty error string.
- Risk: users and agents could see `Error:` without actionable context.
- Fix: empty server error payloads now fall back to `server error (<status>)`.
- Regression coverage: `TestParseErrorFallsBackForEmptyServerError`.

### Cloud pull trusted empty or oversized response bodies

- Area: `internal/cloud`
- Symptom: `Pull` accepted any `200 OK` body from a sync endpoint and wrote it directly over the local vault path.
- Risk: a misbehaving or incompatible sync endpoint could replace the local vault with an empty blob, and an oversized body could consume memory before failing later.
- Reproduction: run `Pull` against an HTTP test server that returns `200 OK` with no body or a body larger than the configured pull limit.
- Root cause: the client mirrored the server write path but did not enforce the same non-empty opaque-blob and maximum-size boundaries on downloads.
- Fix: pull now reads through a bounded reader, rejects blobs larger than 64 MiB, rejects empty blobs, and only writes the vault after those checks pass.
- Regression coverage: `TestPullRejectsEmptyBlobWithoutOverwritingVault`, `TestPullRejectsOversizedBlobWithoutWritingVault`.

### Sync server auth and size limits needed explicit regression coverage

- Area: `internal/syncserver`
- Symptom: bearer auth and opaque blob size limits were implemented, but empty bearer tokens and oversized uploads lacked focused tests.
- Risk: future auth/storage changes could weaken request rejection or accidentally write partial oversized blobs.
- Fix: added tests that empty bearer tokens return 401 and uploads larger than `maxBlobBytes` return 413 without creating a vault blob.
- Regression coverage: `TestSyncRejectsEmptyBearerToken`, `TestSyncRejectsOversizedBlobWithoutWritingVault`.

### CLI error printing was not consistently secret-redacted

- Area: `cmd/ssm`, `sshctl`
- Symptom: `sshctl list` used redaction, but many other CLI paths printed raw `Error: %v`, including sync, update, vault, SSH, and panic recovery errors.
- Risk: malicious or unexpected error strings containing `password=...`, `token=...`, bearer headers, or private-key blocks could be copied into bug reports or logs.
- Fix: added shared `printError`/`redactString` helpers and routed CLI error prints through them; panic recovery, master-pass file errors, and cloud password-file errors now redact before printing.
- Regression coverage: `TestRedactStringRemovesSensitiveFields`, `TestRedactStringRemovesPrivateKeyBlocks`, `TestRedactErrorCoversSecretBearingPaths`.

### Malformed `known_hosts` was trusted

- Area: `internal/ssh`
- Symptom: when `known_hosts` existed but could not be parsed, the callback fell back to accepting and saving the presented host key.
- Risk: a corrupted or malformed host-key database weakened host-key verification.
- Fix: malformed or unreadable `known_hosts` now rejects the key with explicit context; a missing file still uses trust-on-first-use.
- Regression coverage: `TestHostKeyCallbackRejectsMalformedKnownHosts`, `TestHostKeyCallbackSavesUnknownHost`.

### Host-key save ignored directory creation failures

- Area: `internal/ssh`
- Symptom: `saveHostKey` ignored failures from `os.MkdirAll(filepath.Dir(path), 0700)` and then attempted to open the target file.
- Risk: when the known-hosts parent path was invalid, diagnostics pointed at the later open instead of the actual directory creation failure, making host-key setup harder to debug.
- Reproduction: call `saveHostKey` with a known-hosts path whose parent component is an existing regular file.
- Root cause: the directory creation error was discarded.
- Fix: `saveHostKey` now returns the `MkdirAll` error immediately.
- Regression coverage: `TestSaveHostKeyReportsDirectoryErrors`.

### Empty SSH auth produced poor diagnostics

- Area: `internal/ssh`
- Symptom: a connection with no password and no key reached `ssh.Dial` with no auth methods, yielding a low-context connection failure.
- Risk: agent/headless users could not quickly tell that the stored connection lacked auth material.
- Fix: auth construction now fails early with `no authentication configured`.
- Regression coverage: `TestBuildAuthRequiresConfiguredMethod`.

### Upload chmod ran after failed remote write

- Area: `internal/ssh`
- Symptom: upload command used `cat > path; chmod mode path`, so `chmod` ran even when the write command failed.
- Risk: noisy or misleading remote errors during `sshctl put`.
- Fix: upload command now uses `cat > path && chmod mode path`.
- Regression coverage: `TestUploadCommandRequiresSuccessfulWriteBeforeChmod`, `scripts/ssh_matrix_test.sh`.

### Session manager closed-state updates were not consistently locked

- Area: `internal/ssh`
- Symptom: session shutdown wrote `SSHSession.closed` before taking the session manager mutex, while resize and detach paths read it while holding that mutex.
- Risk: interactive multi-session SSH could develop a data race under concurrent session exit and terminal resize/detach, making full-screen behavior harder to debug.
- Reproduction: inspect `waitSession`, `resize`, and detach handling; the same field was accessed under different synchronization.
- Root cause: the done-channel close and closed flag update were not centralized behind the manager lock.
- Fix: closed-state updates now go through `markSessionClosedLocked`, making the flag/channel transition idempotent under the manager mutex.
- Regression coverage: `TestMarkSessionClosedLockedIsIdempotent`, `go test -race ./internal/ssh`.

### `cloud.json` save failed in a fresh config directory

- Area: `internal/cloud`
- Symptom: noninteractive login/register could fail to save sync config if `~/.config/ssm` did not already exist.
- Risk: first-run headless setup was brittle.
- Fix: `SaveCloud` now creates the config directory with `0700` before writing `cloud.json` as `0600`.
- Regression coverage: `TestSaveCloudCreatesConfigDir`.

### Interactive cloud auth ignored sync config save failures

- Area: `cmd/ssm`, `internal/cloud`
- Symptom: interactive `ssm register` and `ssm login` called `cloud.SaveCloud(cfg)` and discarded the returned error, while the noninteractive paths handled it.
- Risk: an account login/register could appear successful even though `cloud.json` was not written, leaving later sync commands with misleading "not logged in" failures.
- Reproduction: make the SSM config path unwritable during interactive login/register after the server returns a token; before the fix the save error was ignored.
- Root cause: interactive and noninteractive cloud auth paths had inconsistent error handling.
- Fix: interactive register/login now check `cloud.SaveCloud` and exit through the shared redacted error path on failure.
- Regression coverage: code review of the unified save-error handling plus `go test ./cmd/ssm`; TUI form interaction remains manually validated.

### Vault merge order was nondeterministic

- Area: `internal/config`
- Symptom: `MergeVaults` emitted map iteration order.
- Risk: merge diffs and reviews were noisy and nondeterministic.
- Fix: merge now preserves first-seen local order, appends new remote names, and still lets remote entries win conflicts.
- Regression coverage: `TestMergeVaultsKeepsStableOrderAndRemoteWinsConflicts`.

### Update checks lacked an explicit off switch

- Area: `internal/update`, README
- Symptom: tests and offline/headless runs had no documented environment value to disable release checks.
- Risk: startup could unexpectedly touch the network outside test intent.
- Fix: `SSM_UPDATE_REPO=off`, `none`, or `disabled` disables release repo resolution.
- Regression coverage: `TestReleaseRepoCanBeDisabledByEnvironment`.

### Partial settings files disabled enabled-by-default behavior

- Area: `internal/config`, `internal/update`, `internal/cloud`
- Symptom: `LoadSettings` unmarshaled JSON into a zero-value `Settings`, so a settings file missing `auto_update`, `auto_sync`, or `vim_keys` interpreted those booleans as `false`.
- Risk: older or hand-written settings files could silently disable auto-update or auto-sync even though defaults require those capabilities to stay enabled.
- Reproduction: write `{"password_cache":"session"}` to `settings.json`, then call `LoadSettings`; before the fix `AutoUpdate` and `AutoSync` were false.
- Root cause: boolean absence was indistinguishable from explicit `false` when loading directly into the final struct.
- Fix: settings now load by overlaying pointer fields onto `DefaultSettings`, preserving explicit `false` while keeping missing booleans enabled.
- Regression coverage: `TestLoadSettingsDefaultsMissingBooleansToEnabled`, `TestLoadSettingsPreservesExplicitFalseBooleans`.

## SSH Matrix

`scripts/ssh_matrix_test.sh` starts an isolated local `sshd` with temporary keys, temporary HOME, and a temporary SSM vault. It covers:

- simple command execution
- single-quoted command payloads
- double-quoted command payloads
- nested shell commands
- pipes and redirects
- stdin forwarding
- non-zero remote exit codes
- long-running commands
- persistent background scripts
- `sshctl put` upload
- `sshctl shell` under a pseudo-terminal smoke test
- missing connection diagnostics
- `known_hosts` creation

## Remaining Risks

- Interactive `sshctl shell` and the multi-tab TUI session manager still require terminal/manual validation for full-screen behavior.
- CI prepares `openssh-server` before the SSH matrix; the matrix still assumes an Ubuntu-like runner with `/usr/lib/openssh/sftp-server`.
- `zap-hosting-de` has the new binary installed and `sshctl --help` works, but `sshctl status` cannot unlock a vault there because `/root/.config/ssm/master.pass` is absent; creating or copying that secret is outside this review.
