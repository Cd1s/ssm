# Review Findings

This document records the review evidence for the OpenSpec change
`improve-review-debug-feature-workflow`.

## Fixed Bugs And Risks

### Malformed `known_hosts` was trusted

- Area: `internal/ssh`
- Symptom: when `known_hosts` existed but could not be parsed, the callback fell back to accepting and saving the presented host key.
- Risk: a corrupted or malformed host-key database weakened host-key verification.
- Fix: malformed or unreadable `known_hosts` now rejects the key with explicit context; a missing file still uses trust-on-first-use.
- Regression coverage: `TestHostKeyCallbackRejectsMalformedKnownHosts`, `TestHostKeyCallbackSavesUnknownHost`.

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

### `cloud.json` save failed in a fresh config directory

- Area: `internal/cloud`
- Symptom: noninteractive login/register could fail to save sync config if `~/.config/ssm` did not already exist.
- Risk: first-run headless setup was brittle.
- Fix: `SaveCloud` now creates the config directory with `0700` before writing `cloud.json` as `0600`.
- Regression coverage: `TestSaveCloudCreatesConfigDir`.

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
- missing connection diagnostics
- `known_hosts` creation

## Remaining Risks

- Interactive `sshctl shell` and the multi-tab TUI session manager still require terminal/manual validation for full-screen behavior.
- CI prepares `openssh-server` before the SSH matrix; the matrix still assumes an Ubuntu-like runner with `/usr/lib/openssh/sftp-server`.
- Release publication still requires an explicit tag push approval; this work only prepares the `v1.0.1` release notes draft.
