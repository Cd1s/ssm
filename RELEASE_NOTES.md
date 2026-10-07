# Release Notes

These notes are the reviewed contract for the authorized stable v2.3.0
Release. The official exact-tag workflow publishes it non-latest first with
`make_latest=false`; v2.2.0 remains GitHub latest until published-asset
canaries pass and a separate promotion is made. See the
[v1→v2 migration guide](docs/migration-v1-to-v2.md) and
[update-provenance runbook](docs/update-provenance-runbook.md) for operator and
maintainer gates.

## v2.3.0

This is a v2 minor release. The official exact-tag release workflow creates
the stable v2.3.0 Release with `make_latest=false`; v2.2.0 remains GitHub
latest until published-asset canaries pass and a separate promotion is made.
Ordinary `ssm update` stays within v2.

### `sshctl tunnel`

- `sshctl tunnel` provides foreground `-L` local port forwarding and `-D`
  dynamic forwarding. It reuses the existing connection path, so host-key
  verification and `proxy_jump` continue to apply.
- Local listeners bind to loopback by default. A non-loopback bind requires
  both `--allow-remote-bind` and `--yes`.
- `--ready-file` writes readiness state, and `--duration` bounds the
  foreground lifetime. Readiness and termination each produce one JSON line
  when JSON output is selected.
- An SSH disconnect exits the tunnel; it does not reconnect automatically.
- New error codes are `tunnel_invalid_arguments`, `tunnel_bind_failed`, and
  `tunnel_remote_bind_refused`.
- This release does not include `-R`, a background daemon, or automatic
  reconnect.

### Important update fix: Alpine and gcompat

Older `ssm update` versions could write the new version onto the system C
library on Alpine with gcompat (`/lib/ld-musl-x86_64.so.1`), causing most host
programs to crash with segmentation faults. The updater now replaces only a
file named `ssm` or `sshctl`; otherwise it refuses and explains the reason
without changing any file.

On Alpine, do not use `ssm update` to upgrade from v2.2.0 or earlier: those
versions contain this defect. Download the matching release asset manually,
verify its SHA-256, and replace the binary. After upgrading to v2.3.0,
`ssm update` is safe.

### Sync server token history

Each account now retains 256 login-token hashes instead of 16. With 16
machines under one account, logging in on one more machine could evict another
machine's token and make its next sync fail with HTTP 401. Deploy the new
`internal/syncserver` server for this change to take effect.

There is no request-schema or JSON-field breaking change; no request schema or
JSON field has a newly added or changed breaking form.
The checked range has no request-schema file changes; request and result
additions remain additive. Error codes are additive: these tunnel codes are
new, and existing codes are unchanged.

### Changes since v2.2.0

- Added foreground SSH tunnel forwarding and its lifecycle/error contracts.
- Fixed tunnel half-close handling so replies are not truncated.
- Fixed updater executable lookup and refusal to replace foreign executables.
- Increased sync-server login-token history from 16 to 256.

## v2.2.0

This is a v2 minor release containing all fixes from PR #120 (the reviewed
commits in `6431cae..c77ffdf`). It **changes some default behavior** and has a
vault-format compatibility requirement. The official exact-tag release
workflow creates the stable v2.2.0 Release with `make_latest=false`;
v2.1.0 remains GitHub latest until published-asset canaries pass and a separate
promotion is made. Ordinary `ssm update` stays within v2.

### Upgrade before saving or publishing (read first)

- **Vault format v2 encryption.** New vaults use an authenticated monotonic
  generation. Older clients (v2.1.0 and earlier) cannot read a v2-format vault;
  upgrade all machines to v2.2.0 before any machine saves or publishes one.
  v2.2.0 continues to read old-format vaults.
- **Conditional sync publication.** The sync server now checks `If-Match` and
  `If-None-Match` preconditions on uploads. If two machines upload at once,
  only one succeeds and the other receives `sync_conflict`. A new client can
  still push to an old server, but that server cannot provide this protection.
  If the local `remote.etag` cache is missing while a remote vault exists, push
  first requires `sync` or `pull`.
- Deploy the new `internal/syncserver` before relying on the upload checks.

### User-visible changes

- A push whose scope no longer matches an interrupted publication fails as
  `sync_push_failed` (exit 1), and it does not publish extra inventory.
- A downloaded vault that fails authentication is rejected and the existing
  `connections.enc.prev` is retained.
- A client that has never synchronized reports empty `last_pull` and
  `last_sync` values.
- `password_cache` and `vim_keys` settings are ignored; `put` to an existing
  remote directory fails.
- If the server returns an older vault (a rollback), the client reports
  `sync_conflict`; review it and use `pull --adopt-remote` to adopt it.
- When `HOME` cannot be determined, startup errors and instructs the operator
  to set `HOME` or `SSM_CONFIG_DIR`.
- Credential files passed with `--password-file`, `--key-file`, `--secret`, or
  `--master-pass-file` that are readable by other users produce a warning.
  Set `SSM_NO_PERMISSION_WARNING=1` to suppress it; Windows does not warn.
- `get` directory downloads reject device files and remove special permission
  bits. Cloud clients reject cross-host or downgrade redirects.
- `status` reuses one unlock and completes faster.

There is no new error code and no request-schema or JSON-field breaking
change. The checked range has no request-schema file changes
(`git diff 6431cae..c77ffdf --stat -- skills/agent-ssm/references/*.json` is
empty); result and request additions remain additive.

## v2.1.0

This is a v2 minor release. It fixes the agent-experience issues from the
2026-09 usage audit (tracking issue #89) and **changes some default
behavior and some error codes**. Only some of the changes have a
compatibility switch; the lists below say which. The official exact-tag release workflow created the stable v2.1.0
Release with `make_latest=false`; after the published-asset canaries passed,
the authorized latest-promotion step made v2.1.0 GitHub latest. Ordinary
`ssm update` stays within v2 and installs the highest stable release of the
installed major (it does not consult the GitHub latest flag), so same-major
`ssm update` (including automatic update) adopts these defaults on existing
installs; it already did so before the latest flag moved. If a fleet needs the old behavior, pin
`sync_mode: strict` and `SSM_RUN_OUTPUT=buffered` first.

### Default behavior changes (read before upgrading)

- **Local-first inventory (#72).** Read commands (`run`, `map`, `get`, `put`,
  `check`, `doctor`, `list`, `host list|show`, `host-key`, `keys`, `status`)
  read the local vault and no longer contact the sync server first; a sync
  server outage no longer fails them. Automatic sync runs in a detached
  background process, rate-limited (`sync_interval`, default 10m) with
  exponential backoff (30s doubling to 1h). `status` reports freshness
  (`remote_state`, `last_successful_sync`, `last_sync_error`,
  `next_sync_attempt`, `cache_age_seconds`, `inventory_stale`,
  `inventory_unsynced`); inventory older than `stale_after` (default 7d) is
  reported stale. `run` JSON adds `inventory_stale`, `inventory_unsynced`,
  `inventory_sync_error`. **Restore the v2.0.2 behavior** with
  `"sync_mode": "strict"` in `settings.json` or `SSM_SYNC_MODE=strict`.
  `--offline` is deprecated for reads (it now only suppresses background
  sync); `SSM_OFFLINE=1` is equivalent. `login` now fetches the inventory
  immediately. Local vault mutations and every pull (explicit `sync`/`pull`,
  strict-mode refresh, background) take a short vault write lock; a
  concurrent writer can produce a bounded (5s) "vault is busy ... retry"
  failure.
- **Streaming human-mode `run` output (#71).** Output is streamed as it
  arrives instead of being held until the command exits (no more 8 MiB
  per-stream limit); stdout is byte-exact, stderr is redacted line by line.
  `--json` still returns one complete value. `SSM_RUN_OUTPUT=buffered`
  restores the previous buffering. Local SIGINT/SIGTERM/SIGHUP are forwarded
  to the remote command (`interrupted`, exit 128+signal).
- **Connect timeout covers the SSH handshake (#73).** `--connect-timeout`
  (default 15s) bounds TCP connect plus the SSH handshake and
  authentication; legacy `--timeout` on run/exec/plan/map/`--stream` is a
  deprecated alias of it (last flag wins; flags beat `SSM_CONNECT_TIMEOUT` /
  `SSM_TIMEOUT`). `put`/`get`/`cp` keep `--timeout` as the transfer timeout.
  See the lists below for the resulting error-code changes.
- **SSH keepalive on by default (#73).** `keepalive@openssh.com` every 15s;
  the connection is closed after 3 unanswered probes (`connection_lost`).
  `SSM_KEEPALIVE=0` disables it; `SSM_KEEPALIVE=<duration>` changes it and an
  invalid value falls back to 15s.

### Error-code changes (affects automation that matches `error`)

These replace codes that were too generic (`internal`) or split out a specific
cause. None has a compatibility switch. Exit 255 is the transport-failure exit
(`dial_*`, `connection_lost`, `handshake_failed`, `session_limit`).

- A dropped connection after the command was sent: `connection_lost`
  (stage `remote_execution`, exit 255, additive `outcome:"unknown"`) instead
  of `internal` (exit 1); a `put`/`get` whose connection breaks midway is
  `connection_lost` (exit 255) instead of `remote_write_failed` /
  `remote_read_failed` (exit 1) (#79).
- A handshake failure or stall after TCP connected: `handshake_failed` (stage
  `handshake`, exit 255) instead of `internal` or `dial_timeout` (#73, #79).
- Windows refused connection: `dial_refused` (stage `dial`, exit 255) instead
  of `internal` (exit 1) (#85).
- A session-limit wait that gives up: `session_limit` (stage `session`, exit
  255) instead of `session_failed` (#76).
- New codes: `exec_timeout` (exit 124), `remote_shell_unsupported` (exit 1),
  `sftp_unavailable` (exit 1) and `proxy_jump_invalid` (exit 2); `error`
  values that v2.0.2 never produced.

### Changes without a compatibility switch

Besides the error codes above:

- `--connect-timeout` (and request `timeout` on run requests, `--timeout` on
  run/exec/plan/map) now also covers the SSH handshake and authentication,
  not only TCP connect. Mitigation: pass a larger `--connect-timeout`.
- CLI duration flags reject integers with trailing text (`30abc`) and other
  malformed values.

Changes that do have a switch: `sync_mode: strict` / `SSM_SYNC_MODE=strict`
(local-first reads), `SSM_RUN_OUTPUT=buffered` (streaming `run` output),
`SSM_KEEPALIVE=0` (keepalive), `--no-stdin` / `SSM_FORWARD_STDIN=0`
(stdin forwarding stays as before by default).

### New features

- `--exec-timeout` for run/exec/map/`--stream` and request-v1
  `exec_timeout`: SIGTERM at the deadline, 5s grace, `exec_timeout`, exit 124,
  `timed_out:true`, output so far kept (#73).
- Explicit stdin forwarding: `--stdin`, `--no-stdin`, `--stdin-file`,
  request-v1 `stdin_file`, JSON `stdin_forwarded`; defaults unchanged (#77).
- `--interpreter` for non-shell `-f` scripts and shebang-aware script errors (#81).
- Command and flag suggestions instead of `alias_not_found` for typos (#82).
- `--retry-dial N[:backoff]` (N at most 10, exponential backoff with jitter
  from `backoff`, default 250ms, capped at 30s) and `sshctl wait <alias>`
  (`--timeout`, `--interval`, `--until ssh|tcp`): retry only transport
  failures before the host key arrived; never retry authentication or
  host-key failures; one SSH connection per `wait` attempt (#85).
- SFTP transfers for targets without a POSIX shell (#87): `put`/`get --sftp`,
  host setting `--transfer auto|shell|sftp` (`host.transfer` in request v1,
  default `auto` through the shell path) and a per-operation request
  `transfer` field. SFTP handles single regular files only. New error codes:
  `remote_shell_unsupported` (stage `discovery`) and `sftp_unavailable`
  (stage `capability`).
- ProxyJump aliases (`host ... --proxy-jump <alias>`, `host.proxy_jump` in
  request v1; chains up to 5 hops, no cycles, otherwise `proxy_jump_invalid`,
  exit 2) with per-hop host-key verification and per-hop local credentials,
  an optional `via` field on failures, and `sshctl cp <a>:<path> <b>:<path>`
  (single regular file) relayed through this machine with three-way SHA-256
  verification. `cp --direct` is not implemented.
  **Upgrade every client before using `proxy_jump`:** v2.0.2 and older
  ignore the field and drop it if they re-save the synced vault.

### Fixes

- Security: Go 1.26.8, `golang.org/x/crypto` v0.56.0, grpc v1.83.1 (#69).
- `-h/--help` and `--json` inside remote argv are no longer captured by
  sshctl; `ssm pull --help` no longer performs a pull (#70, #75).
- host-key: a different recorded key type is no longer reported as a MITM
  mismatch; `accept` no longer deletes other key types (#74).
- Sync failures keep and classify their cause (`cause`) without exposing the
  server address (#78).
- Directory transfer error handling, `--sha256` digest-tool detection,
  `--dir-mode`, get/put option parity (#80).
- The connection pool keeps the shared connection when the server's session
  limit is reached and waits for a free slot (#76).
- Help, README and agent skill aligned with the actual flags and environment
  variables, enforced by a contract test (#83).

### Maintenance

- The test suite no longer requires the pinned toolchain, CI triggers were
  cleaned up, and a weekly `govulncheck` runs (#84, #88).

### Request schema (request v1, version stays 1)

Compared with v2.0.2, every change is additive, and no request that v2.0.2
accepted is now rejected (v2.0.2 already rejected unknown fields):

- New `run`/`plan` fields: `interpreter`, `exec_timeout`, `stdin_file`
  (`stdin_file` is not valid with `script_file`; `interpreter` only with
  `script_file`; `preflight:true` is invalid with a non-shell interpreter).
- New `put`/`get` fields: `transfer` (`auto|shell|sftp`); `dir_mode` on
  `put`. `get` now also accepts `sha256` and `timeout` (v2.0.2 rejected them).
- New `host` fields: `transfer` and `proxy_jump` (empty string clears it).
- Run-only fields (`interpreter`, `stdin_file`, `exec_timeout`) stay invalid
  on `put`/`get`; `transfer` is invalid on run, check, doctor and host ops.
- `op:get` itself is not new; it was added in v2.0.0.

There is no request-schema or JSON-field breaking change: new result fields
(`inventory_*`, `stdin_forwarded`, `via`, `outcome`, `timed_out`,
`dial_attempts`) are additive. The behavior changes are the default changes
and the error-code changes listed above; v2 compatibility behavior remains
available only through the switches named there.

## v2.0.2

This is a backward-compatible patch release containing the reviewed v2.0.2
repair work:

- add explicit, identity-checked reviewed remote adoption for true
  no-transaction divergence;
- honor `SSM_CONFIG_DIR` for the encrypted vault and private sidecars;
- keep ordinary pull fail-closed and preserve the v2.0.1 public contract.

The official exact-tag release workflow created the stable v2.0.2 Release with
`make_latest=false`; after the published-asset canaries passed, the authorized
latest-promotion step made v2.0.2 GitHub latest.

## v2.0.1

This is a backward-compatible patch release. The official exact-tag release
workflow creates the stable v2.0.1 Release with `make_latest=false`; v2.0.2 is now GitHub latest after the published candidate
assets and canaries passed.

- Fix fresh installation with GitHub CLI 2.92.0. `gh attestation verify`
  requires attestation bundle files to have a `.json` or `.jsonl` suffix;
  `install.sh` now downloads the bundle into a private `mktemp` directory as
  `attestation.json` and removes the file and directory on both success and
  failure.
- There is no protocol or schema breaking change, and v2 compatibility
  behavior remains unchanged.

## v2.0.0

This section is prepared for the authorized stable v2.0.0 Release. The exact-tag
release workflow may publish it only with `make_latest=false`; v1.4.4 remains
GitHub latest. All child tickets through Issue #31 are closed and the #31 final readiness
proof is an executable, non-publishing `verify release` profile whose
final `v2-readiness-report` check validates the checked-in evidence map against
the live manifest. BC-1 through BC-10 are the approved compatibility migration
rows; their [complete field-level old/new/action/machine/rollback matrix](docs/migration-v1-to-v2.md#bc-contract-matrix)
is part of this release contract. Verification is non-mutating and does not publish
a tag or release. Only the official exact-tag release workflow may
publish after every source release blocker, migration review, pinned provenance
check, rollback rehearsal, native CI gate, and independent review passes.

### Pinned release provenance

- The updater contract requires automatic and manual same-major updates,
  explicitly authorized major migrations, and installer replacements to carry both the selected
  SHA-256 digest and keyless provenance for the exact downloaded asset.
- Provenance is pinned to `Cd1s/ssm`, the reviewed release workflow identity,
  GitHub Actions' OIDC issuer, the supported six-target manifest, and the
  reviewed identity-rotation state. Missing, malformed, unverifiable,
  wrong-subject, or expired provenance leaves the existing executable intact.
- The official release build publishes one adjacent Sigstore bundle per binary.
  Checksums remain an independent digest input but cannot authorize replacement alone.
- Redirected and unknown-length release responses are streamed through exact
  1 MiB metadata/provenance, 16 KiB checksum, and 64 MiB binary ceilings.
- The installer uses a same-directory staging template accepted by both
  GNU and macOS/BSD `mktemp`. Windows self-update renames the mapped old image
  aside under an exclusive same-directory update lock, installs the
  identity-checked sibling stage synchronously, and rolls back bytes and
  security on failure. Ordinary users preserve and verify owner, primary
  group, DACL, and DACL inheritance; tokens that can enable all three Windows
  backup/restore/security privileges also preserve the complete descriptor.
  A later launch removes only an identity-bound completed rollback image.
- On a trust failure, keep using the preserved executable and wait for a
  repaired release through a reviewed identity. Installer users need a current
  GitHub CLI with attestation verification and `head -c`; there is no
  verification skip.

### Reviewed saved-key publication

- The v2 publication preflight rejects unsatisfied cross-alias saved-key
  create, replace, rename, delete, prune, and reference prerequisites before
  any sync request.
- The safe failure message lists every required stable transaction ID in
  ledger order with alias, operation, key name, and reason. Publish those IDs
  explicitly in order, then retry the original transaction; SSM never adds
  prerequisites or unrelated pending mutations to the selected scope.
- Modern direct and request-v1 host mutations retain their existing encrypted
  vault/ledger schema, transaction ID format, and typed success fields. Legacy
  remove, saved-key removal, and guarded import now append pending transactions
  without automatic publication.
- A state-changing host mutation returns a stable `transaction_id`. An
  idempotent update/upsert can instead return `changed:false`,
  `action:"unchanged"`, with `transaction_id` omitted; it creates no new
  transaction, so do not publish it.

### Exact push scopes and empty-ledger safety

- Bare `push` is invalid and is rejected before vault unlock or any sync HTTP
  request. Callers must choose `sshctl --json push --only <transaction-id>` or
  `sshctl --json push --all`.
- `sshctl --json push --all` publishes only the invocation-start ordered pending-ID snapshot;
  later transactions remain pending.
- An empty `push --all` performs one identity HEAD and no GET or PUT. Identical
  local, cached, and remote encrypted-blob identities return `action:"noop"`;
  any missing or different identity returns a safe `sync_conflict`, preserves
  both blobs and private identity evidence, and never publishes a full blob.
- English, Chinese, agent-skill, command-help, and recovery guidance now use
  only explicit publication scopes.
- The empty-ledger `sync_conflict` hint recommends the guarded `--merge`
  recovery path. It does not suggest `--replace --yes`; the longer recovery
  guide permits replacement only after explicit full-replacement review.

### Complete v2 compatibility migration

- **BC-1:** a present malformed or unreadable `cloud.json` is a fatal
  `sync_config_error` for every online inventory operation. Missing remains
  unconfigured; explicit global `--offline` alone accepts cached state and
  performs no cloud parsing or network access.
- **BC-2:** exact scoped publication preflights transitive alias and saved-key
  prerequisites without automatically adding them. Publish the listed stable
  IDs explicitly in ledger order.
- **BC-3:** stream startup and terminal failures use compact NDJSON from the
  first byte. After initialization, each consumed non-empty input line has one
  ordered result; no ready, summary, or footer record is emitted.
- **BC-4:** state-changing inventory entry points, including legacy remove,
  saved-key removal, and guarded import, create stable pending transactions and
  never auto-publish. A preserved idempotent host no-op has `changed:false`,
  `action:"unchanged"`, omits `transaction_id`, and creates no transaction.
- **BC-5:** bare push is invalid, non-empty `--all` fixes its ordered scope at
  invocation start, and empty `--all` never performs a PUT.
- **BC-6:** online streams require a positive refresh interval. Zero refresh
  is valid only with explicit global offline mode and one fixed cached
  snapshot.
- **BC-7:** direct and request-v1 file/directory put/get results have matching
  `direction`, `kind`, and `stage`. Directory operations report
  `atomic:false`, `integrity:not_available`, and `resume:unsupported`;
  directory get omits `bytes_received` rather than inventing a tar byte count.
- **BC-8:** automatic and ordinary manual replacement remains within the
  installed major. `ssm update --major` reviews the migration and
  `ssm update --major --yes` is the sole non-interactive major authorization.
- **BC-9:** checksums cannot authorize replacement without pinned keyless
  provenance and the exact 14-name release manifest.
- **BC-10:** `make check` is the non-mutating `go run ./cmd/verify ci` adapter;
  `verify release` is a non-publishing strict superset.

The completed issues #2 through #11 remain preserved baselines rather than new
v2 features: non-interactive execution, scoped transactions, stable machine
errors, explicit offline/freshness, exact alias and host-key handling,
observable/resumable transfers, agent-safe invocation, and pre-unlock help all
remain compatible.

### Migration and rollback

- Back up the encrypted vault, `remote.etag`, `publishing-intent.json`,
  `sync-conflict.json`, pending ID order, and authenticated executable-recovery
  state without exposing their contents.
- Run `ssm --json update --major` first. Require all automated checks and
  manually review bare-push consumers, zero-refresh online streams, and
  directory-transfer parsers before using `--major --yes` on a canary.
- Authorization never bypasses digest/provenance verification. A failed trust,
  migration, or replacement gate preserves the old executable and evidence.
- There is no automatic down-migration. Reinstall v1 only when the encrypted
  on-disk state is compatible, no publication/update recovery is outstanding,
  and remote identities and pending transactions have been reconciled. When
  state is uncertain, restore/recover v2 first and do not mutate further.
- Verification does not merge, tag, install, upload, publish artifacts, or
  create a release. Only the official exact-tag workflow can publish after all
  migration, CI, provenance, rollback, and review blockers pass.

<!-- documentation-contract: historical-begin -->

## Historical v1 release notes

The versioned sections below describe behavior of those v1 releases, including
then-supported bare-push compatibility. They are historical evidence, not
current v2 command guidance; the v2 contract above supersedes them.

## v1.4.3

### Fast agent execution

- Keep one-shot literal commands on the direct `sshctl --json run <alias> --argv ...` path; typed request files remain the safer path for dynamic argv, scripts, secrets, and mutations.
- Add `sshctl run <alias> --stream`, a headless NDJSON argv stream that syncs and decrypts once, reuses the SSH connection across commands, refreshes inventory every 30 seconds by default, and stops rather than using stale data after a refresh failure.
- Reuse the already-validated decrypted vault for the command's first load, removing the duplicate Argon2 decrypt previously performed immediately after unlock while allowing later same-process loads to observe intervening saves.
- Open the actual pooled SSH session directly instead of opening and closing a probe channel first. Serialize dials per destination rather than globally, allowing different fleet targets to establish SSH connections concurrently.

### Validation

- Add strict stream parsing/error tests and an in-process SSH regression proving that two commands use one connection and exactly two command sessions.

## v1.4.2

### Push unlock fix

- Load the vault passphrase from the configured private file before both `ssm push` and `sshctl push` read the encrypted local vault.
- Preserve pre-unlock validation for invalid push arguments and keep scoped/all transaction semantics unchanged.
- Add a subprocess regression test that performs a push using only a real `master.pass` file, without pre-populating process-global credentials.

### Validation

- Formatting, unit tests, race tests, vet, golangci-lint, vulnerability scanning, build, and the real OpenSSH matrix pass.

## v1.4.1

### Consistent non-interactive help

- Add command-specific, pre-unlock help for request, push, put, get, run, map, host, host-key, doctor, status, sync, pull, and redirect, including nested host operations.
- Keep help and version paths free of vault unlocks, network calls, and secret access while preserving one-value JSON errors for invalid invocations.

### Smaller agent and code surface

- Reduce the agent SSM skill to its decision rules and security boundaries; command help and the request schema are now the authoritative detail sources.
- Remove 13 unreachable legacy helpers and the unused ring buffer. Bubble Tea, Lip Gloss, TUI entry points, interactive shells, and terminal prompts remain absent.

### Security maintenance

- Raise the supported toolchain to Go 1.25.12 and update the existing `x/crypto`, `x/sys`, and `x/term` modules, fixing all vulnerabilities reachable in the prior build according to `govulncheck`.
- Add a pinned vulnerability scan to CI.

### Validation

- Unit, shuffled, race, vet, golangci-lint, staticcheck, dead-code, build, vulnerability, skill/schema, and real OpenSSH matrix checks pass without skipped tests.
- The complete lint baseline from v1.2.0 is clean; file and process safety annotations are limited to explicit user paths or test-owned temporary paths.

## v1.4.0

### Transactional inventory sync

- Give each changed host mutation a stable transaction ID and expose a secret-free pending mutation list through `status --json`.
- Add `push --only <transaction-id>` with an exact alias/operation preflight so unrelated local changes remain pending.
- Add deliberate `push --all`; retain bare push only as a compatibility push-all path. Transaction journals stay inside the encrypted local vault, while the sync service continues to receive only an encrypted inventory blob.

### Explicit SSH host trust

- Reject both first-use and changed host keys during normal run/check operations; no key is auto-saved or auto-replaced.
- Expand `host-key inspect --json` with address/port, observed and known fingerprints, `new|mismatch|trusted` classification, and safe guidance.
- Require the exact re-observed SHA-256 fingerprint plus `--yes` for acceptance. Remove automatic `ssh-keygen -R`/`ssh-keyscan` recovery advice.

### Atomic, observable, resumable put

- Stream regular files into private sibling temporary files, verify remote byte count, and atomically rename only after completion. Optional `--sha256` performs end-to-end digest verification; `--timeout` reports a stable timeout stage and byte count.
- Return structured transfer stage, bytes sent, integrity, atomicity, and resume status. Distinguish local read, SSH dial/auth, remote write, timeout, integrity, capability, partial-state, and publish failures.
- Add explicit regular-file-only `--resume=v1` and typed request support. Resume state is mode 0600 and bound to protocol version, destination hash, local size, and full digest; local and remote prefix digests must match before append.
- Preserve verified partial state across interruption, report reused versus sent bytes, verify full SHA-256 before atomic publish, reject changed/corrupt/ambiguous state, and opportunistically expire same-target v1 state older than seven days. Directory uploads remain non-resumable.

### Agent-safe contract and diagnostics

- Normalize machine failures around stable `ok/error/message/hint/exit/stage` fields while preserving a remote program's own exit 255 as a remote failure rather than assuming transport failure.
- Make alias drift, sync freshness/offline state, conflicts, and exact candidate selection explicit; never auto-select suggestions or silently fall back offline.
- Consolidate README, CLI help, request schema, and the `agent-ssm` skill around global `--json`, `request --file`, literal `argv`, file-backed `script_file`, and path-only `secret_files`.
- Mark one-string shell commands as compatibility-only with quoting/expansion warnings, and add troubleshooting for alias, sync, host-key, remote-process, and transfer failures.

### Validation

- Unit and integration coverage for scoped push isolation, secret-free transaction status, first-use/changed host-key rejection, wrong-fingerprint immutability, atomic upload cleanup, SHA-256 mismatch, missing verification tooling, and resume state validation.
- Real OpenSSH matrix forces upload timeouts and mid-transfer disconnects, resumes only a verified prefix with exact byte accounting, rejects corrupt partials, handles changed sources and shell-metacharacter paths, and verifies final digests.
- Release gates: formatting, tests, race tests, vet, build, SSH matrix, request/skill artifact validation, and diff checks.

## v1.3.0

### Non-interactive CLI only

- Remove the Bubble Tea/Lip Gloss TUI, interactive connection manager, shell entry points, and their dependencies.
- Require explicit commands and file-backed credentials for vault creation/unlock and sync login/register; no command waits for terminal input.
- Keep connection management through `sshctl host` and versioned typed requests. Uploads now stream to a sibling temporary file and atomically rename on success, preserving an existing destination after interrupted or failed transfers.

### Typed agent interface

- Add `sshctl request [--file <json>|-]` with strict schema version 1 and unknown-field rejection. A run request must select exactly one of `argv`, `shell_command`, or `script_file`.
- Preserve literal arguments and script arguments as JSON arrays so the local shell cannot reinterpret agent-generated values. Request secrets are file paths only and remain redacted.
- Identify every execution with `mode`, `transport`, and optional `preflight` metadata. Global `sshctl --json ...` now keeps argument, unlock, alias, and sync failures to one JSON value.
- Fix `sshctl run --json` without an alias: it now returns structured `missing_alias` instead of treating `--json` as a host name.

### Verified mutations and safer legacy boundaries

- Add `--verify` for host add/update/upsert. SSM checks the in-memory candidate with `hostname; uname -sr` and saves only after success; failure returns `verification_failed`, `applied:false`, and leaves the encrypted vault unchanged.
- Require `--verify` when a host mutation uses `--push`. A push failure reports `sync_push_failed` while preserving the verified local change as pending.
- Default typed host add/update/upsert requests to candidate verification.
- Remove the destructive `import-json` default. Callers must choose `--merge`, or explicitly authorize full replacement with `--replace --yes`.
- Replace former add/edit/key-entry paths with explicit host CLI/request operations and file-backed credential inputs.

### Script and host-key hardening

- Add remote script syntax preflight using the same selected interpreter with `-n`; classify parse failures as `script_syntax_error` before executing the body. Typed script requests enable it by default.
- Add `sshctl host-key inspect` to observe the current algorithm/fingerprint without sending credentials and report `trusted`, `new`, or `mismatch` against `known_hosts`.
- Add fingerprint-bound `sshctl host-key accept ... --fingerprint SHA256:... --yes`. A mismatched or changed fingerprint does not install the new key.
- Report connection reuse scope explicitly as `process`, and document that exit 255 alone is not a failure category because a remote process can return it.

### Validation

- Strict request parsing, exact argv/secret-file handling, import mode guards, verify/push option guards, and global JSON parsing tests.
- In-process SSH coverage for script syntax preflight and host-key inspect/accept with wrong-fingerprint immutability.
- Real OpenSSH matrix covers candidate-vault rollback, typed argv/script requests, syntax-error no-side-effect behavior, host-key fingerprint guards, and guarded import.

## v1.2.0

### Agent-safe host management

- Add `sshctl host list/show/add/update/upsert/remove` (also `ssm host`) with stable JSON, strict validation, exact-alias semantics, and retry-safe `upsert` (`changed:false` on a no-op retry).
- Read SSH passwords and new private keys only from `--password-file` / `--key-file`; validate private keys before vault writes and never return credential material in JSON.
- Prevent accidental overwrite of unrelated/shared saved keys. `remove --prune-key` deletes a key only after its last host reference is gone.
- Stage host changes locally with `sync_pending:true`; verification happens before an explicit `sshctl push`, whose failures are observable.
- Stop before mutation when a configured remote refresh fails (`sync_pull_failed`); `--offline` is an explicit stale-state override.

### Script and quote reliability

- `-s`, `-f`, and `--scripts` now send bodies through SSH stdin to a fixed shell runner instead of embedding generated text in the SSH exec command.
- Normalize UTF-8 BOM and CRLF, reject NUL and scripts over 16 MiB, select `sh/bash/dash/ash/ksh/zsh` from shebang or `--shell`, and pass arguments after `--` with exact POSIX quoting.
- Script plan/JSON output reports `interpreter`, `stdin_bytes`, and `script_sha256` without exposing the body. Failures distinguish `interpreter_not_found` from `remote_script_failed`.
- Add explicit `--argv` mode so even a single argument is treated literally; legacy single-string shell behavior remains compatible.
- Validate `--secret` environment names and export script secrets into the interpreter environment while keeping plan/trace redacted.
- Return structured `invalid_arguments` JSON with exit 2 when `--json` parsing fails, instead of mixing machine output with a usage page.

### Validation

- `go test ./...`, `go test -race ./...`, `go vet ./...`, and cross-platform builds.
- Real local-shell runner test covers BOM/CRLF, nested single/double quotes, exact args, and secret export.
- Isolated encrypted-vault CLI smoke covers host create, unchanged upsert, partial update, show, remove, and JSON errors.

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

<!-- documentation-contract: historical-end -->
