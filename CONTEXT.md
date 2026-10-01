# Domain context

This file records the agreed vocabulary and hard contracts for the public
product domain. It defines stable meanings and invariants, while implementation
plans and speculative APIs live elsewhere.

## Product vocabulary

- **`ssm` / `sshctl`**: Names for the same non-interactive SSH
  connection-manager binary. `sshctl` is the agent-oriented command name.
- **Vault**: The local encrypted store containing SSH host information and
  credentials. Synchronization transfers encrypted vault data; SSH connections
  originate on the current machine.
- **Inventory**: The host data read from the vault. In `local_first` mode
  (the default) reads use the local vault and report its freshness; in
  `strict` mode online operations refresh configured remote state before using
  it unless the caller explicitly chooses `--offline`.
- **Host**: A saved SSH connection target and its non-secret metadata plus a
  reference to authentication material.
- **Alias**: The exact name used to address a host. Searches and suggestions
  return candidates but do not select or connect automatically.
- **Request**: A typed JSON operation with schema version 1, used for dynamic
  arguments, scripts, secret-file paths, transfers, and host mutations.
- **Mutation**: A local change to host inventory that remains pending until
  synchronization publishes it. Every inventory-changing operation creates a
  reviewable pending transaction, including legacy removal and bulk import
  operations.
- **Transaction ID**: The stable identifier returned for a mutation and
  consumed by `push --only` to publish that reviewed change.
- **Publication scope**: The exact pending transaction or invocation-start
  snapshot of pending transactions selected for publication. Dependencies may
  block a scope, but never enlarge it implicitly.
- **Publishing intent**: A non-sensitive durable recovery record binding a
  publication scope to its target encrypted-blob identity and prerequisite
  remote identity.
- **Sync**: Pulling or pushing encrypted vault state against the configured
  synchronization endpoint.
- **Sync mode**: The `sync_mode` setting (`SSM_SYNC_MODE` overrides it for one
  process). `local_first` is the default: the sync service is a replication
  channel and never stands in front of a command. `strict` is the v2.0.2
  behavior: every inventory read refreshes online first and a refresh failure
  fails the command.
- **Background sync**: In `local_first` mode, a detached `sshctl sync
  --background` process started by an inventory read whose automatic sync is
  due. It pulls only when the remote identity changed, never publishes, never
  overwrites divergent local state, and records its outcome in
  `sync-state.json`.
- **Sync state**: `sync-state.json` in the private configuration directory:
  last attempt and success, next scheduled attempt, consecutive failures,
  the last classified failure (`cause`, redacted `message`, time), and the
  atomic claim that lets exactly one command start a background sync.
- **Inventory staleness**: Local-first inventory whose last confirmed sync
  (pull, push, or successful background check) is older than `stale_after`
  (default 7 days).
- **Sync configuration state**: Sync is **unconfigured** only when its
  configuration is absent. A present but invalid or unreadable configuration
  is a distinct failure state.
- **Offline inventory**: Explicit use of cached local state with `--offline`
  or `SSM_OFFLINE=1`; cloud configuration is not parsed, no network access
  occurs, no background sync starts, remote state is not checked, and
  freshness metadata is reported.
- **Host-key inspection**: Observation of an SSH host key as `new`, `mismatch`,
  or `trusted` before explicit acceptance of the exact fingerprint.
- **Jump host (`proxy_jump`)**: A host alias another host is reached
  through. The target's SSH handshake runs over a `direct-tcpip` channel opened
  on the jump host's own verified and authenticated connection, so every hop
  checks its own host key against the local `known_hosts` and uses its own
  credentials; credentials and agents are never forwarded. A chain has at most
  five jump hosts and no cycles, and is resolved (with redirects) when it is
  used.
- **Via**: The additive failure field naming the alias of the hop (a jump host
  or the target itself) that failed while connecting through a jump chain. It
  never replaces `error`, `stage`, or `exit` and is omitted for direct
  connections.
- **Host-to-host copy (`cp`)**: A single regular file streamed from one host
  through this machine to another, published only when the source digest, the
  digest of the relayed bytes, and the destination's digest agree. With
  `--direct --yes` the source host instead pushes straight to the destination
  over its own network path: it runs `ssh` (ignoring A's ssh_config and A's own
  keys) to the destination with a scoped,
  in-process SSH agent that holds only the destination's vault key, forwarded
  for that one session and emptied when the copy ends, and with strict
  host-key checking against a private known_hosts that holds only the
  destination key this machine already trusts. The exposure is explicit: while
  the copy runs, the source host (and whoever controls it) can use the
  destination's key for other connections but cannot extract it. The
  destination's password, this machine's own agent and other keys are never
  forwarded. Requires a key-authenticated destination without `proxy_jump`,
  no `transfer: sftp` host, and `--yes`; `--timeout` closes the agent and the
  connection carrying it at the deadline (A's ssh is bounded only when A has
  GNU `timeout`; no limit without `--timeout`); the result reports `route:"direct"`
  with the source and destination digests and no relayed-bytes digest.
- **Transfer outcome**: A machine-readable transfer result that identifies its
  direction and kind and reports only guarantees the selected transfer
  protocol actually provides.
- **Major update authorization**: Explicit approval to cross a major-version
  boundary after reviewing release notes, breaking changes, and migration
  checks. Ordinary automatic replacement never grants this approval.
- **Update recovery-required state**: The Windows-only terminal state after a
  mapped original has moved from its canonical pathname and both the
  handle-bound forward commit and authenticated rollback are refused. Exact
  original evidence remains retained for authenticated startup recovery.

## Hard contracts

### Credentials and sensitive data

- Passwords, private keys, and other secrets are supplied through
  permission-restricted file paths, not inline values.
- Secrets, passwords, private keys, `cloud.json`, `master.pass`, tokens, and
  decrypted vault contents must not appear in structured output, command
  arguments, logs, errors, issues, or commits.
- The optional synchronization service stores encrypted vault blobs and does
  not perform the actual SSH connection.
- Security vulnerabilities are reported privately, not in public issues.

### Host identity

- First-use and changed SSH host keys are rejected by normal operations.
- Acceptance requires inspecting the observed key, verifying it through a
  trusted channel, and explicitly accepting the exact fingerprint.
- Host-key algorithms are negotiated in the order of the key types already
  recorded in known_hosts for the endpoint. A changed key of a recorded type is
  a mismatch; an endpoint that only offers other key types is a distinct
  key-type change. Acceptance replaces only the entry of the accepted key type
  and leaves other key types and other hosts untouched.
- Alias suggestions and search results are candidates only; callers choose an
  exact alias before connecting.

### Inventory freshness and publication scope

- In `strict` mode refresh failures stop online inventory operations, and
  cached inventory is never selected silently.
- In `local_first` mode (the default) an inventory read never sends a sync
  request and is never stopped by the sync service. Using local inventory is
  not silent: `status` reports `remote_state`, `last_successful_sync`,
  `last_sync_error`, `next_sync_attempt`, and `cache_age_seconds`; stale
  inventory adds `inventory_stale` to `status` and `run` JSON and a one-line
  stderr warning to human reads. Automatic sync failures never fail a command
  and back off exponentially (30 seconds to one hour); a divergence is
  recorded with `cause=conflict` and never resolved automatically.
- Explicit `sync`, `pull`, and `push` are strict in every mode: failure is
  failure, and the outcome is recorded in the sync state.
- A missing sync configuration means sync is not configured. An invalid or
  unreadable sync configuration stops every inventory read or mutation in both
  modes.
- Local vault mutations, publication finalization, and every pull (background,
  explicit `sync`/`pull`, strict refresh, reviewed adoption) share one bounded
  cross-process vault write lock that is never held across network I/O. A
  mutation saves only if the vault file is still the version it loaded; a pull
  downloads first, then re-reads local identity under the lock and fails closed
  on divergence, so neither can overwrite the other.
- Configured sync that has never confirmed the inventory is reported
  (`inventory_unsynced` in `status`, one stderr line for human reads).
- An unrecognized `sync_mode` runs as `local_first` and is reported once on
  stderr by `status` and human reads.
- `auto_sync: false` disables automatic sync in both modes.
- In `strict` mode offline inventory requires an explicit `--offline` (or
  `SSM_OFFLINE=1`) choice that accepts stale local state.
- Online streams require a positive refresh interval. A zero interval is valid
  only with explicit offline inventory and therefore uses one fixed cached
  snapshot.
- Any refreshed inventory change invalidates the entire process-scoped SSH
  connection pool before the new snapshot is used.
- Alias ordering and saved-key creation, replacement, rename, and deletion
  create explicit publication dependencies. Unsatisfied transitive
  dependencies stop publication before network access.
- A reviewed mutation is published with `push --only <transaction-id>`.
  Unrelated pending mutations remain pending.
- A transaction remains pending until the target remote encrypted-blob identity
  is confirmed. Ambiguous remote outcomes are reconciled against that identity
  before local finalization.
- Bare `push` is invalid. `push --all` publishes only the non-empty set of
  pending transactions captured when the command starts.
- An empty pending set never causes a remote PUT. Untracked local/remote
  divergence requires a separate reviewed repair, pull, or import flow.

### Public automation interface

- The CLI is non-interactive: it does not start a TUI, open an interactive
  shell, or wait for terminal input.
- Normal JSON commands emit exactly one JSON value.
- From process start, `run --stream` emits compact NDJSON. Initialization
  failure emits one terminal result without consuming input; after successful
  initialization, each consumed non-empty input line emits exactly one ordered
  result. Empty lines emit nothing, and there are no ready, summary, or footer
  records.
- In `strict` mode a stream refresh failure is the triggering input line's only
  terminal result and stops further processing. In `local_first` mode sync
  failures never stop a stream; a due refresh reloads the local snapshot when
  the vault changed and starts a background sync.
- Public CLI behavior, help output, stable JSON fields, canonical `error`,
  `stage`, `exit`, and `hint` values, and cross-platform behavior are
  compatibility boundaries.
- Failures are classified by `error` and `stage`; `exit` is for process control
  and cannot by itself distinguish a transport failure from a remote program
  that exits with the same value.
- All transfer outcomes share stable minimal failure metadata, direction, and
  kind. Atomicity, integrity, resume, and similar fields appear only when the
  underlying protocol supplies the guarantee or explicitly reports it as
  unavailable or false.

### Remote execution and connection bounds

- `--connect-timeout` bounds TCP connect plus the SSH handshake as one budget;
  the deprecated `--timeout` alias keeps that connection-only meaning for
  `run`/`exec`/`plan`/`map` and `run --stream`. Both flags set one value (the
  last on the command line wins) and beat an inherited `SSM_CONNECT_TIMEOUT` or
  `SSM_TIMEOUT`. A stalled handshake fails as
  `handshake_failed` (stage `handshake`, exit 255) before any command is
  sent; only a TCP connect that never completed stays `dial_timeout`. A
  handshake timeout used to classify as `dial_timeout`; consumers that matched
  that tuple must also accept `handshake_failed`.
- `--exec-timeout` bounds each remote command. At expiry sshctl sends SIGTERM,
  allows a five-second grace period, then closes the session and reports
  `exec_timeout` (stage `remote_execution`) with `timed_out:true` and exit
  124. Once sshctl has sent SIGTERM because the deadline passed the result is
  `exec_timeout` even if the command traps TERM and exits 0 during the grace
  period; only a command that completed before the signal was sent reports its
  real result. The bound applies to
  `run`, `exec`, `plan`, `map`, and every line of `run --stream`.
- `put`/`get` retain their separate transfer `--timeout` meaning. SSH
  keepalive probes use `keepalive@openssh.com` every 15 seconds by default;
  three unanswered probes close the connection and classify an in-flight
  command as `connection_lost`. `SSM_KEEPALIVE=0` disables the probes.

### Update authorization and trust

- Ordinary automatic replacement is limited to the current major version.
  Cross-major installation requires explicit major update authorization.
- Release replacement requires the artifact digest plus keyless build
  provenance pinned to the expected repository, release workflow identity,
  and OIDC issuer.
- Trust and preflight failures, failures before canonical mutation, and
  ordinary `update_failed` outcomes leave the exact original executable
  canonical. On Windows only, simultaneous forward-commit and authenticated
  rollback refusal after the original moves uses
  `error=update_recovery_required`, `stage=update_recovery`, and `exit=1`;
  command dispatch and later updates remain blocked until recovery revalidates
  the original File ID, SHA-256, and security-descriptor binding, restores the
  canonical pathname, and clears the authenticated record.
