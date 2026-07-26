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
- **Inventory**: The host data read from the vault. Online operations refresh
  configured remote state before using it unless the caller explicitly chooses
  `--offline`.
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
- **Sync configuration state**: Sync is **unconfigured** only when its
  configuration is absent. A present but invalid or unreadable configuration
  is a distinct failure state.
- **Offline inventory**: Explicit use of cached local state with `--offline`;
  cloud configuration is not parsed, no network access occurs, remote state is
  not checked, and freshness metadata is reported.
- **Host-key inspection**: Observation of an SSH host key as `new`, `mismatch`,
  or `trusted` before explicit acceptance of the exact fingerprint.
- **Transfer outcome**: A machine-readable transfer result that identifies its
  direction and kind and reports only guarantees the selected transfer
  protocol actually provides.
- **Major update authorization**: Explicit approval to cross a major-version
  boundary after reviewing release notes, breaking changes, and migration
  checks. Ordinary automatic replacement never grants this approval.

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
- Alias suggestions and search results are candidates only; callers choose an
  exact alias before connecting.

### Inventory freshness and publication scope

- Refresh failures stop online inventory operations. Cached inventory is never
  selected silently.
- A missing sync configuration means sync is not configured. An invalid or
  unreadable sync configuration stops every online inventory read or mutation.
- Offline inventory requires an explicit `--offline` choice that accepts stale
  local state.
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
- A stream refresh failure is the triggering input line's only terminal result
  and stops further processing.
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

### Update authorization and trust

- Ordinary automatic replacement is limited to the current major version.
  Cross-major installation requires explicit major update authorization.
- Release replacement requires the artifact digest plus keyless build
  provenance pinned to the expected repository, release workflow identity,
  and OIDC issuer.
