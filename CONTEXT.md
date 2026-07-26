# Domain context

This file records vocabulary and hard contracts already observable in the
public documentation, security policy, agent skill, and CLI behavior. It does
not introduce new product or architecture decisions.

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
  synchronization publishes it.
- **Transaction ID**: The stable identifier returned for a mutation and
  consumed by `push --only` to publish that reviewed change.
- **Sync**: Pulling or pushing encrypted vault state against the configured
  synchronization endpoint.
- **Offline inventory**: Explicit use of cached local state with `--offline`;
  remote state is not checked and freshness metadata is reported.
- **Host-key inspection**: Observation of an SSH host key as `new`, `mismatch`,
  or `trusted` before explicit acceptance of the exact fingerprint.

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
- Offline inventory requires an explicit `--offline` choice that accepts stale
  local state.
- A reviewed mutation is published with `push --only <transaction-id>`.
  Unrelated pending mutations remain pending.
- Bare `push` and `push --all` are compatibility paths for deliberately
  publishing every pending mutation; scoped publication must not be enlarged
  to either form.

### Public automation interface

- The CLI is non-interactive: it does not start a TUI, open an interactive
  shell, or wait for terminal input.
- Normal JSON commands emit one JSON value. `run --stream` emits one NDJSON
  result for each input line.
- Public CLI behavior, help output, stable JSON fields, canonical `error`,
  `stage`, `exit`, and `hint` values, and cross-platform behavior are
  compatibility boundaries.
- Failures are classified by `error` and `stage`; `exit` is for process control
  and cannot by itself distinguish a transport failure from a remote program
  that exits with the same value.
