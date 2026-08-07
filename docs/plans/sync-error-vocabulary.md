# Stable sync state and divergence vocabulary

Status: implemented and characterized on the v2 line.

This document freezes the names already emitted by the sync transaction and
machine-contract modules. It does not add a new public error or change the
meaning of an existing field.

## Local configuration state

| State | Meaning | Network allowed | Stable error |
| --- | --- | --- | --- |
| `offline` | Explicit global offline mode; cloud configuration is not inspected. | No | None for local inspection/stream initialization |
| `unconfigured` | `cloud.json` is absent. | No for local inspection; explicit sync reports `sync_config_error`. | `not logged in (run: ssm login)` / `ErrUnconfigured` |
| `configured` | Present configuration parses and has an `http`/`https` server, host, and non-empty token. | Yes | None |
| `invalid` | `cloud.json` is present but unreadable, malformed, or has invalid required fields. | No | `sync configuration is invalid` / `ErrConfiguration` |

A present invalid configuration is never treated as unconfigured. Explicit
offline mode remains the only path that ignores invalid cloud configuration.

## Divergence errors

| Condition | Stable error | Machine contract |
| --- | --- | --- |
| Local and remote opaque blobs diverge during refresh/pull/push preflight. | `sync conflict` / `ErrConflict` | `error=sync_conflict`, `stage=sync_compare` |
| Empty publication ledger has non-identical local, cached, and remote opaque identities. | `empty-ledger sync divergence` / `ErrEmptyLedgerDivergence` | `error=sync_conflict`, `stage=sync_compare`, reviewed-recovery hint |

Only opaque identities and conflict metadata are retained. Decrypted inventory,
configuration contents, tokens, and keys are not part of these errors.

## Evidence

- `internal/synctransaction/inspection_test.go` freezes offline, unconfigured,
  configured, invalid, and unreadable states without network access.
- `internal/synctransaction/policy_test.go` freezes invalid-configuration
  failures and two-sided divergence preservation.
- `internal/machinecontract/contract_test.go` freezes the stable error/stage
  mapping and the reviewed empty-ledger recovery hint.
- `internal/synctransaction/transaction.go` is the exclusive owner of the
  configuration-state and sync-divergence sentinels.
- `internal/machinecontract/contract.go` is the exclusive owner of their
  serialized machine fields.
