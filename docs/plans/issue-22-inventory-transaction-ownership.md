# Issue 22 inventory transaction ownership and BC-2 migration

`internal/inventorytransaction` is the single policy owner for modern reviewed
host mutations and scoped inventory publication. It constructs and validates
decrypted candidates locally, but delegates publication as opaque encrypted
bytes to `internal/synctransaction`.

## BC-2 old/new compiled fixture

The compiled fixture in `TestApprovedV2BreakingChangeBaselines` pins the
previous same-alias-only behavior:

- `tx_alpha` created alias `alpha` and saved key `shared-key`.
- `tx_beta` created alias `beta` referencing `shared-key`.
- Because the aliases differed, `push --only tx_beta` was allowed.
- The old remote projection contained `beta` with
  `key_name=shared-key`, but contained no saved key. It performed one PUT.

BC-2 now rejects that exact scope before sync configuration or transport is
used. The unchanged canonical `sync_push_failed` failure identifies
`tx_alpha`, alias `alpha`, operation `created`, key name `shared-key`, and
reason `saved_key_create`. The request-counting endpoint observes zero HEAD,
GET, and PUT requests, and the encrypted local vault remains byte-for-byte
logically unchanged.

Callers must publish every reported prerequisite explicitly in the displayed
ledger order, then retry the originally selected transaction:

```text
sshctl --json push --only <first-required-transaction-id>
sshctl --json push --only <next-required-transaction-id>
sshctl --json push --only <original-transaction-id>
```

Publication never adds those IDs to the requested scope automatically.

## Dependency and projection evidence

`TestScopedPublicationSavedKeyDependencies` uses compiled binaries, temporary
encrypted vaults, valid test-only private keys, and a request-counting endpoint.
Captured blobs are decrypted only in the test process and converted to safe
identities containing names plus secret length/digest; plaintext inventory is
never printed on mismatch.

| Saved-key form | Compiled transaction chain | Safe prerequisite evidence |
| --- | --- | --- |
| create | `alpha` creates `shared-key`; `beta` references it | `saved_key_create` |
| replace | `beta` stops referencing `rotated-key`; `alpha` replaces it; `gamma` references it | `saved_key_reference`, then `saved_key_replace` |
| rename | `alpha` changes from `old-key` to newly created `new-key`; `beta` references `new-key` | transitive `alias_order`, then `saved_key_rename` |
| delete | `alpha` changes reference and deletes `deleted-key`; `beta` recreates it | `saved_key_delete` |
| last-reference prune | `alpha` stops referencing `pruned-key`; removing last reference `beta` prunes it; `gamma` recreates it | `saved_key_reference`, then `saved_key_prune` |
| reference | cross-alias removal is required before replacement or last-reference deletion | `saved_key_reference` |
| transitive closure | selected reference depends on a key lifecycle mutation which itself depends on an earlier alias/reference mutation | every required stable ID in original ledger order |

The prune/recreate fixture first proves the selected dependent transaction is
rejected with zero HTTP. It then publishes the two prerequisites explicitly,
followed by the selected transaction. The last captured remote blob contains
only the valid `alpha` and `gamma` projection with the recreated key. A fourth,
unrelated host mutation remains pending locally and is absent from the remote
blob. The sync endpoint therefore receives neither pending-ledger fields nor
publication metadata.

## Ownership contraction

| Former owner | Removed policy | New owner |
| --- | --- | --- |
| `cmd/ssm/hosts.go` | candidate construction, credential-file loading, saved-key installation/replacement/prune rules, candidate validation, verification ordering | `inventorytransaction.Transaction.ApplyHost` |
| `cmd/ssm/transactions.go` | random stable IDs, pending-base append, secret-free views, same-alias preflight, key delta projection, and rebasing | deleted; `inventorytransaction` |
| `cmd/ssm/cloud.go` | projection selection, pre-persist/finalize, rollback, encryption selection, and remaining-ledger receipts | `inventorytransaction.Transaction.Publish` |
| `cmd/ssm/sshctl.go` | pending mutation view construction | `inventorytransaction.Pending` |
| direct `ssm`/`sshctl host` | mutation policy | parsed option-presence mapping plus module invocation |
| request schema v1 host operations | independent mutation path risk | unchanged strict request adapter into the same direct module invocation |

The module preserves the compatible `config.Vault`,
`config.InventorySnapshot`, and `config.PendingMutation` serialization. Stable
IDs retain the `tx_` plus 32 lowercase hexadecimal format; existing JSON
fields and omissions remain unchanged. `config.EncryptVault` remains the vault
crypto mechanism, private-file writes remain in `internal/config`, and
`synctransaction.Transaction.PushBlob` remains the only publication transport.

## Bounded remaining migrations

BC-2 is the only behavior change in this ticket.

- Issue #23 owns durable publishing intent, crash-window reconciliation, and
  replacement of the current bounded rollback behavior.
- Issue #24 owns legacy `ssm remove` (`runRemove`), `ssm keys remove`
  (`runKeysRemove`), and `import-json --merge|--replace` (`runImportJSON`).
  Their characterized direct-save/automatic-publication effects are unchanged
  here.
- Bare/empty-ledger push and other approved v2 breaks remain governed by their
  separate migration work; this ticket preserves the current paths.
