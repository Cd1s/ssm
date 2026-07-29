# Issue 24 legacy mutation ownership and BC-4 migration

`internal/inventorytransaction` is now the single policy owner for every
inventory mutation. Issue #24 completes the bounded follow-on from Issue #22:
legacy connection removal, saved-key removal, and both guarded bulk-import
modes no longer save a raw candidate or publish it automatically.

## BC-4 old/new compiled matrix

The old side is the compiled `TestApprovedV2BreakingChangeBaselines` fixture at
base commit `cd2c8b3057d0c17d34655b94a0a7b8d968faacaf`. The new side is pinned by
the updated fixture plus the three Issue #24 compiled tests.

| Entry point | Old output and local encrypted state | Old sync requests in the configured fixture | New output and local encrypted state | New sync requests | Explicit next command |
| --- | --- | --- | --- | --- | --- |
| `ssm remove <alias>` | Compatible human removal message; directly re-encrypted the candidate; retained any unrelated ledger but created no removal transaction | `HEAD=2`, `GET=1`, `PUT=1` | Same human message; machine mode adds a stable secret-free host mutation receipt; candidate plus exactly one `removed` transaction are encrypted atomically | refresh only (`HEAD=1`, `GET=1`, `PUT=0`); explicit offline is zero network | `sshctl --json push --only <transaction_id>` |
| `ssm keys remove <name>` | Compatible human removal message; directly re-encrypted the candidate; could leave live references dangling; created no key transaction | `HEAD=2`, `GET=1`, `PUT=1` | Same human message; machine mode adds a stable key-name/count receipt; live references reject before persistence; a safe removal appends exactly one `saved_key_removed` transaction | refresh only (`HEAD=1`, `GET=1`, `PUT=0`); explicit offline is zero network | Publish every reported reference prerequisite in ledger order, then `push --only <transaction_id>` |
| `ssm import-json ... --merge` | Stable action/connection/key/conflict fields; directly saved the merged candidate and discarded an existing pending ledger; no import transaction | `HEAD=1`, `GET=1`, `PUT=0` | Preserves the compatible fields and adds safe aliases, pending state, and one stable ID; preserves the prior ledger and appends one atomic `import_merged` bulk transaction | unchanged refresh only (`HEAD=1`, `GET=1`, `PUT=0`); explicit offline is zero network | Publish reported earlier ledger prerequisites, then `push --only <transaction_id>` |
| `ssm import-json ... --replace --yes` | Explicit destructive guard; directly saved the replacement while retaining an existing ledger but recording no replacement transaction | `HEAD=1`, `GET=1`, `PUT=0` | Same `--replace --yes` guard and compatible counts; appends one atomic `import_replaced` bulk transaction with safe aliases/counts | unchanged refresh only (`HEAD=1`, `GET=1`, `PUT=0`); explicit offline is zero network | Publish reported earlier ledger prerequisites, then `push --only <transaction_id>` |

`TestMutationEntryPointsNeverAutoPublish` also runs the existing `ssm host
remove` compatibility adapter and request-v1 `host.remove` route with
`auto_sync=true`. Every successful mutation performs one normal freshness
`HEAD`, no `GET` when the cached remote identity matches, and no `PUT`.

## Atomicity, dependencies, and projection

- A late invalid import item leaves the encrypted vault byte-for-byte unchanged.
  Complete import parsing and candidate validation therefore precede ID
  generation and persistence.
- Expected-count checks and `--merge` versus `--replace --yes` parsing remain in
  front of the module.
- Merge-report persistence remains before the atomic encrypted vault write; a
  merge-report failure cannot append inventory or ledger state.
- Saved-key deletion rejects every current referencing alias. If earlier
  reviewed host mutations removed those references, the key transaction keeps
  the existing `saved_key_reference` prerequisites.
- A bulk import stores its full before/after inventory only inside the encrypted
  ledger. Public pending and publication preflight views contain only the stable
  ID, operation, creation time, sorted affected aliases, and affected
  connection/key counts.
- A bulk transaction orders every earlier transaction before itself and itself
  before every later transaction with the safe `inventory_order` reason.
  Prerequisites are rejected before cloud configuration or transport is used;
  they are never auto-included.
- The compiled projection fixture publishes the earlier transaction, one bulk
  import, and the later transaction explicitly. The final opaque remote blob
  decrypts in-process to the exact expected inventory, with no ledger or
  publication metadata.

## Ownership contraction

| Former owner or bypass | Removed policy | Current owner |
| --- | --- | --- |
| `cmd/ssm/connections.go:runRemove` | slice mutation, raw `config.Save`, settings-driven automatic push | `inventorytransaction.Transaction.ApplyHost` |
| `cmd/ssm/keys.go:runKeysRemove` | unsafe key deletion, raw `config.Save`, settings-driven automatic push | `inventorytransaction.Transaction.RemoveSavedKey` |
| `cmd/ssm/connections.go:runImportJSON` | merge/replace candidate construction, direct save, pending-ledger loss | `inventorytransaction.Transaction.ApplyImport` |
| `cmd/ssm/cloud.go:autoPushOpaque` | raw encrypted-file read and ignored automatic publication result | deleted |
| `synctransaction.Transaction.AutoPushBlob` | settings-driven publication API retained only for the legacy callers | deleted |
| command pending/status adapters | independent public mutation view construction | `inventorytransaction.Pending` |

The command layer retains parsing, compatible not-found rendering, refresh
invocation, and command-specific human output. Encrypted serialization and
private atomic replacement remain in `internal/config`; explicit opaque
publication remains in `internal/synctransaction`.

## Compatibility and later documentation source

- Command names, `host`/`hosts` aliases, request schema v1, import guards,
  expected counts, merge conflicts, and existing human success messages remain.
- Modern direct and request-v1 host mutations from Issue #22 retain their
  receipt fields, pending shape, dependencies, and projection.
- No durable publishing intent, crash reconciliation, or other Issue #23
  behavior is included.
- The later public documentation ticket should update the legacy mutation
  workflow near `README.md` and `README.en.md` bulk-import guidance,
  `cmd/ssm/main.go` help text, and the BC-4 section of `RELEASE_NOTES.md`.
  This implementation evidence deliberately does not make that unrelated
  public-documentation change.

## Verification seams

- `TestLegacyMutationsCreatePendingTransactions`
- `TestImportCreatesOneAtomicBulkTransaction`
- `TestMutationEntryPointsNeverAutoPublish`
- Updated BC-4 section of `TestApprovedV2BreakingChangeBaselines`
- Existing `TestInventoryTransactionPolicy` and
  `TestScopedPublicationSavedKeyDependencies`
