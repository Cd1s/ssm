# Issue 25 exact push scopes and empty-ledger safety

`internal/inventorytransaction.PublicationSession.Publish` is the single owner
of reviewed inventory publication. It selects and projects a fixed transaction
scope, validates dependencies, persists and reconciles publishing intent,
delegates only opaque encrypted bytes and identities to
`internal/synctransaction`, and finalizes only the selected stable IDs after
the target identity is confirmed.

<!-- documentation-contract: historical-begin -->

## BC-5 old/new compiled matrix

The old side is the compiled `TestApprovedV2BreakingChangeBaselines` fixture at
`de66f23ee444d7f61a16e0d39375e97538913b4d`. It ran both bare `push` and
`push --all` against an empty pending ledger and proved that each uploaded the
complete encrypted local vault with one PUT. The new side is the updated BC-5
fixture plus the three Issue 25 compiled tests.

| Case | Old compiled behavior | New output and exit | New requests | Local/remote result |
| --- | --- | --- | --- | --- |
| bare `push` under either binary name | Treated as `scope=all`; empty ledger uploaded the full local blob | `error=invalid_arguments`, hint to inspect `status.pending_mutations`, exit 2 | `HEAD=0`, `GET=0`, `PUT=0` | No unlock-dependent state or remote change |
| non-empty `push --only <id>` | Exact same-alias scope with bounded rollback | Compatible `action=pushed`, `scope=only`, exact `transaction_id`, exit 0 | Confirmed path `HEAD=2`, `GET=0`, `PUT=1` | Durable intent binds one exact satisfiable ID; unrelated and later IDs remain pending |
| non-empty `push --all` | Selected the ledger observed during projection, but had no durable commit protocol | Compatible `action=pushed`, `scope=all`, ordered preflight, exit 0 | Confirmed path `HEAD=2`, `GET=0`, `PUT=1` | Durable intent binds the invocation-start ordered ID snapshot and exact prerequisite/target identities |
| empty `push --all`, all identities equal | Uploaded the complete encrypted local blob with `action=pushed` | `action=noop`, `scope=all`, empty preflight/remaining arrays, exit 0; human output explicitly says no pending transaction was published | Per invocation `HEAD=1`, `GET=0`, `PUT=0` | Local and remote blobs unchanged; no publishing intent |
| empty `push --all`, identities differ | Uploaded and overwrote with the complete encrypted local blob | `error=sync_conflict`, `stage=sync_compare`, reviewed-recovery hint, exit 1 | `HEAD=1`, `GET=0`, `PUT=0` | Local, remote, cached identity, and private conflict evidence preserved; no publishing intent |
| empty-ledger `push --only <unknown-id>` | Returned an empty successful scope | `error=sync_push_failed`, exit 1 | `HEAD=0`, `GET=0`, `PUT=0` | Unknown ID rejected before configuration or transport |
| `push --only ""` or both scope flags | Argument failure | Stable `invalid_arguments`, exit 2 | Zero transport | No unlock-dependent state |

BC-5 changes only bare-push validation and empty-ledger behavior. Stable
transaction IDs, non-empty receipt fields, exact projections, dependency
failures, durable intent states, request v1, and cross-platform persistence
remain unchanged.

<!-- documentation-contract: historical-end -->

## Empty-ledger identity state table

`VerifyEmptyPublication` reads the exact SHA-256 identity of the encrypted
local vault, the validated cached remote identity, and one current remote HEAD
identity. It never re-encrypts a candidate and never GETs or PUTs.

| Local `L` | cached `C` | remote `R` | Result |
| --- | --- | --- | --- |
| Present and equal to `C` and `R` | Present and equal to `L` and `R` | Present and equal to `L` and `C` | Explicit no-op; clear of publishing intent; one HEAD |
| Absent or unequal | Absent or unequal | Absent or unequal | Divergent or untracked; persist `sync-conflict.json` containing only `L`, `C`, `R`, and detection time; return `sync_conflict`; one HEAD and no overwrite |
| Present | Unsupported | Unsupported | Stable sync failure before PUT; preserve existing evidence |
| Present | Present | HEAD fails | Stable sync failure; no GET/PUT and no local change |

The no-op requires all three identities to agree. A missing cache or remote
blob is not permission to publish an untracked local blob.

## Invocation-start concurrency trace

`TestPushAllUsesInvocationStartSnapshot` uses a compiled `sshctl`, a real
private encrypted home, and a channel barrier in the request-counting endpoint:

1. Local ledger order is `tx_...25`, `tx_...26`; the cached and remote
   prerequisite identify the encrypted pending base.
2. `push --all` loads that ledger and persists a `ready` intent containing
   exactly those two IDs in order, the exact prerequisite identity, and the
   exact encrypted target identity.
3. The endpoint reads the PUT body and pauses before remote commit. No timing
   sleep is used.
4. A second compiled command appends a third host transaction while publication
   is paused.
5. The intent is read again and still contains only the first two IDs.
6. The endpoint resumes. The captured remote blob identity equals the intent
   target and its in-process decrypted safe projection contains only the first
   two mutations' inventory effects, with no pending ledger or intent metadata.
7. Local finalization rebases the third transaction onto that exact projection
   and leaves its stable ID pending.

Observed requests are `HEAD=2`, `GET=0`, `PUT=1`. The first HEAD captures the
prerequisite; the second confirms it immediately before the one PUT.

## Publication entry-point ownership

`TestEveryPushPathUsesInventoryTransactions` lists and exercises every retained
publication adapter with compiled binaries.

| Public entry point | Command adapter | Publication scope and owner |
| --- | --- | --- |
| `ssm --json push --only <transaction-id>` | `runPush` | one exact ID through `PublicationSession.Publish` |
| `sshctl --json push --only <transaction-id>` | compatibility command name into the same `runPush` | one exact ID through the same owner |
| `ssm --json push --all` | `runPush` | invocation-start ordered snapshot through the same owner |
| `sshctl --json push --all` | compatibility command name into the same `runPush` | invocation-start ordered snapshot through the same owner |
| `ssm host/hosts add/update/upsert --verify --push` | `runHostCommand` → `pushTransactions` | only the newly verified transaction ID through the same owner |
| `sshctl host/hosts add/update/upsert --verify --push` | same host adapter | only the newly verified transaction ID through the same owner |
| request v1 host add/update/upsert with `verify:true,push:true` | strict request adapter → `runHostCommand` | only the newly verified transaction ID through the same owner |

Each compiled host compatibility route begins with unrelated pending work. Its
captured blob contains only the newly reviewed host transaction's projection,
and the earlier ID remains pending. The successful configured request count is
`HEAD=3`, `GET=0`, `PUT=1`: one mutation freshness HEAD plus the two durable
publication HEADs and one PUT.

The following mutation routes never publish and remain covered by
`TestMutationEntryPointsNeverAutoPublish` and the Issue 24 compiled tests:
host remove under both command names and request v1, legacy `ssm remove`,
`ssm keys remove`, and `ssm import-json --merge|--replace --yes`. No command
calls the direct full-blob sync mechanism.

## Failure and restart semantics

Both `--only` and non-empty `--all` use the Issue 23 state machine unchanged:

- dependency and exact-scope projection precede intent and network access;
- `prepared` and `ready` intents retain the exact ordered IDs;
- explicit rejection clears retry intent but keeps every selected ID pending;
- response loss records `ambiguous` and reconciles remote prerequisite versus
  target without absorbing new IDs;
- a third remote identity records `divergent` evidence and never PUTs again;
- target confirmation followed by local-save failure records
  `finalization_failed`; restart completes only local finalization;
- successful finalization removes only the intended IDs and rebases later work.

`TestPublicationIntentCrashMatrix`,
`TestPublicationReconcilesLostResponse`,
`TestPublicationReconcilesFinalizeFailure`, and
`TestScopedPublicationSavedKeyDependencies` provide the compiled crash,
restart, and dependency evidence for both scopes.

## Reviewed divergence recovery

An empty-ledger conflict is not recoverable by retrying `push --all`; that
command will never publish an untracked full blob.

The emitted machine hint is deliberately merge-only and does not authorize
replacement:

```text
review sshctl --offline --json doctor and preserve the local vault and sync-conflict.json; run sshctl --json pull --adopt-remote <remote-sha256> --yes only after reviewing the exact remote identity, then use guarded ssm --offline --json import-json <reviewed-file> --merge and publish its reviewed transaction with sshctl --json push --only <transaction-id>
```

1. Run `sshctl --offline --json doctor` and review the safe `sync_conflict`
   identities.
2. Preserve private copies of the local encrypted vault,
   `remote.etag`, and `sync-conflict.json`. Keep their permissions private.
3. Prepare any local inventory that must survive as a reviewed import file;
   keep secrets in that private file, never in command arguments or logs.
4. Run `sshctl --json pull --adopt-remote <remote-sha256> --yes` with the exact
   remote identity from the preserved evidence. The reviewed path rechecks the
   remote HEAD, verifies the GET body identity, and atomically adopts the
   encrypted blob. If any identity changes, stop and retain all evidence.
5. If remote wins completely, recovery is finished. To reapply retained local
   inventory, run exactly one guarded command:

   ```text
   ssm --offline --json import-json <reviewed-file> --merge
   ```

   or, after explicit full-replacement review:

   ```text
   ssm --offline --json import-json <reviewed-file> --replace --yes
   ```

6. Review the returned transaction and publish only that ID:

   ```text
   sshctl --json push --only <transaction-id>
   ```

This sequence makes the remote baseline explicit before a new reviewed
transaction is created. There is no force flag, automatic repair, evidence
deletion, or empty-ledger overwrite path.

<!-- documentation-contract: historical-begin -->

## Historical documentation follow-up

Before the public documentation update, this plan required removal of the
then-current bare-push compatibility wording, documentation of `action=noop`
and the identity-HEAD/zero-PUT counts, and inclusion of the reviewed recovery
sequence above. It also prohibited copying the migration-era wording in
`README.md`, `README.en.md`, and older `RELEASE_NOTES.md` sections into a v2
release unchanged. Issue #25 superseded that wording with the current explicit
scope contract.

<!-- documentation-contract: historical-end -->
