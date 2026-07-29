# Issue 23 durable publication intent

`internal/inventorytransaction` owns publication intent, exact-ID
finalization, reconciliation, and recovery. `internal/synctransaction` continues
to own configuration, remote identity comparison, conflict evidence, and the
opaque HTTP transport. The sync server remains inventory-unaware.

## Additive encoding and location

One outstanding publication is represented at
`$SSM_CONFIG_DIR/publishing-intent.json` (normally
`~/.config/ssm/publishing-intent.json`). A new publication reconciles an
existing recovery record before selecting another scope.

Version 1 is a private JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `version` | Encoding version `1`. Unknown versions stop recovery. |
| `state` | `prepared`, `ready`, `ambiguous`, `divergent`, or `finalization_failed`. |
| `scope` | `only` or the invocation-start snapshot `all`. |
| `transaction_ids` | Exact stable IDs in original ledger order. |
| `transactions` | The existing secret-free ID/alias/operation/time receipt metadata, in the same order. |
| `prerequisite_remote_exists` | Distinguishes no remote blob from an identity. |
| `prerequisite_remote_identity` | Lowercase SHA-256 content identity when a prerequisite exists. |
| `target_encrypted_blob_identity` | Lowercase SHA-256 identity of the exact encrypted bytes prepared for PUT. |
| `observed_remote_exists` | Present for divergent recovery evidence. |
| `observed_remote_identity` | Safe lowercase SHA-256 divergent identity. |
| `created_at` | UTC preparation time. |

The first `prepared` replacement occurs before cloud-configuration parsing,
HEAD, or PUT. It binds the exact scope, target identity, and last confirmed
cached prerequisite. After HEAD confirms the current prerequisite, a second
`ready` replacement is durably committed before PUT. A crash before that
second replacement is known to be pre-send and safely returns the exact scope
to pending.

Every replacement uses a private temporary file, file flush, atomic rename,
and supported directory durability. Unix flushes the containing directory
after rename/removal. Windows flushes the file before atomic replacement; Go
does not expose a portable directory-handle flush, so no stronger Windows
directory-flush claim is made.

The encrypted vault serialization and sync request body are unchanged. Older
binaries ignore the additive sidecar and can still read the vault. Rolling
back while an intent is outstanding is not recovery-safe because an older
binary cannot reconcile it and may repeat a confirmed PUT; reconcile with this
version before rollback.

## Privacy analysis

The intent contains no connection objects, network addresses, usernames,
passwords, saved-key names or material, master passphrases, tokens, cloud
configuration, encrypted blob bytes, plaintext inventory, or decrypted vault
data. It contains only scope, the already-public mutation receipt metadata
(ID, alias, operation, and time), timestamps, state, and validated content
identities. Malformed, unknown-version, or unsupported non-content remote
identities stop instead of being copied into the record or printed as recovery
metadata.

The PUT remains `application/octet-stream` containing only the encrypted vault
projection. The server receives neither the intent nor pending-ledger fields.

## State transitions

Remote target identity equality is the only publication commit point.

| Durable state and event | Network action | Local ledger/result |
| --- | --- | --- |
| No intent; scope selected | None | Persist `prepared`; all selected IDs remain pending. |
| `prepared`; prerequisite HEAD confirmed | HEAD only | Persist `ready` with the exact observed prerequisite. |
| `prepared`; restart/status | None | Remove intent; exact IDs remain ordinary pending. |
| `ready`; pre-send failure or explicit rejection | No PUT, or one rejected PUT | Remove intent; exact IDs remain pending. |
| `ready`; transport/response loss | At most one PUT attempt | Persist `ambiguous`; exact IDs remain pending. |
| `ready`/`ambiguous`; remote equals prerequisite | HEAD only | Status returns the scope to pending. A publication retry re-encrypts and sends only the recorded IDs, never new pending IDs. |
| `ready`/`ambiguous`; remote equals target | HEAD only | Atomically finalize only recorded IDs, confirm sync metadata, then remove intent. |
| Any sent state; remote is a third identity | HEAD only | Persist `divergent` evidence; preserve local ledger and remote blob; never PUT. |
| Target confirmed; local save fails | No additional network required | Persist `finalization_failed`; its durable target confirmation retries exact local finalization on restart, including offline status. |
| Local save completed; crash before intent removal | No additional PUT | Restart observes target and already-absent IDs, confirms metadata, and removes intent. |

New mutations appended after intent creation remain in the encrypted local
vault. Finalization rebases their pending base onto the exact confirmed
projection and leaves their IDs/order untouched.

## Crash and reconciliation evidence

`TestPublicationIntentCrashMatrix` uses the compiled CLI, process termination,
a temporary private home, and a fault-injectable opaque sync endpoint. It
covers:

1. before and after initial intent persistence;
2. after confirmed-prerequisite persistence and immediately before request
   send;
3. after the request body is sent but before remote commit;
4. after remote commit but before response;
5. after response receipt;
6. before and after local finalization;
7. explicit rejection and a divergent third identity;
8. invocation-start `--all` retry with a new pending mutation.

`TestPublicationReconcilesLostResponse` commits the encrypted target, drops the
response, appends a new mutation, and proves restart finalizes the original ID
once without another PUT. `TestPublicationReconcilesFinalizeFailure` confirms
the target, injects a local finalization failure, and proves restart finalizes
once without republishing.

Tests decrypt captured blobs only inside the test process and compare safe
names/digests. Failure messages never print decrypted vault values.

## Bounded limitations

- Restart reconciliation requires the current server contract: HEAD/PUT
  identities are lowercase SHA-256 identities of encrypted blob bytes. A
  missing identity or arbitrary opaque ETag is unsupported and stops before
  finalization or overwrite.
- Reconciliation requires readable private local persistence and the local
  master passphrase. It never asks the server for plaintext and never makes the
  server inventory-aware.
- This ticket does not change the separately owned legacy mutation migration
  described in the Issue 22 ownership document.
