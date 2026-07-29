# Issue 20 sync transaction ownership and BC-1 migration

`internal/synctransaction` is the single policy owner for inventory
synchronization. It operates on encrypted bytes and opaque blob identities;
decrypted inventory remains outside the module.

## BC-1 old/new compiled matrix

The issue 17 compiled baseline at `de66f23` characterized the old split before
migration. Missing configuration continues to mean unconfigured. For a present
malformed or unreadable `cloud.json`, the command-by-command migration is:

| Compiled command | Old online behavior | New online behavior |
| --- | --- | --- |
| `ssm list`, `sshctl list` | Silently used cached inventory | `sync_config_error`, `stage=sync_config` |
| `sshctl host list/search/show` | `sync_pull_failed`, `stage=sync_pull` | `sync_config_error`, `stage=sync_config` |
| `ssm keys` | Did not refresh first | `sync_config_error`, `stage=sync_config` |
| `sshctl run/plan`, request-v1 `run/plan` | Silently used cached inventory | `sync_config_error`, `stage=sync_config` |
| `sshctl map`, `sshctl check`, request-v1 `check` | Silently used cached inventory | `sync_config_error`, `stage=sync_config` |
| `sshctl put/get`, request-v1 `put` | Silently used cached inventory | `sync_config_error`, `stage=sync_config` |
| `sshctl host-key inspect/accept` | Silently used cached inventory | `sync_config_error`, `stage=sync_config` |
| `sshctl status`, `sshctl doctor`, request-v1 `doctor` | Silently used cached inventory | `sync_config_error`, `stage=sync_config` |
| `sshctl host add/update/upsert/remove`, request-v1 host mutations | `sync_pull_failed`, `stage=sync_pull` | `sync_config_error`, `stage=sync_config` |
| `ssm remove`, `ssm keys remove`, `ssm import-json` | Did not refresh consistently before mutation | `sync_config_error`, `stage=sync_config`, before mutation |
| `sshctl push`, `ssm push` | Configuration failure was projected as a push failure | `sync_config_error`, `stage=sync_config` |
| `sshctl pull/sync`, `ssm pull` | Used the pull command's configuration projection | `sync_config_error`, `stage=sync_config` |
| `ssm pull-if-changed`, `ssm remote-hash` | Used generic command-specific configuration errors | `sync_config_error`, `stage=sync_config` |
| `sshctl run --stream` initialization and refresh | Initialization could use cache; refresh used stream pull failure | `sync_config_error`, `stage=sync_config` |

The stable failure hint is `repair sync configuration or retry explicitly with
--offline`. Repair the JSON and its read permissions, or use explicit
`--offline` only after accepting that the cached inventory may be stale.
Configuration contents and credentials are never included in the failure.

## Transaction state tables

Configuration and invocation policy:

| Invocation state | Configuration result | Config read | Sync HTTP | Inventory result |
| --- | --- | --- | --- | --- |
| Explicit global or command offline | `offline` | No | None | One cached snapshot; `remote_state=not_checked` |
| Online, `cloud.json` absent | `unconfigured` | Absence only | None | Characterized cached success; explicit sync operations reject |
| Online, `cloud.json` present but invalid/unreadable | `invalid` | Yes, redacted | None | Canonical configuration failure |
| Online, configured, `auto_sync=false` | `configured` | Yes | None for automatic refresh/publication | Cached success; `remote_state=auto_sync_disabled` |
| Online, configured, automatic sync enabled | `configured` | Yes | Transaction-controlled | HEAD/ETag state table below |
| Explicit pull/sync/push, configured | `configured` | Yes | Transaction-controlled regardless of `auto_sync` | Operation-specific success or canonical failure |

For refresh and pull, `C` is the cached remote identity, `L` is the local
encrypted-blob identity, and `R` is the identity returned by `HEAD`:

| Identity state | Automatic refresh / explicit sync | Explicit pull |
| --- | --- | --- |
| No `C` | `GET`, atomically replace, commit GET identity | Same |
| `R = C` | No `GET`; preserve local state, including local-ahead state | `GET` and atomically replace as explicitly requested |
| `R != C`, `L = C` | `GET`, atomically replace, commit GET identity | Same |
| `R != C`, `L != C` | Preserve `L`, `R`, and `C`; no `GET` | Same |

For push, `P` is the identity of the exact encrypted candidate blob, including
a scoped publication projection. With no `C`, compatibility permits the first
`PUT`. With `R = C`, `PUT P` is allowed. When both `R != C` and `P != C`, the
transaction preserves `P`, `R`, and `C` and performs no `PUT`.

Metadata changes only after confirmed opaque commits:

| Event | Local blob | Cached identity | Conflict evidence | Timestamp | Invalidation |
| --- | --- | --- | --- | --- | --- |
| Failed transport `HEAD`, `GET`, or `PUT` | Unchanged | Unchanged | Unchanged | Unchanged | None |
| Successful changed `GET` | Atomically replaced first | Confirmed GET ETag, or opaque blob hash fallback | Cleared | `last_pull` | Exactly once |
| Successful `PUT` | Unchanged by sync transport | Confirmed PUT ETag, or opaque candidate hash fallback | Cleared | `last_push` | None |
| Two-sided conflict | Preserved | Preserved | `L/P`, `R`, and `C` persisted | Unchanged | None |

## Offline request-count evidence

`TestCompiledSyncStateMatrix` runs both compiled command names across list,
host list/search/show, keys, run/plan/map/check, put/get, host-key, host
mutation, request-v1, status, doctor, import, legacy removals, pull/sync,
pull-if-changed, push, remote identity, and stream initialization. The endpoint
counts `HEAD`, `GET`, and `PUT` separately.

The matrix proves absent configuration remains unconfigured, disabled automatic
sync performs zero HTTP requests, and malformed configuration is the same
secret-safe failure for every online family. Refresh failures stop before
import/removal mutation. An explicit two-sided pull conflict performs one
`HEAD`, no `GET` or `PUT`, and no local encrypted-blob overwrite. A changed
remote encrypted blob performs one `HEAD` plus one `GET`, replaces the local
opaque bytes, invalidates the initially unlocked snapshot, and makes the
compiled list consume the new snapshot.

The compiled push conflict case likewise performs one `HEAD`, no `GET` or
`PUT`, preserves the exact local encrypted bytes, and records the identity of
the exact candidate blob rather than a caller-side re-encryption or plaintext
projection.

The offline case deliberately supplies malformed configuration containing the
request-counting endpoint. Global and host-command offline modes still use the
cached local host, report `offline=true`, `freshness=cached`, cache age and last
operation metadata, and make zero `HEAD`, `GET`, or `PUT` requests. Status and
doctor have equal configuration, offline, freshness, remote, last-operation,
cache-age, and conflict facts. Offline selection therefore occurs before cloud
configuration loading, and a command or stream consumes one fixed encrypted
local snapshot.

## Ownership contraction

| Former owner | Removed policy | New owner |
| --- | --- | --- |
| `cmd/ssm/cloud.go` | configuration-error swallowing, refresh selection, pull invalidation, push transport selection | `synctransaction.Transaction` |
| `cmd/ssm/hosts.go` | independent file probing and refresh/invalidation | `synctransaction.Transaction` |
| `cmd/ssm/sshctl.go` | ETag comparison, freshness, remote state, cache age | `synctransaction.Facts` |
| `internal/ssh/doctor.go` | duplicate configuration, ETag, conflict, and operation-time calculations | supplied `synctransaction.Facts` |
| `internal/cloud` sync paths | cached ETag, conflict evidence, timestamp commits, and auto-push policy | Opaque HTTP `HEAD`/`GET`/`PUT` mechanism only |
| `internal/config.RecordSync` | last-operation selection and timestamp persistence | `synctransaction.Transaction` confirmed-commit path |
| legacy auto-push callers | `auto_sync` selection and configuration probing | `synctransaction.Transaction.AutoPushBlob` |
| command sync failure switches | separate configuration/conflict projections | `machinecontract.ClassifySyncFailure` |
| stream refresh | direct refresh helper policy | the same transaction refresh result and invalidation notification |

The existing HTTP client remains the only production transport. Atomic private
file replacement and opaque HTTP transfer remain mechanism code in
`internal/config` and `internal/cloud`; the transaction owns when those
mechanisms may commit. A changed pull invalidates exactly once after atomic
replacement and before a caller can load a new snapshot. Push preflight
preserves two-sided conflict identities and performs no `GET` or `PUT` when
both sides diverged from the cached identity.
