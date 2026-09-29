---
status: accepted
---

# Read inventory locally and sync in the background

The sync service is a replication channel, not a gate. By default
(`sync_mode: local_first`) an inventory read uses the local vault and never
sends a sync request. When an automatic sync is due, the command atomically
claims the attempt in `sync-state.json` and starts one detached
`sshctl sync --background` process; the command neither waits for it nor is
affected by its result. `sync_mode: strict` keeps the v2.0.2 behavior of
refreshing online before every read.

## Decision and reason

The maintainer decided that "the central server is only for synchronization; it
must not stand in front of every command, and the tool must work offline". The
evidence behind it: a `HEAD` request before every call added 300-600 ms to each
command and, against an unreachable endpoint, either failed every command or
blocked it for the full 15 second timeout. A two week incident showed the other
side of the old policy: after an outage the recovery hint was `--offline`, agents
kept the flag for 2,873 calls after the service recovered, and nothing told them
the inventory was old. Refusing to fall back did not prevent silent stale
inventory; it moved the silence into a flag.

## Considered options

- Keep refresh-before-read and only shorten its timeout. Still puts the
  service's availability and latency on every command.
- Fall back to the cache when the refresh fails. Hides the failure per command
  and still pays the request on the healthy path.
- Sync inline after the command. Still couples exit latency to the service and
  cannot run for commands that never return.
- Local reads with a rate-limited, backed-off, detached background sync, and
  visible freshness. Selected.

## Design

- **State.** `sync-state.json` (private, atomically written, guarded by a
  short exclusive-create lock file) records `last_attempt_at`,
  `last_success_at`, `next_attempt_at`, `consecutive_failures`, `last_error`
  (`cause`, redacted address-free `message`, `at`), and `in_flight_until`, the
  atomic claim. A claim expires after two minutes so a killed process cannot
  block sync forever.
- **Schedule.** Success schedules the next attempt one `sync_interval` later
  (default 10 minutes). Failure backs off exponentially from 30 seconds to one
  hour. Commands inside the window neither request nor spawn.
- **One install path for every pull.** Explicit `sync`/`pull`, strict-mode refresh, reviewed `--adopt-remote`, and the background sync all
  download outside any lock, then take the vault write lock, re-read the local
  and cached remote identities, fail closed on divergence (conflict evidence,
  nothing overwritten), and only then write the vault together with the cached
  remote identity. The lock is never held across network I/O.
- **Background process.** Observes the remote identity with a 5 second request
  bound. Only when it changed does it download (outside any lock), then take
  the vault write lock only to re-read local facts, compare identities, and
  replace the file. It uses the same conflict protection as before: a diverged
  local vault is preserved, evidence is saved, the outcome is recorded with
  `cause=conflict`, and nothing is overwritten or published. It leaves local
  state alone while a publication holds the lock or an unreconciled publishing
  intent exists.
- **Explicit `sync`, `pull`, and `push`** stay strict: failure is failure, and
  their outcome updates the state.
- **Writes and publication** are unchanged: mutations stay pending until
  `push --only <transaction-id>` or `push --all`, and divergence detection stays fail-closed.
- **Additional safeguards.** The background process refuses a download
  without a valid encrypted-vault header, is reaped by its parent, runs from
  the filesystem root, and truncates recorded messages on UTF-8 boundaries. The
  state-file lock is a kernel lock that a crash cannot leave stale.
- **Visibility.** `status` never fails because of sync and reports
  `remote_state`, `last_successful_sync`, `last_sync_error`, `next_sync_attempt`,
  `cache_age_seconds`, and `inventory_stale`. Staleness (`stale_after`, default
  seven days, measured from the newest confirmed pull, push, or successful
  background check) adds `inventory_stale` to `run` JSON and one stderr line to
  human reads.
- **Offline.** `--offline` and `SSM_OFFLINE=1` are equivalent: they skip
  configuration parsing, network access, and background sync.
- **Streams.** `run --stream --refresh` reloads its snapshot when the vault
  identity changed underneath it and starts a due background sync; sync failures
  never stop the stream.

## Relationship to earlier decisions

This revises the "refresh failures stop online inventory operations; cached
inventory is never selected silently" policy of the sync-transaction ownership
work (#6, #20) for the default mode. What #6 protected against, silent
staleness, is now addressed by mandatory visible freshness metadata instead of
a per-command gate. `strict` keeps that earlier policy unchanged for callers
that need it, so the change is reversible with one setting. Sync configuration
that is present but invalid is still fatal in both modes, and the module
boundaries of [ADR 0001](0001-put-v2-policy-in-three-deep-modules.md) are
unchanged: `synctransaction` owns the schedule, claim, and recorded outcome,
while the command layer only composes the process spawn with the publication
lock.

## Consequences

The first read after `login` on a machine with no vault sees local (possibly
empty) inventory; run `sshctl sync` once to pull, or wait for the background
sync. `update.Auto` still runs inline and is not part of this decision.
Local mutations, publication finalization, and every pull (background and
explicit) are serialised
by one short cross-process vault write lock (`vault-write.lock`, separate from
`publication.lock` so a mutation is still allowed while a publication is in
flight). The background process downloads outside
the lock, then takes it only to re-read local facts, compare identities, and
replace the file, so a local mutation saved earlier is seen as divergence and
kept. Every command that saves the vault after a local mutation (`host`
add/update/upsert/remove, `remove`, `keys remove`, `import-json`, request-v1
host mutations) holds the lock from an identity check through the save and
refuses with a clear error if the vault file is no longer the version it loaded
(nothing is saved; retry). Lock waits are bounded (5 seconds) and report that
the vault is busy. The cached remote identity therefore always names the vault
that was actually pulled, and a later publication still fails closed when the
remote moved.
