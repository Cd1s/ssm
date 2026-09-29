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
- **Background process.** Observes the remote identity with a 5 second request
  bound. Only when it changed does it take the publication lock, re-read local
  facts, and pull. It uses the same conflict protection as before: a diverged
  local vault is preserved, evidence is saved, the outcome is recorded with
  `cause=conflict`, and nothing is overwritten or published. It leaves local
  state alone while a publication holds the lock or an unreconciled publishing
  intent exists.
- **Explicit `sync`, `pull`, and `push`** stay strict: failure is failure, and
  their outcome updates the state.
- **Writes and publication** are unchanged: mutations stay pending until
  `push --only <transaction-id>` or `push --all`, and divergence detection stays fail-closed.
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
A background pull replaces the vault file atomically under the publication
lock, but local mutation commands do not take that lock between loading and
saving the vault. If a remote change is pulled inside that window (roughly the
vault decrypt-and-encrypt time of one mutation command), the mutation command's
save can overwrite the pulled vault while the cached remote identity already
names the pulled version, so a later `push` would not see a divergence.
Concurrent mutation commands in v2.0.2 share the same hazard; the background
process makes it reachable without a second human. Serializing local mutations
with the publication lock is a recommended follow-up.
