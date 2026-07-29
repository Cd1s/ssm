# Issue 21 stream contract migration

This document records the BC-3 and BC-6 migration implemented by issue 21.
It does not change regular command output or implement any inventory-transaction
work from issues 22 through 25. The checked byte/count fixture is
`cmd/ssm/testdata/compiled_contracts/v2_stream_migration.json`.

## Ownership and ordering

`internal/synctransaction.Stream` is the process-lifetime policy owner for
stream initialization, explicit offline behavior, positive online refresh
validation, and refresh cadence. `cmd/ssm` parses the duration, invokes that
module before each non-empty line, and loads a replacement decrypted snapshot
only when the module reports `Changed`.

The synchronization transaction atomically commits a changed opaque encrypted
blob and invokes its invalidation callback before returning the changed result.
The production callback closes the complete process-scoped SSH pool and then
invalidates the unlocked vault cache. Consequently command orchestration cannot
load or execute with the replacement snapshot until `ssh.ClosePool` has
returned. Pool close takes an exclusive lifecycle gate while acquisition holds
its shared side through entry selection and locking, so no new entry can be
acquired while any entry from the prior pool is still being closed. Per-entry
locks continue to allow unrelated destinations to establish concurrently.

Every stream failure and command result is rendered by
`internal/machinecontract` as NDJSON. The command layer does not own JSON
encoding, stable field selection, redaction, or process-exit classification.

## BC-3 framing matrix

The example is a startup refresh failure with stdin held open. Both versions
perform one `HEAD`, no `GET`/`PUT`, consume no input line, and exit 1.

| Property | Before BC-3 | After BC-3 |
| --- | --- | --- |
| First byte | `{` followed by newline | `{` followed by `"ok"` |
| Framing | one indented JSON document | one compact NDJSON record |
| Physical stdout lines | 8 | 1 |
| JSON values/results | 1 | 1 |
| Ready/summary/footer | none | none |
| stderr | empty | empty |
| Input consumed | 0 non-empty lines | 0 non-empty lines |

Before:

```json
{
  "ok": false,
  "error": "sync_pull_failed",
  "message": "sync refresh failed: remote refresh did not commit",
  "hint": "fix sync connectivity or retry explicitly with --offline",
  "stage": "sync_pull",
  "exit": 1
}
```

After, including its terminal newline:

```text
{"ok":false,"error":"sync_pull_failed","message":"sync refresh failed: remote refresh did not commit","hint":"fix sync connectivity or restart explicitly with --offline","stage":"sync_pull","exit":1}
```

Master-pass, vault-unlock, argument, configuration, initial refresh, and later
refresh failures use the same compact framing. A later refresh failure is the
triggering non-empty line's only result and stops the stream without a footer.

## BC-6 refresh and accepted-flag matrix

| Invocation | Before BC-6 | After BC-6 |
| --- | --- | --- |
| online, omitted `--refresh` | accepted; default 30 seconds | unchanged |
| online, positive `--refresh` | accepted | unchanged |
| online, `--refresh=0` | accepted; startup refresh only | rejected before unlock refresh, stdin consumption, or SSH |
| global `--offline`, positive refresh | accepted; cached snapshot | accepted; one fixed cached snapshot |
| global `--offline --refresh=0` | accepted | accepted; canonical fixed-snapshot form |
| command-local/non-global offline spelling | not a stream option | unchanged |

For online zero refresh, the former two-line fixture consumed two non-empty
requests, performed one startup `HEAD`, and used one TCP connection with two
SSH sessions. It now consumes zero input, performs zero sync requests and zero
SSH work, exits 2, and emits exactly:

```text
{"ok":false,"error":"invalid_arguments","message":"--refresh=0 requires explicit global --offline","hint":"use sshctl run \u003calias\u003e --stream [--refresh 30s]","exit":2}
```

Choose a positive interval when remote revocation must be observed. Choose
global `--offline --refresh=0` only after explicitly accepting cached state for
the entire process lifetime.

## Counted runtime evidence

| Scenario | Input results | `HEAD` / `GET` / `PUT` | TCP / SSH sessions | Terminal behavior |
| --- | ---: | ---: | ---: | --- |
| positive interval, unchanged inventory | 2 success | 2 / 0 / 0 | 1 / 2 | normal EOF |
| changed inventory | 2 success | 2 / 1 / 0 | 2 / 2 | old pool closed before second run |
| due refresh failure | 1 failure | 2 / 0 / 0 | 0 / 0 in the failure fixture | stop on triggering line |
| explicit offline fixed snapshot | 2 success | 0 / 0 / 0 | 1 / 2 | replacement file ignored for process lifetime |
| remote exit 255, then success | 3 command results plus one decode failure | 0 / 0 / 0 offline | 1 / 3 | exit 255 remains `remote_failed`, next command succeeds |

The changed-inventory compiled matrix covers alias addition, removal and order,
address/user/port replacement, password material, saved-key material,
authentication reference, and host-key trust re-evaluation. An alias removed
between lines returns exact `alias_not_found`; a similar remaining alias is
never selected. An unrelated inventory or saved-key change still closes the
whole pool, so the active alias also redials.

`--no-reuse`, script/argv transport, exact alias lookup, host-key verification,
result ordering, and ordinary one-shot command rendering are unchanged. The
existing SSH matrix remains the compatibility gate for those mechanisms.

## Line-oriented consumer migration

Consumers should read stdout one line at a time from process start and decode
each non-empty line as one complete JSON value. Do not wait for a ready record
and do not expect a summary or footer. Treat the first record as terminal when
initialization fails. After successful initialization, associate each record
in order with one submitted non-empty line; empty input lines have no response.
A refresh failure belongs to the line that triggered the due refresh and ends
the process, so consumers must not retry later queued lines on the same stream.

Branch on canonical `error` and `stage`, not `exit` alone. In particular,
`error=remote_failed`, `stage=remote_execution`, `exit=255` means SSH transport
succeeded and the remote process returned 255.
