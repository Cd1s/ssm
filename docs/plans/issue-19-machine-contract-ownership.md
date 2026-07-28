# Issue 19 machine-contract ownership

This migration preserves the compiled contract characterized by issue 17.
`internal/machinecontract` is the single policy owner; command packages retain
argument parsing and typed command-specific results.

## Before and after

| Former owner | Former responsibility | New single owner |
| --- | --- | --- |
| `cmd/ssm/machine.go` (`writeMachineError*`, `writeCLIError*`) | Generic failure envelopes, human-vs-JSON placement, and indentation | `machinecontract.Classify`, `Render`, `WriteJSON`, and `WriteHuman` |
| `cmd/ssm/hosts.go` (`hostErrorContract`, anonymous verification/push envelopes, `writeHostJSON`) | Host code/stage/hint/exit switches and host failure serialization | Host `Kind` rows, `Metadata`, `ProcessExit`, and the JSON/human renderers |
| `internal/ssh/errors.go` (`ClassifyError`, `PrintAgentError`, `ExitCodeFor`, code/exit constants, and `ClassifiedError`) | SSH dial, host-key, auth, session, human, and process-exit policy | `ClassifySSH`, `WriteHuman`, and `ExitForError`; only the mechanism-facing `ClassifyError` function remains, with no compatibility constants, type aliases, or public values |
| `internal/ssh/run.go` | Inline session/remote/script classification, interpreter marker policy, human failure fields, and a private JSON encoder | Execution `Kind` rows, `ClassifyRunExecution`, the stable marker helpers, `RenderRunFailure`, `ResultMetadata`, `ProcessExit`, and `WriteJSON` |
| `internal/ssh/check.go`, `doctor.go`, and `map.go` | Copied failure fields, fallback labels, stream placement, stderr-derived hints, aggregate exits, and private JSON encoders | `ClassifyCheck`, concrete `RenderCheckFailure`/`RenderDoctorFailure`/`RenderMapFailure` projections, command-specific `Kind` rows, `Metadata`, `AggregateResultExit`, and `WriteJSON` |
| `cmd/ssm/stream.go` (`writeStreamError`) | Stream failure envelopes, compact encoding, and terminal exits | Stream `Kind` rows, `WriteNDJSON`, `ResultExit`, and `ProcessExit` |
| `internal/ssh/filecopy.go`, `resume.go`, and `dirsync.go` (`TransferError` literals) | Transfer code/stage/hint tuples | Transfer/resume `Kind` rows; `TransferError` carries the concrete classified failure without owning public values |
| `cmd/ssm/connections.go` (anonymous put envelope and transfer switch) | Transfer fallback classification, pre-BC-7 failure fields, and download envelope | `ClassifyTransferOperation`, `ClassifyDownload`, `TransferMetadata`, and the shared renderers |
| `internal/ssh/hostkey.go` (`HostKeyOperationError`) and `cmd/ssm/hostkey.go` (type switch and anonymous envelope) | Host-key operation taxonomy and rendering | Host-key `Kind` rows, `ClassifyHostKeyOperation`, `Metadata`, and the shared renderers |
| `cmd/ssm/request.go`, `cloud.go`, `sshctl.go`, and `main.go` | Request/argument/unlock/sync/panic tuples and separately hard-coded exits | Context-specific `Kind` rows, `Classify`, `ProcessExit`, and the shared renderers |
| `cmd/ssm/sshctl.go` (`printError`) including update callers | Generic internal JSON/human failure rendering | `GenericFailure` plus `WriteClassified`, `WriteFailure`, and `ProcessExit` |
| `cmd/ssm/sshctl.go` (anonymous status document sent through the success writer) | Failed-status serialization and exit selection | Named `statusResult` plus `WriteFailure`; successful status still uses the unchanged typed-success path |

## Compatibility details retained

- `Failure.Exit` is serialized metadata. `ProcessExit` separately retains the
  historical host-command cases whose process exit differs from serialized
  `exit`.
- JSON documents remain indented, NDJSON remains compact and one value per
  line, and human failure diagnostics are written to stderr.
- Global `--json` does not convert historical raw usage, flag-parser, or cloud
  required-field failures into a new document. A private renderer policy in
  the module retains their exact historical stream and bytes while leaving
  established machine-aware failures unchanged.
- `login`, `register`, and `server` retain raw `-h`/`--help` bytes on stderr
  and exit 0, including with global `--json`; `WriteFlagHelp` owns that
  placement and exit.
- The pre-BC-3 stream startup document still uses the JSON-document renderer.
- `TransferMetadata` retains the pre-BC-7 required fields and field order.
- Download classification retains the requested alias in the machine document
  and the resolved alias in legacy human diagnostics without a caller-owned
  second classification.
- Put classification retains the typed pre-BC-7 machine tuple while deriving
  the legacy human code/message/hint/alias/address projection from the same
  production context for both carried and fallback transfer errors. Carried
  session/auth/permission-shaped errors retain their legacy exit-255
  projection.
- Typed run, check, doctor, map, host, status, transfer, and host-key success
  payloads remain command-specific and are serialized without reflection or
  known-value redaction.
- Failed status retains its existing status fields and omissions, but is
  sanitized by the failure renderer immediately before serialization.
- A remote execution result with exit 255 keeps `error=remote_failed` and
  `stage=remote_execution`; exit value alone is never treated as a connection
  failure.
- Exact-alias suggestions remain output-only candidates and are never used for
  selection.
- Legacy human failure bytes and their stdout/stderr placement are selected by
  concrete module renderers; command code supplies typed projection data and
  retains only success layouts.
- Typed run, check, doctor, map, host, transfer, and host-key writers keep their
  command-specific layouts and sanitize only failed results immediately before
  human or machine failure formatting. Successful remote stdout/stderr and
  typed success payloads retain their issue 17 bytes, including values a caller
  intentionally supplied or echoed. Captured stdout/stderr included in a failed
  result is sanitized only at that failure-rendering boundary. Direct SSH and
  tar diagnostics are spooled until the operation outcome is known in
  bounded-memory, private temp-file-backed spools: successful streams are
  replayed byte-for-byte, while failed or cancelled streams pass through the
  module's split-write/private-key-safe redacting writer. One spool per
  destination preserves local/remote transfer diagnostic ordering, and every
  replay/error path removes the temporary file.
- Credential assignments use an escape-aware quoted-value scanner, including
  outer-escaped quotes and escaped JSON carried by `config`, `request_body`,
  and `decrypted_inventory`; `master_pass`/`masterPass`, short explicitly known
  values, and multiple fragmented structures use the same boundary.
- Typed success rendering propagates writer errors; the legacy human
  `Error: ...` fallback and exit 1 remain observable when stdout rejects a
  JSON document.
- The reviewed issue 17 failure fixture is consumed by a 14-row human and
  machine acceptance matrix that checks exact bytes, fields, omissions,
  placement, cardinality, and process exits. It includes the Windows unknown
  dial case, remote exit 255, the pre-BC-3 startup document, the pre-BC-7
  transfer document, and exact alias candidates. Compiled production-adapter
  cases additionally cover legacy global-JSON raw bytes, carried/fallback
  put/get failures in human and machine modes (including redirects and carried
  session/permission exits), failed status, non-captured run redaction,
  successful run replay, directory fallback ordering, and exit-0
  upload-tar/download-tar/single-file diagnostic streams.

Deleting `internal/machinecontract` now removes the only definitions of public
failure metadata, SSH/transfer/host-key classification, redaction, JSON and
NDJSON framing, human failure rendering, placement, and process-exit policy.
