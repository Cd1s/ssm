# Issue 29 three-module contraction evidence

This note records the bounded contraction completed after the stream,
transfer, sync, inventory, publication, and provenance migrations. It is an
implementation record; public CLI behavior and the approved breaking-change
inventory are unchanged.

## Ownership and dependency graph

Before the final deletion, command callers still routed every online inventory
read through command-owned refresh wrappers and routed redaction through
command aliases:

```text
cmd/ssm list/run/map/put/get/check/doctor/host/key/import
  -> pullIfChanged -> refreshVaultIfChangedResult -> synctransaction.Refresh
cmd/ssm host
  -> refreshHostVault -> synctransaction.Refresh
cmd/ssm host error paths
  -> redactError/redactString -> machinecontract.Redact*
```

The contracted graph is direct and one-way:

```text
cmd/ssm (parse, invoke, success shaping, process entry)
  ├─> internal/machinecontract
  ├─> internal/synctransaction
  ├─> internal/inventorytransaction
  └─> existing mechanism packages

internal/machinecontract -> internal/synctransaction, internal/privatepath
internal/synctransaction -> internal/cloud, internal/config
internal/inventorytransaction -> internal/config, internal/machinecontract,
                                 internal/privatepath, internal/ssh,
                                 internal/synctransaction
```

The checked `TestDeepPolicyOwnershipContraction` parses production Go syntax
and verifies this dependency direction. It also rejects direct command calls
to cloud publication/refresh mechanisms and direct JSON output encoders.

## Deleted command policy

| Deleted caller policy | Former command seams | Owner now used directly |
| --- | --- | --- |
| Refresh invocation wrappers | `pullIfChanged`, `refreshVaultIfChanged`, `refreshVaultIfChangedResult`, `refreshHostVault` | `synctransaction.Transaction.Refresh`; command process wiring still classifies/writes through `machinecontract` |
| Redaction aliases | `redactError`, `redactString` | `machinecontract.RedactError`, `machinecontract.RedactString` |

The command call sites now invoke the concrete sync transaction and send any
failure to the machine-contract writer. No cloud configuration, ETag, pull,
conflict, freshness, or cache decision is reconstructed in those callers.
Earlier migration records (`issue-19`, `issue-20`, `issue-22`, `issue-24`, and
`issue-23`) document deletion of the remaining duplicate classification,
transaction, projection, publication-intent, and rollback seams.

## Retained command responsibilities

- Argument/help parsers validate syntax and select a semantic machine-contract
  `Kind`; the owning module still supplies stable codes, stages, hints,
  redaction, framing, and exits.
- `syncTransaction` only wires global offline state, the clock, and the pool /
  decrypted-snapshot invalidation callback into `synctransaction.New`.
- `run*` functions invoke concrete module methods and construct typed
  command-specific success payloads. Host verification/push adapters retain
  their established typed fields while delegating failure metadata and
  rendering to `machinecontract`.
- Existing SSH, vault, cloud HTTP, transfer, host-key, sync-server, and update
  implementations remain mechanism modules; no protocol or security workflow
  was flattened.

## Structural and compiled evidence

The AST gate proves multiple meaningful policy paths in each owner (failure
classification/redaction/rendering and exit mapping; sync configuration,
refresh, publication identity, and stream cadence; inventory candidate,
dependency, projection, publication, and reconciliation paths), rather than
relying on line counts or source-text markers.

The exact issue suite is:

```text
test -z "$(gofmt -l .)"
go test ./... -run 'TestDeepPolicyOwnershipContraction|TestCompiledCLIContractMatrix|TestEveryPushPathUsesInventoryTransactions' -count=1
```

The contraction test was first run on the pre-deletion tree and failed on the
six named command helpers above (RED). After deletion, the same suite passed
(GREEN); the compiled CLI and push-path fixtures remained green.
