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

The ownership analyzer also has a checked adversarial RED/GREEN loop in
`TestDeepPolicyOwnershipAnalyzerAdversarialFixtures`. Before hardening, its
fixtures were accepted when they used aliased or multiple dot imports,
function-value selector references, renamed/chained refresh wrappers, policy
closures, or dead owner paths. A second RED caught receiver identifiers such
as `tx := syncTransaction(false); tx.Refresh()` and typed transaction/stream
parameters, while a separate shallow fixture caught an unrelated branch being
counted as an owner's policy decision. The GREEN analyzer resolves ownership
by import path, tracks reviewed command invocation boundaries through a local
call graph (including closures), uses conservative policy-selector matching
instead of scope-insensitive receiver provenance, treats
`synctransaction.New` as an owner construction seam while retaining only the
reviewed `syncTransaction` factory, and only counts reachable, meaningful
decision branches.
The focused ownership and compiled/push suites plus the full `cmd/ssm` test
run passed after these checks were added.

The third remediation cycle first recorded this exact RED command:

```text
go test ./cmd/ssm -run '^TestDeepPolicyOwnershipAnalyzerAdversarialFixtures$' -count=1 -v
```

The failing subtests were `renamed_local_factory_returning_syncTransaction_remains_a_seam`,
`stored_transaction_and_stream_fields_retain_ownership`,
`transaction_and_stream_aliases_retain_ownership`,
`transaction_and_stream_method_expressions_remain_policy_references`,
`function-value_syncTransaction_factories_remain_policy_references`,
`named_constant_false_is_dead`, `for_false_is_dead`,
`panic_terminates_policy_path`, `os.Exit_terminates_policy_path`,
`runtime.Goexit_terminates_policy_path`, and
`unrelated_returns_do_not_satisfy_policy_decisions`.

The corresponding GREEN command is:

```text
gofmt -w cmd/ssm/deep_policy_ownership_test.go
go test ./cmd/ssm -run '^(TestDeepPolicyOwnershipContraction|TestDeepPolicyOwnershipAnalyzerAdversarialFixtures)$' -count=1
```

The correction uses conservative selector/method-name matching outside the
explicit invocation boundaries, import-path-qualified construction matching
for `synctransaction.New` (so unrelated `errors.New` remains valid), and
rejects local `syncTransaction` factory uses outside its reviewed boundary.
Reachability now resolves package and local named boolean constants, handles
`for false`, stops after `panic` and imported `os.Exit`/`runtime.Goexit` (with
aliases), and requires owner-specific calls/selectors rather than generic
returns. The only push wiring boundary added is
`pushTransactionScopeInSession`: it directly places the retained
`syncTransaction(false)` factory into `inventorytransaction.Options`; its
outer `pushTransactionScope`/`pushTransactions` helpers only delegate and are
not grandfathered as policy owners. A positive wiring fixture covers this
boundary, while renamed factories remain rejected.

The final scope-soundness RED used the same focused command and exposed
`terminator_imports_remain_file-scoped`,
`local_terminator_alias_shadowing_remains_ordinary_code`, and
`constant_shadowing_remains_block_scoped_and_sequential`. GREEN was then
verified with:

```text
gofmt -w cmd/ssm/deep_policy_ownership_test.go
go test ./cmd/ssm -run '^(TestDeepPolicyOwnershipContraction|TestDeepPolicyOwnershipAnalyzerAdversarialFixtures)$' -count=1
```

The final all-package ownership/compiled/push suite and full `go test
./cmd/ssm -count=1` also passed.
