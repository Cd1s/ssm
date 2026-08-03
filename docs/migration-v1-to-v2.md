# SSM v1 to v2 migration contract

This guide is the operator and machine-consumer contract for the planned
SSM v2.0.0 release. The source version remains v1 until the official release
workflow publishes v2; this document does not mean that v2 is already
available.

[中文](migration-v1-to-v2.zh-CN.md) | [Provenance runbook](update-provenance-runbook.md)

<!-- ssm-v2-migration: guide-begin -->

<!-- ssm-v2-migration: section=prerequisites -->

## Prerequisites and preserved baselines

Before changing a client, identify its current executable, config directory,
sync endpoint, operating system, architecture, and all automation that parses
SSM output. The release gate requires Go 1.25.12, `jq`, `bash`, the official
golangci-lint 2.11.4 binary, the `v1.2.0` lint baseline, and the other tools
reported by `go run ./cmd/verify list`.

Issues [#2](https://github.com/Cd1s/ssm/issues/2) through
[#11](https://github.com/Cd1s/ssm/issues/11) are preserved v1 baselines, not
new v2 work: non-interactive operation, transactional/scoped changes,
observable and resumable transfers, stable machine failures, explicit sync
freshness/offline state, exact alias selection, fingerprint-bound host-key
acceptance, agent-safe invocation, and pre-unlock command help all remain in
force. Request schema v1 remains strict and rejects unknown fields.

<!-- ssm-v2-migration: section=backup-recovery-metadata -->

## Back up encrypted state and recovery metadata

Stop SSM processes that could mutate the same config directory. Make a private,
permission-preserving backup of the encrypted vault and of existing
`remote.etag`, `publishing-intent.json`, `sync-conflict.json`, and Windows
`.old`/`.old.state` executable-recovery records. Do not copy decrypted
inventory or secret contents into tickets, logs, commands, or this checklist.

Retain pending transaction IDs and their order. An outstanding v2 publication
intent must be reconciled by v2 before a v1 executable touches the same state.
An authenticated updater recovery record must be recovered by the updater; it
must not be deleted or renamed by hand.

<!-- ssm-v2-migration: section=automated-preflight -->

## Run automated preflight

From an exact clean candidate checkout, run:

```bash
go run ./cmd/verify ci
go run ./cmd/verify release
```

Require `preflight_passed`, not `completed_with_unavailable`. The major-update
review must also report successful automated checks named
`cloud_configuration`, `pending_recovery`, `untracked_divergence`,
`platform_asset`, and `rollback_readiness`. A local preflight cannot discover
unknown external parsers, crons, deployment wrappers, or agents.

<!-- ssm-v2-migration: section=manual-external-consumer-review -->

## Review external consumers manually

Inventory every external call site. Complete the three manual review checks
reported by `ssm --json update --major`:

- `legacy_bare_push_consumers`: replace bare push with an exact reviewed scope;
- `zero_refresh_online_streams`: choose a strictly positive online refresh;
- `directory_transfer_consumers`: use `direction` and `kind`, and respect
  truthful guarantee values and omissions.

Also confirm one-value JSON versus NDJSON parsing, exact alias handling,
host-key approval, request-v1 strictness, secret file references, and exit-code
handling. A remote command can legitimately exit 255; use `error` and `stage`
to distinguish it from a transport failure.

<!-- ssm-v2-migration: section=staged-canary-rollout -->

## Stage a canary rollout

Keep ordinary v1 automatic updates enabled only for the installed major. On a
backed-up canary, first run the non-installing review:

```bash
ssm --json update --major
```

Review the target, release notes, BC-1 through BC-10, automated checks, manual
checks, rollback guidance, and `authorized:false`/`installed:false`. Only then
authorize that exact canary migration:

```bash
ssm --json update --major --yes
```

`--yes` is valid only with `--major`; neither flag bypasses digest or
provenance verification. Expand the rollout only after the canary passes the
success evidence below.

<!-- ssm-v2-migration: section=success-evidence -->

## Collect success evidence

Retain non-secret evidence showing:

- the exact tag and executable version, platform, and digest;
- the selected asset's valid pinned provenance;
- `go run ./cmd/verify release` returned `preflight_passed` on exact main;
- online status is fresh, or an explicitly approved offline result says so;
- each mutation returned a stable transaction ID and only its reviewed scope
  was published;
- stream consumers observed one compact NDJSON result for each consumed
  non-empty input line; and
- file/directory transfer consumers interpreted the exact v2 fields below.

Never retain credentials, decrypted inventory, vault bytes, private recovery
metadata, or secret-file contents as rollout evidence.

<!-- ssm-v2-migration: section=failure-handling -->

## Failure handling

Stop at the earliest failed gate. Preserve the old executable, encrypted vault,
pending ledger, publication intent, conflict report, and updater recovery
evidence. Do not broaden a push, silently switch offline, requeue stream input,
remove a host key, use an older release after a newer one fails trust, or copy
an unverified binary into place.

An ambiguous publication is resolved only by comparing the durable intent's
prerequisite/target identities with the remote identity. Equality with the
target permits exact-ID finalization; a third identity is divergent and must
remain unmodified for reviewed reconciliation.

<!-- ssm-v2-migration: section=rollback -->

## Rollback

There is no automatic down-migration. A safe v1 reinstall is possible only
when the encrypted vault/on-disk schema is compatible, no v2 publication
intent or Windows updater recovery is outstanding, and all pending IDs and
remote state are either confirmed or intentionally preserved. Restore the
permission-preserving backup and the reviewed v1 executable together.

If remote publication might have committed, if local/remote encrypted
identities differ, if v2-only intent is present, or if rollback metadata cannot
be authenticated, do not mutate further. Reinstall v2 if necessary, reconcile
the exact identities and pending transactions, then decide which reviewed
inventory should survive. Never erase evidence to make v1 start.

<!-- ssm-v2-migration: section=troubleshooting -->

## Troubleshooting

- `sync_config_error` / `sync_config`: repair `cloud.json` and permissions, or
  deliberately accept cached state with global `--offline`.
- `sync_conflict` / `sync_compare`: preserve both encrypted sides and
  `sync-conflict.json`; follow reviewed pull/import reconciliation below.
- `sync_push_failed`: keep the same pending transaction ID and retry only its
  reviewed prerequisites and exact scope.
- `update_recovery_required` / `update_recovery`: stop command dispatch and
  retain authenticated `.old` and `.old.state` evidence until serialized
  recovery restores the exact original.
- `host_key_unknown|host_key_mismatch`: inspect, verify out-of-band, then accept
  the exact observed fingerprint; never remove/rescan automatically.

<!-- ssm-v2-migration: section=stream-cardinality-refresh -->

## Stream framing, cardinality, and refresh

`sshctl run <exact-alias> --stream` uses compact NDJSON from process start. An
initialization failure emits one terminal result without consuming input.
After initialization, each consumed non-empty input line produces exactly one
ordered result; empty lines produce none. A refresh failure is the triggering
line's only terminal result and stops the process. There is no ready, summary,
or footer record.

Online `--refresh` must be strictly positive (30 seconds by default) so
credential, endpoint, alias, and trust revocation can be observed. Any detected
inventory change closes the whole process SSH pool before the new cache is
used. `--refresh=0` is accepted only with explicit global `--offline`, which
skips cloud parsing/network access and holds one fixed cached snapshot.

<!-- ssm-v2-migration: section=mutation-publication-reconciliation -->

## Mutation, publication, and reconciliation

Host add/update/upsert/remove, legacy `ssm remove`, `ssm keys remove`, and
`import-json --merge|--replace` all create reviewable pending transactions.
IDs are stable (`tx_` plus 32 lowercase hexadecimal characters). Imports are
one atomic bulk transaction. No mutation automatically publishes.

Use `sshctl --json status` to review the secret-free ledger. Cross-alias and
saved-key create/replace/rename/delete/prune/reference dependencies are
reported before network I/O. Publish prerequisite IDs explicitly in ledger
order, then the original ID:

```bash
sshctl --json push --only <transaction-id>
```

Use `sshctl --json push --all` only after reviewing its non-empty,
invocation-start ordered set; IDs created later remain pending. Bare push is
invalid. Empty `--all` does one identity comparison and no PUT: equality is a
no-op, while missing/different identities are a preserved `sync_conflict`.

For empty-ledger divergence, preserve private evidence, run
`sshctl --json pull` only when its cached prerequisite makes replacement safe,
then reapply retained local inventory with guarded
`ssm --offline --json import-json <reviewed-file> --merge`. Full
`--replace --yes` needs separate explicit full-replacement review. Publish only
the returned transaction. Durable `publishing-intent.json` reconciliation uses
the exact selected IDs and encrypted-blob identities; it can reconcile only
those IDs and never expands scope.

The production merge-only machine hint is exact:

```text
review sshctl --offline --json doctor and preserve the local vault and sync-conflict.json; run sshctl --json pull to adopt remote, then use guarded ssm --offline --json import-json <reviewed-file> --merge and publish its reviewed transaction with sshctl --json push --only <transaction-id>
```

<!-- ssm-v2-migration: section=update-authorization-trust -->

## Update authorization and trust

Ordinary automatic/manual update is same-major: it selects only a newer stable
release within the installed major. Cross-major availability is reported but
not installed.
`ssm update --major` is review-only; `ssm update --major --yes` is the sole
explicit major replacement path.

Every replacement still needs the selected digest and pinned keyless
provenance for the exact repository, workflow, issuer, tag, subject, and
six-target release manifest. Checksum-only artifacts are rejected. Draft,
prerelease, malformed, incomplete, older, or untrusted releases are not a
fallback. The old executable remains available until verification and atomic
platform replacement succeed. See the
[provenance runbook](update-provenance-runbook.md).

<!-- ssm-v2-migration: section=verification-profiles -->

## Verification profiles

`make check` is exactly the non-mutating `go run ./cmd/verify ci` adapter.
`verify fast` is a convenience subset, not a merge or release gate. `verify ci`
is the complete non-publishing merge profile. `verify release` is its strict
non-publishing superset, including six cross-builds, installer/checksum checks,
and synthetic provenance verification.

Profiles write only private verifier temporary/cache state and receive no
publication credentials. They do not merge, tag, install, replace an
executable, upload, publish, or create a GitHub release. Their exact
prerequisites and runtime boundary are documented in
[the verification manifest](plans/verification-manifest.md).

<!-- ssm-v2-migration: section=all-decisions -->

## Approved architecture decisions

The following register maps every approved decision from D01 through D14 to
operator-visible behavior. The detailed maintainer record remains the
[architecture decision log](plans/ssm-v2-decision-log.md).

<!-- ssm-v2-migration: decision=D01 -->

### D01 — Compatibility is preserved by default

Only BC-1 through BC-10 are approved breaks. CLI, JSON, exits, on-disk state,
platform behavior, and security remain compatible unless one of those rows
explicitly says otherwise; a major number alone never authorizes a break.

<!-- ssm-v2-migration: decision=D02 -->

### D02 — Missing configuration differs from invalid configuration

A missing sync config remains unconfigured. A present malformed or unreadable
config is fatal online; explicit offline mode alone accepts stale cached state
and prevents config parsing and network access.

<!-- ssm-v2-migration: decision=D03 -->

### D03 — Scoped publication has transitive dependencies

Alias ordering and saved-key creation, replacement, rename, deletion, prune,
and reference dependencies are preflighted. Required IDs are safe to report,
but SSM never adds them automatically to a selected scope.

<!-- ssm-v2-migration: decision=D04 -->

### D04 — Remote identity equality is the commit point

A durable non-secret intent precedes transport. Exact transactions become
published only after the target encrypted-blob identity is confirmed; lost
responses and local-finalization failures are reconciled on restart.

<!-- ssm-v2-migration: decision=D05 -->

### D05 — JSON and NDJSON cardinality is exact

Normal machine commands emit one JSON value. Streams emit compact NDJSON from
startup with one result per consumed non-empty line and no ready, summary, or
footer records; terminal refresh failure consumes only its triggering line.

<!-- ssm-v2-migration: decision=D06 -->

### D06 — Every inventory mutation is reviewable

Every mutation creates one pending transaction, including legacy removal,
saved-key removal, and guarded bulk import. No mutation path publishes
automatically; publication is a later explicit operation.

<!-- ssm-v2-migration: decision=D07 -->

### D07 — Unscoped and empty-ledger push cannot publish

Bare push is invalid. Non-empty all uses an invocation-start snapshot, while
empty all performs no PUT and returns either a proved no-op or preserved
divergence requiring reviewed pull/import reconciliation.

<!-- ssm-v2-migration: decision=D08 -->

### D08 — Online streams remain refreshable

Online refresh intervals are strictly positive. Zero refresh requires global
offline mode, which deliberately uses one fixed stale snapshot without cloud
configuration parsing or network access.

<!-- ssm-v2-migration: decision=D09 -->

### D09 — Inventory changes close the whole SSH pool

Any online inventory change closes the complete process-scoped SSH pool before
new cached state can be used. Immediate credential and trust revocation takes
priority over selective connection reuse.

<!-- ssm-v2-migration: decision=D10 -->

### D10 — Three modules own policy exclusively

`machinecontract` owns failure/redaction/framing/exits; `synctransaction` owns
online/offline refresh, transport, conflicts, freshness, and invalidation;
`inventorytransaction` owns mutations, dependencies, projection, durable
intent, finalization, reconciliation, and recovery. Commands only adapt inputs
and success payloads.

<!-- ssm-v2-migration: decision=D11 -->

### D11 — Automatic update never authorizes a major migration

Ordinary replacement remains within the current major. A major migration first
presents release notes, all approved breaks, automated checks, manual checks,
and rollback guidance, then requires explicit `--major --yes` authorization.

<!-- ssm-v2-migration: decision=D12 -->

### D12 — Pinned provenance blocks release

HTTPS and adjacent checksums do not establish release authority. Digest plus
keyless provenance pinned to the repository, workflow, exact tag, subject, and
issuer must pass on every supported platform before replacement.

<!-- ssm-v2-migration: decision=D13 -->

### D13 — One manifest defines verification

One checked-in non-mutating manifest owns profiles, actions, order,
prerequisites, and extensions. CI and `make check` share `verify ci`; release
uses the strict superset, while coverage remains observational.

<!-- ssm-v2-migration: decision=D14 -->

### D14 — Transfer output states truthful guarantees

Direction, kind, and failure stage are explicit. Regular-file detail remains
compatible, while directory fields report unsupported/unavailable guarantees
or omit measurements that the selected protocol cannot truthfully provide.

Direct CLI and request-v1 results use the same success contract:

| Route | Always present after success | Conditional fields | Explicit guarantee or omission |
| --- | --- | --- | --- |
| File put | `ok`, `action`, `alias`, `local`, `remote`, `direction=put`, `kind=file`, `stage=complete`, `bytes_sent`, `integrity`, `atomic`, `resume` | `local_sha256` and `remote_sha256` only with digest verification; `bytes_reused` only with resume | `atomic=true`; integrity and resume state describe the selected protocol; `bytes_received` is omitted |
| Directory put | Common identity fields, `direction=put`, `kind=directory`, `stage=complete`, `bytes_sent=0`, `integrity=not_available`, `atomic=false`, `resume=unsupported` | None | Digest, reuse, and receive-byte fields are omitted; no whole-tree atomicity or integrity is promised |
| File get | Common identity fields, `direction=get`, `kind=file`, `stage=complete`, actual `bytes_received`, `integrity=not_checked`, `atomic=true`, `resume=unsupported` | None | `bytes_sent`, digest, and reuse fields are omitted; atomic means local final-path publication, not end-to-end digest verification |
| Directory get | Common identity fields, `direction=get`, `kind=directory`, `stage=complete`, `integrity=not_available`, `atomic=false`, `resume=unsupported` | None | `bytes_sent`, `bytes_received`, digest, and reuse fields are omitted because tar has no stable payload measure or whole-tree guarantee |

On failure, the canonical envelope remains `ok:false`, `error`, `message`,
`hint`, and `exit`; `direction`, discovered `kind`, and canonical `stage` are
added without changing the classifier. `kind=unknown` is limited to failures
before a protocol kind is known. Staged file/directory recovery preserves the
prior destination when restoration succeeds; if directory restoration also
fails, one backup is retained and no unchanged-final claim is made.

<!-- ssm-v2-migration: section=release-blockers -->

## Release blockers

Initial v2 requires all BC fixtures/matrices, transaction crash/retry and
contraction gates, bilingual migration/security/agent docs, pinned provenance,
all exact release assets, clean authoritative CI, and successful review. The
verification manifest's `migration-extension` must be promoted for
`initial_v2_release`; `preflight_passed` alone is not readiness.

Verification does not merge, tag, upload, publish artifacts, or create a
release. Only the official exact-tag workflow may do those things after all
blockers pass.

<!-- ssm-v2-migration: section=reviewer-mapping -->

## Reviewer mapping

Every item below is required. Each BC entry maps the summary matrix to checked
old/new fixtures and final behavior; the decision and release entries map to
stable section anchors.

- [ ] BC-1 — [BC matrix](#bc-contract-matrix); [Issue #20 checked fixtures and final behavior](plans/issue-20-sync-transaction-ownership.md)
- [ ] BC-2 — [BC matrix](#bc-contract-matrix); [Issue #22 checked fixtures and final behavior](plans/issue-22-inventory-transaction-ownership.md)
- [ ] BC-3 — [BC matrix](#bc-contract-matrix); [Issue #21 checked fixtures and final behavior](plans/issue-21-stream-contract-migration.md)
- [ ] BC-4 — [BC matrix](#bc-contract-matrix); [Issue #24 checked fixtures and final behavior](plans/issue-24-legacy-mutation-ownership.md); [Issue #23 publication and reconciliation evidence](plans/issue-23-publication-intent.md)
- [ ] BC-5 — [BC matrix](#bc-contract-matrix); [Issue #25 checked fixtures and final behavior](plans/issue-25-exact-push-scopes.md)
- [ ] BC-6 — [BC matrix](#bc-contract-matrix); [Issue #21 checked fixtures and final behavior](plans/issue-21-stream-contract-migration.md)
- [ ] BC-7 — [BC matrix](#bc-contract-matrix); [Issue #26 checked fixtures and final behavior](plans/bc-7-transfer-outcome-migration.md)
- [ ] BC-8 — [BC matrix](#bc-contract-matrix); [Issue #27 checked fixtures and final behavior](plans/issue-27-major-update-migration.md)
- [ ] BC-9 — [BC matrix](#bc-contract-matrix); [Issue #28 checked fixtures and final behavior](plans/issue-28-pinned-provenance.md)
- [ ] BC-10 — [BC matrix](#bc-contract-matrix); [checked verification fixtures and final behavior](plans/verification-manifest.md)
- [ ] D01 — [decision contract](#d01--compatibility-is-preserved-by-default)
- [ ] D02 — [decision contract](#d02--missing-configuration-differs-from-invalid-configuration)
- [ ] D03 — [decision contract](#d03--scoped-publication-has-transitive-dependencies)
- [ ] D04 — [decision contract](#d04--remote-identity-equality-is-the-commit-point)
- [ ] D05 — [decision contract](#d05--json-and-ndjson-cardinality-is-exact)
- [ ] D06 — [decision contract](#d06--every-inventory-mutation-is-reviewable)
- [ ] D07 — [decision contract](#d07--unscoped-and-empty-ledger-push-cannot-publish)
- [ ] D08 — [decision contract](#d08--online-streams-remain-refreshable)
- [ ] D09 — [decision contract](#d09--inventory-changes-close-the-whole-ssh-pool)
- [ ] D10 — [decision contract](#d10--three-modules-own-policy-exclusively); [Issue #29 final three-module ownership evidence](plans/issue-29-three-module-contraction.md)
- [ ] D11 — [decision contract](#d11--automatic-update-never-authorizes-a-major-migration)
- [ ] D12 — [decision contract](#d12--pinned-provenance-blocks-release)
- [ ] D13 — [decision contract](#d13--one-manifest-defines-verification)
- [ ] D14 — [decision contract](#d14--transfer-output-states-truthful-guarantees)
- [ ] Release blockers — [initial-v2 release gate](#release-blockers)
- [ ] Rollback guarantees — [migration rollback contract](#rollback)

<!-- markdownlint-disable MD013 -->
### BC contract matrix

<!-- ssm-v2-migration: bc-table columns=bc|old|new|affected|action|machine|rollback -->
| bc | old | new | affected | action | machine | rollback |
| --- | --- | --- | --- | --- | --- | --- |
| BC-1 | A present invalid `cloud.json` could be treated like unconfigured sync. | Every online inventory path fails with `sync_config_error`. | Online reads, mutations, stream startup, sync, push, and pull. | Repair the file/permissions, or accept stale state with explicit `--offline`. | `process exit=1`; `cardinality=one JSON value or one terminal NDJSON record`; failure has `stage=sync_config`, `exit=1`; offline makes zero network requests. | No state mutation; restore valid config or the backed-up encrypted state. |
| BC-2 | Same-alias checks could publish a cross-alias dangling saved-key reference. | Transitive dependencies such as `saved_key_create` reject before network. | `push --only <transaction-id>` callers and shared saved-key changes. | Publish each reported prerequisite transaction in ledger order, then retry the original ID. | `process exit=1`; `cardinality=one JSON value`; stable safe transaction/alias/key/reason fields, zero network requests, and no automatic scope expansion. | Local encrypted vault stays pending and byte/logical state is preserved. |
| BC-3 | Stream startup failures were one indented ordinary JSON document. | Stream output is compact NDJSON from startup with one terminal initialization result. | Line-oriented stream readers and supervisors. | Parse one compact record per line and stop after a terminal startup/refresh failure. | `process exit=1`; `cardinality=one terminal NDJSON record`; startup consumes no input and emits no stderr, ready, summary, or footer. | Restart only after fixing refresh, or explicitly choose offline cached state. |
| BC-4 | `remove`, `keys remove`, and `import-json` could save/auto-publish without a reviewable mutation. | Each appends one pending transaction and never auto-publishes. | Legacy mutation and bulk migration callers. | Review `transaction_id`, dependencies, then publish exact IDs explicitly. | `process exit=0 on success` and classified failure exits are unchanged; `cardinality=one JSON value`; stable ID and secret-free pending receipt; configured mutation refreshes but does not publish. | Preserve the prior ledger; late validation failure leaves vault bytes unchanged. |
| BC-5 | Bare push acted like all, and empty-ledger all could PUT the full local blob. | Bare push returns `invalid_arguments`; non-empty all snapshots the invocation-start IDs; empty all makes no PUT and may return `sync_conflict`. | Every publication wrapper and recovery tool. | Use exact `--only`, or deliberate non-empty `--all`; follow reviewed merge recovery for divergence. | `process exit=2 for bare`; `process exit=1 for divergence`; `cardinality=one JSON value`; bare fails before unlock/network, empty equality is noop, and divergence has `stage=sync_compare`. | Preserve local/remote blobs and private conflict evidence; pull/import/re-publish only after review. |
| BC-6 | Online `--refresh=0` accepted a startup-only snapshot. | Online refresh must be positive; zero requires explicit `--offline`. | Long-running stream consumers. | Use the positive default/interval, or explicitly accept one stale cached offline snapshot. | `process exit=2`; `cardinality=one terminal NDJSON record`; online zero is `invalid_arguments`, `exit=2`, consumes zero input, and makes zero sync/SSH connections. | Restart with a positive interval; offline rollback means retaining the fixed cached snapshot. |
| BC-7 | Direct/request-v1 transfer fields differed and directory guarantees could be inferred. | Direct and request-v1 share `direction`, `kind`, `stage`; request-v1 supports get. | File/directory put/get JSON consumers. | Branch on direction/kind: file put has `bytes_sent`; file get has `bytes_received`; directory get keeps `bytes_received` omitted. | `process exit=0 on success` and classified failure exits are unchanged; `cardinality=one JSON value`; file put conditionally adds `local_sha256`, `remote_sha256`, and `bytes_reused`; file get is `not_checked`, atomic true, resume unsupported; directory put/get is `not_available`, `atomic=false`, `resume=unsupported` and omits digest/reuse; directory put bytes_sent is zero; direct/request-v1 parity. | File staging preserves prior final; directory restore failure retains one backup path and makes no unchanged-final claim. |
| BC-8 | Automatic latest-version replacement could cross a major boundary. | Automatic/manual ordinary update is same-major; `update --major --yes` is explicit migration. | Installers, unattended update jobs, and rollout systems. | Run review first, require automated/manual checks, then authorize the exact target. | `process exit=0 on successful review/install` and classified failure exits are unchanged; `cardinality=one JSON value`; review reports `installed=false`, breaks/checks/rollback; ordinary status reports cross-major availability only. | Trust/preflight failure preserves old executable; restore reviewed v1 only under compatible-state assumptions. |
| BC-9 | An adjacent `checksums.txt` digest alone authorized replacement. | Digest plus exact pinned provenance and the 14-name release manifest are mandatory. | Updater, installer, release workflow, all six platforms. | Verify `Cd1s/ssm`, exact-tag `release.yml` identity, issuer, subject, digest, and rotation state. | `process exit=1 on trust failure`; `cardinality=one JSON value for updater machine mode` while the installer remains non-JSON; any selection/trust/digest/provenance failure has no fallback and preserves installed bytes/mode. | Use the preserved executable; rotate through reviewed overlap, never a checksum-only or skip path. |
| BC-10 | `make check` ran `gofmt -w`, PATH lint, and a repository-root build. | `make check` is non-mutating `verify ci`; `verify release` is a non-publishing strict superset. | Contributors, CI, release maintainers, external gate wrappers. | Install exact prerequisites and require profile completion on a safe clean worktree. | `process exit=0 only on completed profile`, otherwise nonzero; `cardinality=not a JSON/NDJSON contract`: deterministic check lines plus one terminal status; release success is `preflight_passed`, not publication or initial-v2 readiness. | Restore the untouched source; fix prerequisites or action failures without weakening the manifest. |
<!-- markdownlint-enable MD013 -->

<!-- ssm-v2-migration: guide-end -->
