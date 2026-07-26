# SSM v2 Architecture Decision Log

Status: accepted maintainer decisions; documentation only

This log resolves the maintainer questions raised by the
[SSM v2 architecture audit](./ssm-v2-architecture-audit.md). It refines the
observable contracts in [CONTEXT.md](../../CONTEXT.md) without changing runtime
behavior in this branch.

The compatibility and safety boundaries in [AGENTS.md](../../AGENTS.md) and
[SECURITY.md](../../SECURITY.md) remain architecture inputs. These decisions do
not permit secret output, silent offline fallback, weakened host-key
verification, or implicit publication-scope expansion.

The governing decision is to adopt one machine contract module, one sync
transaction module, and one inventory transaction module while preserving the
existing deep vault cryptography, private-file writing, host-key trust, SSH
pool, script transport, atomic/resumable transfer, opaque sync-server, and
update-download mechanisms.

## Approved decisions

### 1. Compatibility defaults to strict preservation

Public CLI behavior, help, machine fields and omissions, output cardinality,
exit behavior, on-disk compatibility, cross-platform behavior, and security
boundaries remain compatible by default.

A breaking change is permitted only when it is listed and approved
individually, the old behavior has characterization tests, a migration path and
release notes exist, and automatic-update risk is mitigated. A major version
number alone does not authorize a break.

### 2. Sync configuration and offline state are distinct

A missing cloud configuration means sync is unconfigured. A present but
invalid or unreadable cloud configuration causes every online inventory read
or mutation to fail with one stable configuration failure.

Explicit `--offline` skips cloud-configuration parsing and all network access,
uses cached inventory, and reports offline and freshness state. It is the only
general permission to accept stale inventory.

### 3. Scoped publication has alias and saved-key dependencies

The inventory transaction module builds explicit dependencies from alias
identity and saved-key names for key creation, replacement, rename, and
deletion. An unsatisfied transitive dependency rejects `push --only` before
network I/O.

The failure may expose only non-sensitive dependency transaction IDs, aliases,
key names, and reasons. Publication scope is never expanded automatically; the
caller publishes prerequisite transactions explicitly and in order.

### 4. Remote confirmation is the publication commit point

A transaction remains pending until remote success is confirmed. Before
network I/O, publication persists a non-sensitive publishing intent containing
the selected scope, target encrypted-blob identity, and prerequisite remote
identity.

An explicit remote failure returns the scope to ordinary pending state. When
the remote may have committed but its response was lost, or local finalization
fails, a later execution reconciles the intended and remote blob identities and
atomically marks the stable transaction IDs published only after equality is
confirmed. Every crash and retry window is part of the contract test surface.

### 5. JSON and NDJSON cardinality are exact contracts

Normal `--json` commands emit exactly one JSON value.

`run --stream` uses compact NDJSON from process start. Initialization failure
emits one terminal error without consuming input. After initialization, every
consumed non-empty input line maps to exactly one ordered result. A refresh
failure is the triggering line's only terminal result and stops processing.
Empty lines emit no record, and the stream emits no ready, summary, or footer
records.

Diagnostics and secrets remain out of machine stdout. Stable machine fields
retain their meanings.

### 6. Every inventory mutation is reviewable

Every v2 inventory mutation enters the inventory transaction module and creates
a pending transaction. This includes `ssm remove`, `ssm keys remove`, all host
mutations, and `import-json --merge|--replace`.

Key removal obeys saved-key dependency rules. An import is one atomic bulk
transaction. No mutation entry point publishes automatically; remote
publication is a later explicit operation.

### 7. Unscoped and empty-ledger push cannot publish

Bare `push` returns stable `invalid_arguments`.

`push --all` snapshots the non-empty pending set at invocation start and
publishes only that set. With no pending transactions it never performs a PUT:
identical state is an explicit no-op, while local/remote identity divergence
without transactions is a stable invariant/divergence failure requiring a
separate reviewed repair, pull, or import flow.

### 8. Online streams remain refreshable

An online `run --stream` refresh interval must be strictly positive.
`--refresh=0` is legal only together with explicit global `--offline`.

Offline stream mode performs no cloud parsing or network access from startup
and holds one fixed cached inventory snapshot.

### 9. Any inventory change closes the SSH pool

For the initial v2 release, any inventory change detected by online refresh
closes the entire process-scoped SSH pool before the new snapshot is loaded or
used. Immediate revocation of credentials, aliases, endpoints, and trust state
takes precedence over retaining unrelated connections.

Selective invalidation is outside initial scope until a complete security
identity model and exhaustive tests exist.

### 10. The three modules have a hard contraction gate

The machine contract module exclusively owns failure classification, stable
fields, redaction, JSON and NDJSON framing, stdout/stderr placement, and
process-exit mapping.

The sync transaction module exclusively owns cloud-configuration state,
online/offline semantics, refresh, pull, push, ETag, conflicts, freshness, and
cache/pool invalidation notifications.

The inventory transaction module exclusively owns all mutations, validation
ordering, pending ledger, dependencies, projection, publishing intent,
commit/finalization, reconciliation, and recovery.

`cmd/ssm` retains argument parsing, module invocation, and command-specific
success payloads. Duplicate classification switches, writers, refresh helpers,
projection, rebasing, marking, and rollback policy must be deleted before a
migration is accepted.

### 11. Automatic update does not authorize a major migration

Ordinary-command automatic replacement is limited to the current major
version. Cross-major availability may be reported, but installation requires
an explicit major-update or install migration operation.

That operation presents release notes, the approved breaking-change inventory,
and migration checks before replacing the binary. Existing v1 installations do
not silently enter v2.

### 12. Provenance is a v2 release blocker

HTTPS and a checksum published beside an artifact are insufficient by
themselves. Before replacement, the updater verifies the artifact digest and
keyless build provenance pinned to the expected repository, release workflow
identity, and OIDC issuer.

Cross-platform verification, identity rotation, safe failure behavior, and
release-pipeline tests are in v2 scope and block the initial release.

### 13. One manifest defines verification

One checked-in, non-mutating verification manifest owns the required commands
and named profiles. `make check` and CI execute the same `verify ci` profile.
`verify release` is a strict superset that covers cross-platform
assets/updater behavior, signing and provenance identities, and failure paths.

Required public-seam scenarios, rather than a global coverage percentage, block
merge and release. Coverage remains an observed report.

### 14. Transfer machine output reports truthful guarantees

All transfer operations share a stable minimal machine contract and failure
envelope, including truthful direction and kind. Existing detailed
regular-file fields remain stable.

Directory put/get output must first be characterized. Direct CLI and
request-v1 results then move through an explicitly approved v2 field-level
migration. Atomicity, integrity, resume, and similar guarantee fields appear
only when the selected protocol provides them, or explicitly report
unavailable/false without implying support.

## Explicitly approved breaking-change inventory

These are the only behavior changes approved by this interview. Each item still
requires an old-behavior characterization test, migration guidance, release
notes, and the automatic-update controls in Decision 11.

- **BC-1 — invalid cloud configuration becomes fatal online.**
  Characterize generic and host command differences; document repair and
  explicit offline use.
- **BC-2 — `push --only` gains cross-alias saved-key dependency rejection.**
  Characterize projections the current same-alias check permits; direct callers
  to publish the reported prerequisite transaction IDs first.
- **BC-3 — stream startup failures become compact NDJSON.**
  Pin the former ordinary indented JSON framing; update line-oriented consumers
  and examples.
- **BC-4 — legacy mutation paths become pending transactions.**
  Remove direct-save/auto-push from remove, key removal, and import. Characterize
  their local/remote effects and output, then document explicit review and
  scoped publication.
- **BC-5 — bare and empty-ledger push lose full-blob behavior.**
  Reject bare `push`; make empty-ledger `push --all` perform no PUT. Direct
  callers to `--only`, non-empty `--all`, or reviewed recovery.
- **BC-6 — zero online stream refresh is rejected.**
  Characterize startup-once behavior; migrate callers to a positive interval or
  explicit offline mode.
- **BC-7 — directory transfer output gets a field-level migration.**
  Snapshot direct CLI and request-v1 fields and omissions first, then publish an
  old-to-new field matrix for truthful common transfer output.
- **BC-8 — automatic replacement no longer crosses a major boundary.**
  Characterize current latest-version replacement; document explicit major
  migration/install and non-interactive rollout controls.
- **BC-9 — checksum-only update artifacts are rejected.**
  Characterize adjacent-checksum acceptance; migrate the release pipeline to
  pinned keyless provenance and document identity rotation and failure
  recovery.
- **BC-10 — `make check` becomes non-mutating and CI-equivalent.**
  Characterize the old mutating subset; document prerequisites, runtime
  expectations, and any later faster development profile.

No other behavior change is implied by adopting the three modules. Newly named
stable error values, field additions, omissions, exit changes, or on-disk
formats require separate compatibility review unless already covered above.

## Strongest counterexamples and public test seams

### Sync state

**Counterexample:** a previously configured machine has a truncated or
permission-denied `cloud.json`. Treating the error as unconfigured lets a
generic online command silently use cached, possibly revoked inventory, while a
host command stops.

**Required seams:**

- Run every online inventory read and mutation through a compiled CLI against
  missing, malformed, and unreadable configuration.
- Prove missing means unconfigured and invalid means one stable failure.
- Run the same matrix with explicit offline mode and assert no config read that
  affects the result and zero HTTP requests.
- Assert offline/freshness fields and absence of secret-bearing diagnostics.

### Transaction dependencies

**Counterexample:** transaction A creates alias `alpha` and saved key `K`;
transaction B creates alias `beta` referencing `K`. Publishing only B under a
same-alias-only rule can produce an alias that references a missing key.

**Required seams:**

- Cover key creation, replacement, rename, deletion, and pruning across aliases.
- Assert transitive prerequisites are reported without key material.
- Assert rejection occurs before any HTTP request.
- Assert publishing prerequisites in order preserves stable transaction IDs and
  creates a valid exact projection.
- Decrypt captured blobs only inside the test process and compare safe names
  and digests without printing plaintext inventory.

### Publication crash recovery

**Counterexample:** the local ledger is marked published and the process dies
before the PUT. The remote lacks the change, local pending state has vanished,
and compensating rollback never runs.

**Required seams:**

- Inject failure before and after publishing-intent persistence, request send,
  remote commit, response receipt, and local finalization.
- Simulate remote commit followed by response loss.
- Simulate local finalization failure after confirmed remote success.
- Restart for every window and prove identity reconciliation either finalizes
  the exact scope or leaves the same transaction IDs pending.
- Prove no retry expands scope or sends plaintext.

### Machine framing and classification

**Counterexample:** a stream startup sync failure goes through the ordinary
pretty JSON writer, so an NDJSON client sees several invalid lines before the
normal stream loop has begun.

**Required seams:**

- Use a compiled subprocess matrix for argument, unlock, alias, sync, host-key,
  transfer, remote-exit-255, and stream failures.
- Assert exact stable fields and omissions, process exit, stdout/stderr
  placement, redaction, and one-value or one-line cardinality.
- Assert initialization failure consumes no input.
- Assert each consumed non-empty stream line has exactly one ordered result,
  empty lines have none, and refresh failure emits one terminal result without
  a footer.

### Mutation entry points and push scope

**Counterexample:** with pending transaction A, legacy `ssm remove` directly
saves the vault and `AutoPush` uploads the whole encrypted file, publishing A
without its explicit review while silently ignoring push failure.

**Required seams:**

- Exercise host add/update/upsert/remove, legacy remove, key removal, and both
  import modes through the compiled CLI.
- Assert each creates exactly one reviewable transaction, with import
  represented as one atomic bulk transaction, and performs no PUT.
- Assert bare push is rejected.
- Assert `push --all` publishes exactly the invocation-start pending snapshot,
  does not absorb concurrent/new mutations, and never PUTs an empty ledger.
- Assert untracked divergence returns a stable safe failure and preserves both
  sides for reviewed recovery.

### Stream freshness and pool lifetime

**Counterexample:** a long-running stream keeps the same alias and saved-key
name while the key material is rotated. A field-incomplete selective comparison
would continue using the revoked pooled connection.

**Required seams:**

- Reject a zero online refresh interval and accept it only with explicit
  offline mode.
- Prove offline startup and every line perform zero cloud requests.
- In the live SSH fixture, refresh changed inventory between commands and prove
  the old pool closes before the next command uses the new snapshot.
- Cover alias removal, address/user/credential/trust changes, refresh failure,
  ordering, and remote exit 255.

### Module contraction

**Counterexample:** new `Render`, `Refresh`, and `Publish` wrappers exist, but
commands still choose error codes, reinterpret configuration failures, build
projections, and compensate failed writes. All public tests may pass while the
new packages remain removable shallow facades.

**Required seams:**

- Review the final dependency graph and removed command-level policy named in
  Decision 10.
- Reject migration while duplicate policy switches/helpers remain.
- Keep command tests focused on parsing, invocation, and command-specific
  success payloads; put policy matrices at the owning module and compiled CLI
  seams.

### Update authorization and provenance

**Counterexample:** an unattended v1 bare push silently upgrades to v2 before
execution and then fails under the new push contract. Separately, a compromised
release workflow can replace both a binary and its adjacent checksum.

**Required seams:**

- Prove ordinary update selects only a newer version in the current major.
- Prove cross-major availability never replaces the binary without the explicit
  migration operation and that failed checks leave the old executable intact.
- Verify artifact digest, repository, workflow identity, OIDC issuer, and
  provenance for every release platform.
- Reject wrong repository/workflow/issuer, missing or malformed provenance,
  digest mismatch, identity-expiration/rotation errors, and unsupported assets.
- Exercise release generation and updater verification against the same
  manifest without publishing.

### Verification and transfers

**Counterexample:** high package coverage does not exercise `os.Exit`, actual
stdout framing, remote commit/local finalize crashes, or directory atomicity
claims.

**Required seams:**

- Snapshot the commands in `verify ci` and `verify release`, prove both are
  non-mutating, and prove release is a strict superset.
- Include format, lint, vet, vulnerability, build, unit, race, compiled
  contracts, live SSH, crash/retry, transfer-safety, updater, and provenance
  scenarios.
- Characterize direct and request-v1 regular-file and directory put/get output.
- Assert common direction/kind and failure metadata while rejecting false
  atomicity, integrity, or resume claims.
- Keep coverage visible without substituting a percentage for required cases.

## Migration and automatic-update implications

Migration follows expand, migrate, and contract phases:

1. **Characterize.** Build the compiled CLI matrix and capture every old
   behavior named in the breaking-change inventory before changing it.
2. **Expand.** Add concrete modules behind existing entry points, the
   verification manifest, and publication recovery state without changing
   unapproved public behavior.
3. **Migrate.** Route machine output first, then sync transactions, then every
   inventory mutation/publication path. Introduce approved breaking changes
   only with their migration tests and documentation.
4. **Contract.** Delete the command-owned policy listed in Decision 10. Passing
   tests without this deletion does not complete the architecture migration.
5. **Release.** Pass `verify release`, including cross-platform provenance and
   updater failure paths. Publish release notes containing the complete
   breaking-change inventory.

An existing major automatically receives only same-major updates. Moving from
v1 to v2 requires an explicit migration/install operation that can run
preflight checks for cloud configuration, pending or untracked inventory state,
stream flags, legacy push usage, and affected transfer consumers before binary
replacement. A failed migration or trust check leaves the prior executable
intact.

## Candidate verdicts

### Candidate 1: Inventory transaction module

**Verdict: Proceed, revised.** It becomes the sole owner of every mutation and
publication invariant, including bulk transactions, alias/key dependencies,
durable intent, remote-identity reconciliation, and recovery. The hard
contraction gate proves depth.

### Candidate 2: Sync transaction module

**Verdict: Proceed, revised.** It owns the
configured/unconfigured/invalid state model, explicit offline behavior,
freshness/conflict/ETag policy, and invalidation notifications. The approved
semantics remove caller disagreement without moving opaque transport or
plaintext into sync.

### Candidate 3: Machine contract module

**Verdict: Proceed, revised.** It owns stable failure metadata, redaction,
framing/cardinality, output placement, and exit mapping while command-specific
success payloads remain typed. The compiled contract matrix and deletion gate
prevent a generic shallow output framework.

None of Candidates 1–3 is accepted merely because a package exists. Each
verdict is conditional on the verification and contraction gates above.

## ADRs

The following decisions meet all three ADR criteria: they are hard to reverse,
surprising without context, and resolve genuine alternatives:

- [ADR 0001: Put v2 policy in three deep modules](../adr/0001-put-v2-policy-in-three-deep-modules.md)
- [ADR 0002: Require reviewed inventory publication](../adr/0002-require-reviewed-inventory-publication.md)
- [ADR 0003: Separate update authorization from release trust](../adr/0003-separate-update-authorization-from-release-trust.md)

The remaining interview answers are contract details recorded here and in
`CONTEXT.md`; separate ADRs would duplicate this log without preserving an
additional architectural tradeoff.

## Out of scope

- Vault format, version byte, Argon2id/AES-GCM parameters, and encrypted
  serialization changes.
- Plaintext sync, sync-server protocol/authentication changes, background sync,
  or a second remote transport.
- Weakening host-key inspection, exact fingerprint acceptance, or known-host
  replacement rules.
- Selective SSH pool invalidation before a complete security-identity model and
  exhaustive tests.
- A decrypted-vault session unless later work proves it deletes raw-vault
  seams rather than wrapping them.
- A broad process-scoped execution-session redesign beyond the approved
  refresh/pool invalidation contract.
- New transfer protocols, directory atomicity by declaration, or changes to the
  resumable v1 protocol.
- A global coverage threshold.
- Automatic tagging, merging, release publication, or provenance identity
  changes hidden inside verification tooling.
- GitHub Issue creation for follow-up work during this documentation phase.

The verification manifest and keyless provenance work were outside the
original audit's three-module implementation core, but the maintainer
explicitly brought both into v2 release scope through Decisions 12 and 13.

## Unresolved non-blocking follow-up work

- Name the stable configuration and invariant/divergence error values after
  characterizing current machine fields; naming must not alter the meanings
  approved here.
- Define the reviewed repair flow for no-transaction local/remote divergence.
- Select the durable encoding and backward-compatible storage location for
  publishing intent.
- Characterize directory put/get field presence and omissions, then write the
  approved field-level migration table.
- Define the operational keyless identity-rotation procedure and emergency
  recovery path without weakening pinned identity verification.
- Re-evaluate selective pool invalidation only after defining a complete
  connection security identity.

These follow-ups refine implementation and operations. They do not block the
proceed verdict for Candidates 1–3, but release-blocking items remain subject to
Decisions 12 and 13.
