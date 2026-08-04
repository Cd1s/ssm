# Issue 47 v1 major-safety bridge plan

## Provenance and boundary

The maintenance base is exact released tag `v1.4.3` at
`47309c26b95db6ba5f3c91a1d9c63a9a17353060`. The bridge is a v1 maintenance
candidate; it does not merge or reproduce the v2 runtime. PRs #36, #43, #45,
and #46 and their merged commits are reference implementations only.

The permitted runtime backport is limited to BC-8/BC-9 seams:

- semantic release selection for automatic and ordinary manual updates;
- the existing `ssm update --major [--yes]` review/authorization contract;
- read-only v1-format migration preflight;
- exact release-manifest, digest, selected-tag keyless provenance, and
  authenticated executable replacement;
- startup recovery needed by native Windows replacement.

Vault encryption, serialized inventory, sync/push/mutation policy, machine
classification outside the update command, streams, transfers, SSH, and
request-v1 behavior remain the v1.4.3 implementations. No BC-1..BC-7 or BC-10
runtime owner is imported.

## Vertical slices and public seams

1. Characterize and then restrict automatic and ordinary manual selection.
   A v2-only latest set performs metadata observation only; it requests no v2
   release asset and preserves the executable. The newest supported v1 release
   remains eligible regardless of API ordering.
2. Add the sole explicit major interface. `update --major` emits a complete
   non-mutating review; only `update --major --yes` authorizes replacement.
   The v1-format preflight validates cloud configuration without networking,
   blocks pending/recovery/divergence evidence, validates the exact platform
   manifest, and proves adjacent rollback staging.
3. Require the identical digest and pinned Sigstore verifier for every bridge
   updater replacement. Bind repository `Cd1s/ssm`, workflow
   `.github/workflows/release.yml`, GitHub Actions issuer, hosted runner, exact
   selected tag ref, one exact subject, and its SHA-256. Backport the reviewed
   Unix and Windows handle-bound replacement/recovery implementation because
   pathname-only replacement cannot prove the required native semantics.
4. Preserve legacy bridge binary names, `checksums.txt`, and the `install.sh`
   asset while requiring its selected-tag digest/provenance verification and
   adding six adjacent provenance bundles to future release output. Add a
   non-publishing candidate verifier that builds all six targets
   in temporary storage and verifies source version, asset/checksum manifest,
   synthetic exact-tag provenance, release notes, and maintenance ancestry.
5. Extend maintenance CI triggers minimally and require native Linux, macOS,
   and Windows gates plus Windows amd64/arm64 compilation/vet. The release
   workflow remains v1-tag-only; this work never invokes it and performs no tag,
   Release, asset upload, latest change, or v2 install.
   A separately authorized future v1 bridge tag may publish the bridge as
   GitHub latest so unmodified v1.4.3 clients can receive it; v2 still requires
   its own later human latest decision.

## TDD evidence log

Each slice begins with its public tests committed to the worktree and an
observed failing command before production code is added. The exact RED and
GREEN commands/results are recorded here and in the PR evidence as the slices
land.

- Ordinary automatic RED: `TestAutoV2LatestDoesNotRequestAssetsOrReplace`
  observed two v2 asset requests from the v1.4.3 updater. GREEN: zero asset
  requests and byte-identical executable after semantic release enumeration.
- Ordinary manual RED: `TestOrdinaryDownloadReportsV2WithoutAssetRequestOrReplacement`
  did not compile because the v1.4.3 `Download` seam had no running-version
  input or result contract. GREEN: it reports `v2.0.0`, installs nothing,
  requests no asset, and preserves the executable.
- Major review RED: migration review/preflight tests did not compile because
  v1.4.3 had no `ReviewMajor` contract. GREEN: review and authorization are
  distinct, all BC-1..BC-10 evidence is present, preflight is read-only, and
  cloud/pending/divergence failures preserve the executable and encrypted
  files. A dangling recovery-intent symlink was then shown to pass incorrectly;
  GREEN adds `Lstat` evidence and fails it closed.
- CLI RED: `--major`/`--yes` parsing and one-document streamed migration output
  had no v1 seam. GREEN rejects `--yes` alone and every bypass flag, renders the
  review before replacement, and reports truthful final installation state.
- Provenance RED: the checksum-only v1.4.3 updater accepted replacement without
  a bundle. GREEN requires the reviewed Sigstore verifier and rejects branch,
  replayed tag, repository, workflow, issuer, runner, predicate, subject,
  subject-cardinality, digest-cardinality, and digest mismatches while
  preserving the executable.
- Selection RED: a future v3 was selected directly from v1. GREEN restricts the
  sole explicit migration target to the newest supported release in the next
  major (v2), preventing a skipped-major migration.
- Input-bound GREEN coverage proves oversized release metadata, checksum data,
  provenance, declared binaries, and chunked binaries fail closed before
  replacement; duplicate checksums and empty/malformed evidence are rejected.
- Release/workflow RED: the legacy workflow lacked exact tag identity,
  provenance bundles, six-target/native gates, and a non-publishing verifier.
  GREEN preserves legacy latest URLs/names/checksums/install asset layout,
  requires installer digest plus exact-tag provenance, stages 14 exact entries
  for a separately authorized v1 bridge rollout, and keeps CI
  read-only with native Windows/macOS jobs.
- Candidate/docs RED: source still reported 1.4.3, v1.4.4 notes were absent,
  and both READMEs lacked the major boundary. GREEN binds version/notes/base,
  documents same-major ordinary updates, the one explicit major command,
  BC-1..BC-10, exact trust pins, bridge-first rollout, and the separate v2
  latest decision.
- Native Windows RED: PR run `30864521674`, job `91853359593`, showed that
  reopening a named synchronization event returns `ERROR_ALREADY_EXISTS`; the
  child treated that successful reopen as failure, never signaled readiness,
  and the adversarial fixtures returned `WAIT_TIMEOUT` (258). GREEN accepts the
  existing-event handle explicitly and adds a native reopen test. The same run
  showed that a blanket native `go test ./...` executes unrelated v1 tests whose
  HOME, permission-bit, newline, and OpenSSH fixtures are Unix-specific; the
  Windows job now runs the required native replacement suite plus targeted
  contract guards, while both Windows architectures still compile and vet every
  package in the Linux check job. CI checkouts are explicitly bound to the PR
  head SHA rather than GitHub's synthetic merge ref.
- Exact-HEAD review RED: `TestMajorPreflightDoesNotChangeConfigDirectoryMode`
  reproduced a persistent config-directory mode change from 0755 to 0700.
  GREEN decrypts both current and legacy v1 vault encodings directly through a
  read-only update seam and proves encrypted bytes and directory mode unchanged.
- Exact-HEAD review RED: `TestBridgeInstallerRejectsChecksumOnlyAndPreservesExecutable`
  showed that a forged asset/checksum pair replaced an existing executable.
  GREEN requires the exact selected-tag 14-entry manifest, bounded downloads,
  digest, pinned GitHub keyless provenance, exact subject, and sibling staging;
  failed trust preserves the installed bytes and mode.
- Provenance-operations RED: the documentation contract found no identity
  rotation/emergency-recovery runbook. GREEN records the current identity,
  overlap, expiry/removal, rollback/audit, fail-closed recovery, and no-bypass
  gates. The candidate additionally materializes and re-parses its exact
  seven-entry checksum manifest and reports its SHA-256.
- Native Darwin RED: PR run `30866848674`, job `91860499974`, passed the native
  replacement suite but exposed a BSD fixture defect: `cp` attempted to copy
  modes and extended attributes to `/dev/stdout`. GREEN streams test-owned curl
  fixture bytes with portable `dd`, matching the already-reviewed v2 fixture;
  production installer behavior is unchanged.
- Fresh scope-review RED: the guide attached unrelated meanings to BC-1..BC-7
  and BC-10 while its shallow test checked identifiers only. GREEN binds every
  BC identifier to the canonical Issue #16/#30 old/new meaning and explains
  that BC-1..BC-7/BC-10 begin only after verified v2 replacement.
- Fresh security-review RED: a cached remote ETag differing from the encrypted
  local-vault hash passed `ReviewMajor`; GREEN blocks this safely observable
  divergence while preserving all encrypted/config files.
- Fresh security-review RED: `install.sh` requested an older or cross-major
  binary for an existing v1.4.4 installation. GREEN reads the stable installed
  version before any asset request and permits only the same or a newer version
  in that major; explicit major migration remains the sole cross-major path.
