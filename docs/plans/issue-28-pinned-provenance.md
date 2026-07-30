# BC-9 pinned release provenance

Status: implemented by GitHub Issue #28

BC-9 changes only release trust. Same-major selection, explicit cross-major
authorization, release naming, machine failure contracts, and platform-safe
replacement remain separate compatibility boundaries.

## Old and new trust matrix

| Replacement path | Before BC-9 | After BC-9 | Authorization unchanged |
| --- | --- | --- | --- |
| Automatic same-major update | Adjacent `checksums.txt` selected the runtime asset; a matching SHA-256 authorized replacement. | The selected release must have the exact 14-name manifest. The downloaded bytes must match the selected checksum and an adjacent, cryptographically valid provenance subject under the pinned policy. | Automatic updates remain same-major only. |
| Manual same-major update | The same checksum-only downloader was used. | The same release-manifest and provenance verifier as automatic update is used. | Manual ordinary update remains same-major only. |
| Explicit major migration | Migration checked that the runtime binary was declared, then delegated to the checksum-only downloader after `--major --yes`. | Migration requires the exact release manifest, retains the explicit review/authorization callback, and delegates to the same digest-and-provenance verifier before replacement. | `--major --yes` remains mandatory and cannot authorize trust failure. |
| `install.sh` replacement | Downloaded the latest asset and checksum, then installed directly after SHA-256 matched. | Validates bounded GitHub metadata contains the exact 14-name manifest, streams bounded assets from that exact tag, independently matches SHA-256, verifies the exact single named subject and digest with GitHub CLI against the pinned repository/workflow/ref/issuer/predicate/runner/rotation policy, and stages a sibling file before rename. | There is no verification skip or fallback. A selection or trust failure leaves an existing installation unchanged. |

An adjacent checksum remains release digest data, but it is no longer an
authority by itself. The updater computes SHA-256 while copying the downloaded
bytes into a sibling temporary file. That computed digest must match both the
unique selected `checksums.txt` record and the unique provenance subject.
Provenance verification completes before the pre-replacement callback and
platform replacement.

## Subject and identity policy

Production provenance is a Sigstore bundle with media type v0.3 containing one
DSSE in-toto statement. The statement must have:

- `_type` `https://in-toto.io/Statement/v1`;
- predicate type `https://slsa.dev/provenance/v1`;
- exactly one subject;
- a subject name exactly equal to the selected release asset name;
- exactly one subject digest, named `sha256`, equal to the updater's computed
  digest.

The signature must chain to current Sigstore public-good trust material and
have a verified transparency-log timestamp and signed certificate timestamp.
The certificate is accepted only when all of these fields match:

| Field | Required value |
| --- | --- |
| Repository | `Cd1s/ssm` / `https://github.com/Cd1s/ssm` |
| Workflow path | `.github/workflows/release.yml` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Runner environment | `github-hosted` |
| Predicate | `https://slsa.dev/provenance/v1` |

The reviewed identity-set version introduced by BC-9 is:

| Identity version | Exact certificate SAN form | Valid from | Valid until |
| --- | --- | --- | --- |
| `release-tag-v1` | `https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/vMAJOR.MINOR.PATCH` for the selected version | 2026-07-30 00:00:00 UTC | open |

No wildcard identity, repository alias, alternate issuer, self-hosted runner,
unreviewed workflow, or unreviewed ref is accepted. The release workflow also
checks its own `github.workflow_ref` before building. Publication is tag
triggered only, and the workflow identity must use that exact selected tag.
An unversioned branch identity or a different release tag cannot authorize the
selected release.

## Six-target release manifest

Release and updater names come from `internal/releaseasset`, which owns this
exact manifest:

| Target | Binary subject | Adjacent provenance |
| --- | --- | --- |
| Linux amd64 | `ssm-linux-amd64` | `ssm-linux-amd64.sigstore.json` |
| Linux arm64 | `ssm-linux-arm64` | `ssm-linux-arm64.sigstore.json` |
| macOS amd64 | `ssm-darwin-amd64` | `ssm-darwin-amd64.sigstore.json` |
| macOS arm64 | `ssm-darwin-arm64` | `ssm-darwin-arm64.sigstore.json` |
| Windows amd64 | `ssm-windows-amd64.exe` | `ssm-windows-amd64.exe.sigstore.json` |
| Windows arm64 | `ssm-windows-arm64.exe` | `ssm-windows-arm64.exe.sigstore.json` |

`install.sh` and `checksums.txt` complete the 14-name release manifest.
Missing, additional, duplicate, unsupported, or misnamed entries reject the
selected release. Selection never falls back to an older release after the
newest eligible release fails this check.

## Negative-case matrix and byte preservation

| Case | Failure point | Replacement result |
| --- | --- | --- |
| Missing or empty adjacent bundle | Bundle download/presence | No executable path is opened for replacement. |
| Malformed bundle or unsupported bundle version | Bundle parser | Staged file is removed; installed bytes and mode are unchanged. |
| Invalid signature or untrusted certificate | Cryptographic verifier | Staged file is removed; installed bytes and mode are unchanged. |
| Certificate expired or not yet valid | Certificate verifier | No replacement. |
| Identity version expired or not yet active at a verified timestamp | Rotation policy | No replacement. |
| Unversioned branch identity or a different release tag | Exact selected-tag policy | No replacement. |
| Wrong repository, workflow/ref, issuer, or runner | Exact certificate policy | No replacement. |
| Wrong subject name, additional subject, or non-SHA-256/extra digest | Statement policy | No replacement. |
| Downloaded digest differs from checksum | Independent digest comparison | Provenance cannot rescue the mismatch; no replacement. |
| Downloaded digest matches checksum but differs from provenance | Subject digest comparison | Checksum cannot rescue the mismatch; no replacement. |
| Unsupported, missing, misnamed, additional, or duplicate release asset | Strict manifest selection | No asset download and no fallback. |
| Checksums over 16 KiB, provenance or release metadata over 1 MiB, or a binary over 64 MiB | Header-independent bounded stream, rejecting after at most limit plus one byte | No replacement; temporary output is bounded and removed; installed bytes and mode are unchanged. |
| Windows cannot overwrite its mapped running `.exe` | Platform replacement | Open the exact non-reparse target and verified sibling stage, capture the target's complete backup security descriptor, and apply and verify it on the stage before renaming. Rename the running image to its fixed sibling rollback path, move the stage to the original path, reapply and verify the descriptor on the new canonical executable, and restore the rollback image on any later failure. A completed replacement is reported only after the new bytes and equivalent owner, primary group, DACL, SACL, and inheritance-protection state occupy the original path. |

`TestTrustFailurePreservesExecutable` records the original executable bytes and
permission bits, injects a wrong-subject signed bundle, and proves both remain
identical while the pre-replacement callback is never reached.
`TestVerifiedReplacementPreservesPermissionsAndTarget` proves a valid
replacement reaches the callback only after trust succeeds, renames only the
intended sibling temporary target, preserves the prior permission bits, and
does not modify an adjacent sentinel file. Unix installer regressions give the
same byte-and-mode proof for a failed external attestation verifier,
unversioned-identity replay, invalid exact manifests, and oversized metadata or
trust inputs. Redirected, unknown-length installer fixtures prove that release
metadata (1,048,576 bytes), checksums (16,384 bytes), provenance bundles
(1,048,576 bytes), and binaries (67,108,864 bytes) stop at the next byte rather
than first writing an unlimited response to disk. The Go updater separately
proves declared-length early rejection and a redirected chunked binary stopped
after exactly 67,108,865 bytes. Both paths remove temporary artifacts and
preserve the installed bytes and mode.

Native Windows tests execute a copied Go test binary, so the target is a
genuinely mapped `.exe` during replacement. Success proves the verified stage
occupies the original path with the restrictive, protected descriptor of the
old executable before the updater reports completion. The mapped old image
remains at `.ssm.exe.old` only until a later launch can remove it. One failure
fixture holds the verified stage with a native sharing lock; another injects a
failure into the second native descriptor application after the new bytes
occupy the canonical path. Both prove rollback restores the exact original
bytes and descriptor, removes the fixed rollback path and staging path, and
never reports success.

Windows descriptor preservation uses `CreateFile` with
`FILE_FLAG_OPEN_REPARSE_POINT`, `GetSecurityInfo` with
`BACKUP_SECURITY_INFORMATION`, and `SetSecurityInfo` with explicit owner,
primary-group, DACL, SACL, label, attribute, scope, and protected/unprotected
ACL flags. The updater enables `SeBackupPrivilege`, `SeRestorePrivilege`, and
`SeSecurityPrivilege` only on a self-impersonating, OS-thread-locked token and
restores the prior token state before returning. Missing privileges, an
unreadable owner or SACL, any application error, or any SDDL/control mismatch
is a fail-closed updater error. Before the first rename the original executable
is untouched; after it, the fixed `.old` image retains the original bytes and
descriptor and is moved back on failure. These errors continue through the
existing `update_failed` / `update` machine contract, and the updater's staging
defer removes any verified temporary file that still has its staging name.

The installer success fixture places a BSD-compatible `mktemp` shim ahead of
the host implementation. It rejects every supplied template that does not end
in `XXXXXX`, then proves the installer uses a collision-safe template in the
destination directory, installs the verified bytes with mode `0755`, creates
the `sshctl` link, and leaves no sibling staging file. The destination rename
therefore remains on one filesystem on macOS as well as GNU/Linux.

## Workflow permission review

| Job | Explicit permissions | Reason |
| --- | --- | --- |
| Workflow default | `contents: read` | Least-privilege baseline. |
| `preflight` | `contents: read` | Read source and remote tag identity; cannot attest or publish. |
| `build` | `contents: read`, `id-token: write`, `attestations: write`, `artifact-metadata: write` | Build each exact matrix output and have `actions/attest@v4` attest that output. |
| `publish` | `contents: write` | Publish only after preflight and every build/attestation completes; has no identity-token or attestation permission. |

Each matrix build passes its exact workspace binary path directly to the
attestation action, copies that action's bundle to the adjacent canonical
name, and uploads binary plus bundle together. `checksums.txt` is generated
later and is never an attestation subject or substitute for the build output.
The publish list contains the six binaries, six bundles, installer, and digest
data exactly once.

## Synthetic release gate

`go run ./cmd/verify release` remains non-publishing. Its required
`release-provenance` builtin generates a fresh test-owned root, ephemeral
leaf key, short-lived identity certificate, and signed SLSA statement in
memory for each of the six temporary release builds. It verifies each bundle
with the production verifier core and exact target manifest. The required
`provenance-failure-paths` action exercises the selected-tag identity matrix,
independent digest binding, and byte preservation. The inherited unit gate
also exercises bounded updater and installer inputs and the installer's exact
manifest. It uses no production credential, GitHub publication, tag, upload,
installed executable, or release-write API.

## Identity rotation runbook

Identity rotation is a reviewed policy migration, not an operational flag.

1. Open a review that records the current identity version, proposed exact
   SAN form, repository, workflow path, issuer, runner, trigger/ref form,
   proposed `NotBefore`, proposed `NotAfter` if any, and the reason for change.
2. Add the proposed identity as a new named version in the Go verifier and
   installer policy. Keep the current identity accepted. The proposed
   `NotBefore` must be no earlier than the review approval time.
3. Add synthetic positive and negative cases for the new and old identities,
   update the complete workflow and verification goldens, run the full release
   profile, and retain its output as audit evidence.
4. Release the overlapping verifier before switching the workflow identity.
   The overlap must last at least seven full days and include at least one
   verified six-target release produced by the new identity.
5. Switch the workflow only after the overlap release is available. During
   overlap, rollback means restoring the old reviewed workflow identity and
   publishing only a release that passes the unchanged digest-and-provenance
   gates.
6. Set the old identity's explicit `NotAfter` only in a later review. Removal
   is gated on expiry of the overlap window, retained verification evidence
   for all six targets under the new identity, successful automatic/manual/
   major/installer fixtures, and a released client that accepts the new
   identity. Remove the old identity and installer branch together.

Audit evidence for every rotation consists of the approving change, old/new
identity table and dates, workflow diff, six subject digests and verification
results, negative matrix, release-profile output, rollback result, and the
follow-up removal review.

For emergency recovery, freeze publication and automatic replacement first.
Review a new exact trusted release identity/path and ship a bridge verifier
through any still-valid reviewed identity. If no reviewed identity remains
usable, binary replacement stays blocked: recover from a reviewed source
commit and locally build the bridge verifier, then use it to verify the newly
reviewed release path. Never weaken the issuer, use an identity wildcard,
trust a checksum alone, or add `--skip-verification`.

## User-facing recovery

A trust error leaves the current executable in place. Retry only after the
release owner repairs or republishes the exact asset/bundle set through a
reviewed identity. For installer failures, install `jq` and a current GitHub
CLI that supports `gh attestation verify`; do not manually copy the downloaded
binary.
For an explicit major migration, retain the prior executable until migration
validation completes. If the repository announces an identity rotation, first
install the reviewed overlap/bridge version through a still-valid provenance
path.
