# BC-9 pinned release provenance

Status: implemented by GitHub Issue #28

BC-9 changes only release trust. Same-major selection, explicit cross-major
authorization, release naming, machine failure contracts, and platform-safe
replacement remain separate compatibility boundaries.

The Issue #28 Windows amendment adds one narrowly scoped terminal state for a
mapped executable whose forward commit and authenticated rollback are both
refused after the original has moved. It does not change provenance trust or
any Unix replacement path.

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
| `release-tag-v1` | `https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/EXACT_SELECTED_TAG` | 2026-07-30 00:00:00 UTC | open |

No wildcard identity, repository alias, alternate issuer, self-hosted runner,
unreviewed workflow, or unreviewed ref is accepted. The release workflow also
checks its own `github.workflow_ref` before building. Publication is tag
triggered only, and the workflow identity must use that exact selected tag.
The updater's compatible version parser continues to accept both
`MAJOR.MINOR.PATCH` and `vMAJOR.MINOR.PATCH`, but provenance identity never
normalizes between them: Git tags `1.2.3` and `v1.2.3` are distinct identities.
An unversioned branch identity or any different release tag cannot authorize
the selected release.

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
| A Unix callback or concurrent writer substitutes the staged pathname, mutates the staged object, hard-links the authenticated install copy, or replaces or mutates its final private or canonical entry after authentication | Portable same-filesystem replacement boundary | The post-callback stage is opened once and copied only from that handle; both the handle stream and fresh sibling copy must equal the provenance-authenticated SHA-256. Linux keeps its same-inode descriptor-bound commit: `/proc/self/fd` links the exact open object into a fresh owner-only sibling directory. Darwin, FreeBSD, and OpenBSD instead copy only from the authenticated descriptor into a newly created entry in that open private directory, avoiding any dependency on fdesc vnode linking, and authenticate the commit object again. Both paths reject source-name substitution, remove the public staging name before canonical mutation, and recheck the private-directory entry. Before the final check, a hard link in that directory retains the exact original target object. `renameat` resolves the checked source relative to the already-open directory and atomically replaces the target on the same filesystem. The updater authenticates the source descriptor against the canonical directory entry, exposes the deterministic post-validation race boundary, and authenticates it again before reporting success. A mismatch fails the update. Rollback first isolates and cleans the current canonical entry in the open private directory, then makes the retained exact-original rename the final canonical-path mutation; a file-to-directory pathname change therefore cannot make the direct rollback refuse. |
| Windows cannot overwrite its mapped running `.exe` | Platform replacement | Pass the verified SHA-256 into the platform boundary, hold the fixed sibling update lock across inspection, handle-bound moves, rollback, recovery, and cleanup, and hash the exact non-write-sharing stage handle before any canonical mutation. Reject reparse points and multiple hard links, require `GetFileInformationByHandleEx(FileIdInfo)` volume serial plus 128-bit identity, and keep non-delete-sharing handles on the validated original and stage until the completed record is durable. `SetFileInformationByHandle(FileRenameInfoEx)` renames those exact source objects. Replace, POSIX, and ignore-read-only semantics replace an unlocked object inserted at the temporarily vacant canonical name. Windows cannot replace that object while an external handle withholds delete sharing: installation and synchronous rollback then fail closed as `update_recovery_required`, retain the original at `.old` plus the authenticated prepared record, and block cleanup, startup command dispatch, and later updates. After the hostile handle is released, serialized recovery restores the retained original by handle, verifies its strong identity, authenticated executable digest, and security-descriptor contract at the canonical path, and only then clears the record. The ordinary tier captures, applies, and verifies owner, primary group, DACL, and DACL inheritance/protection without optional privileges. When all three backup/restore/security privileges can be enabled on a duplicated thread token and the filesystem supports whole-descriptor application, the full tier instead preserves and verifies the complete descriptor, including SACL-backed fields and RM control. An unavailable full tier is never claimed; failure to preserve the selected tier stops before the first move, restores the still-held original, or retains authenticated recovery evidence when an external sharing lock makes immediate restoration impossible. |

## Windows replacement terminal-state matrix

| Boundary | Classification and guarantee |
| --- | --- |
| Provenance, trust, descriptor capability, lock-policy, stage authentication, or other preflight refusal before the original moves | Ordinary `update_failed` / `update` / exit 1. The exact original strong File ID, SHA-256, descriptor binding, bytes, and mode remain canonical. |
| Failure after the original moves, followed by successful authenticated rollback | Ordinary `update_failed` / `update` / exit 1 with the same exact-canonical guarantee. Failure to remove or close prepared evidence after successful rollback does not change this classification. |
| Handle-bound forward commit and authenticated rollback both refuse after the original moves | `update_recovery_required` / `update_recovery` / exit 1. No success is reported. The secret-safe stable hint is `authenticated original evidence was preserved; canonical restoration remains required before retrying`. The exact original `.old` object and prepared authenticated record are retained. |
| Startup or a later update finds valid prepared evidence but authenticated canonical restoration is still refused | The same recovery-required contract; command dispatch, stdin consumption for `run --stream`, and later replacement remain blocked. |
| Startup authenticates and restores the exact original | The canonical path is rechecked against the record's strong File ID, SHA-256, and descriptor binding before the exact record and `.old` state are cleared; normal dispatch may then continue. |
| Recovery evidence is malformed, untrusted, or mismatched | Fail closed through the existing generic internal contract without the ordinary preservation hint. Preserve all evidence; never promote it to the authenticated recovery-required state and never delete it to make an update proceed. |
| Completed-record or post-commit cleanup refusal | The durably committed replacement remains success. Authenticated evidence is deferred to later cleanup and is not classified as either update failure. |

The absent-canonical, verified-new-canonical, and attacker-canonical dual
refusal fixtures all require the recovery-required classification and retain
the authenticated `.old` plus prepared record. The ordinary injection matrix
covers failures before mutation and after mutation with successful rollback;
each row independently compares the canonical strong `FileIdInfo`, SHA-256,
semantic descriptor binding, exact bytes, and mode. Descriptor-focused native
tests continue to cover ordinary owner/group/DACL inheritance and the
capability-gated full descriptor including SACL and exact RM control.

`TestTrustFailurePreservesExecutable` records the original executable bytes and
permission bits, injects a wrong-subject signed bundle, and proves both remain
identical while the pre-replacement callback is never reached.
`TestProvenanceIdentityMatrix`, which is required by the release profile,
drives wrong runner and predicate claims, additional subjects, extra digest
algorithms, and non-SHA-256-only subjects through the updater's production
verifier seam and proves the installed bytes remain unchanged.
`TestVerifiedReplacementPreservesPermissionsAndTarget` proves a valid
replacement reaches the callback only after trust succeeds, renames only the
intended sibling temporary target, preserves the prior permission bits, and
does not modify an adjacent sentinel file. The Unix updater race suite proves
callback substitution and same-object or hard-link mutation fail closed,
pathname replacement after source-open cannot retarget the copied object, the
fresh authenticated copy is rehashed and rejects extra hard links, and
unchanged authenticated bytes retain the established atomic replacement and
permission behavior. Unix installer regressions give the
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
genuinely mapped `.exe` during replacement. A restricted-token fixture proves
ordinary operation with no backup, restore, or security privilege. A
capability-gated fixture installs a protected audit SACL and requires exact
full-descriptor equality when the host can configure and read it. Otherwise,
the nested full-tier subcase reports a skip after the same fixture proves
ordinary descriptor preservation. The official focused Windows gate always
runs the complete suite without demanding elevated hosted-runner privileges.
The suite also proves exact
thread-token restoration, one `LocalFree` per native descriptor allocation,
concurrent-updater and cleanup exclusion, hard-link/reparse rejection,
identity-changing source substitution at both former validation/rename gaps,
canonical-name substitution with a non-delete-sharing attacker handle,
fail-closed retention while that handle prevents replacement, exact-object
recovery after its release, late target/stage hard-link recovery, ordinary
rollback, forged control records, owner/DACL rejection, callback-time stage
substitution and same-object content mutation rejection, same-strong-ID
rollback byte/descriptor mutation rejection and retry after exact restoration,
including descriptor verification on the synchronous rollback path before any
restore or evidence deletion,
compiled CLI startup refusal while a hostile sharing handle blocks prepared
recovery, exact human/JSON/compact-NDJSON recovery-required rendering,
rollback-failure evidence retention and retry, and exact-canonical proof for
every ordinary failure injection.

The Unix final-race fixture runs after the authenticated copy's final
permission sync, digest, mode, pathname, and link-count checks. It renames that
inode away, substitutes single-link attacker bytes at the former install path,
and requires the update to fail with the original executable still canonical.
Linux executes this fixture natively. The focused native Darwin suite executes
the public updater's success and final-race cases plus deterministic
descriptor-copy races at the public staging name and private commit entry.
Its final-entry cases substitute the checked pathname and mutate the checked
inode immediately before target mutation; both require post-rename
authentication to fail and restore the exact original object.
The aggregate also mutates the canonical inode immediately after the first
post-rename digest and replaces the canonical pathname with an empty directory
at the rollback boundary. Final reauthentication rejects the content change;
descriptor-relative isolation removes the changed pathname before the retained
original becomes canonical, and failure cleanup leaves no updater sibling.
FreeBSD and OpenBSD compile the same descriptor-copy path for both release
architectures.

The updater calls the native `GetSecurityInfo` entry point through x/sys'
Windows loader and wraps each returned allocation in one idempotent owner.
Every success and failure path calls `LocalFree` exactly once. Ordinary capture
requests only owner, primary group, and DACL information and applies only
components the current token can set; owner/group equality avoids requiring
`WRITE_OWNER` when those fields already match. If a differing owner or group
cannot be set, the update fails before rename. Ordinary verification compares
owner and primary-group SIDs, null/empty/present DACL state, and every ordered
ACE byte, including its type, access mask, trustee, and inheritance flags. It
requires DACL protection to remain exact and never permits an existing
auto-inherited state to disappear. It permits only Windows' one-way addition
of `SE_DACL_AUTO_INHERITED` when `SetSecurityInfo` imposes the current
inheritance model and the complete ordered ACE list remains identical;
defaulted/request metadata and ACL header padding are not treated as access
changes. The updater attempts the full tier only after `SeBackupPrivilege`,
`SeRestorePrivilege`, and `SeSecurityPrivilege` all enable on a duplicated
impersonation token pinned to the current OS thread. A present thread token is
opened using that thread's effective security context, never the process
context, and the updater queries the duplicate's actual enabled privilege set
after adjustment. The process token is used only when the thread has no token.
It selects the full tier only when the requested target and stage support
complete descriptor capture, whole-descriptor `SetFileSecurityW` application,
and exact verification. A non-delete-sharing inspection guard prevents stage
path replacement while the whole descriptor is applied to the fresh stage;
the updater then reopens that same strong identity without write sharing and
verifies every selected field, including a present RM byte. Access, privilege,
unsupported-filesystem, or unpersistable-RM capability failure during that
preparation restores the thread token, closes the privileged handles, and
retries the ordinary tier from fresh handles before any canonical rename.
Closing the scope restores the exact prior thread token (or no token), closes
the duplicate, and never changes the process token.

The persistent hidden `.<exe>.update.lock` is created with an explicit
non-inherited DACL containing one full-control ACE for the effective updater
SID and an explicit owner and primary group from that token. It is opened
without delete sharing, its owner, group, protected-DACL control bits, one-ACE
shape, trustee, and exact access mask are validated, and then it is byte-range
locked exclusively for inspection, both moves, rollback, record writes, and
startup cleanup. An existing lock with unexpected ownership or permissions is
rejected and preserved. Target, stage, lock, rollback, and record objects must
be non-reparse single-link disk files. Every object comparison uses the
filesystem's 128-bit `FileIdInfo` plus its 64-bit volume serial; inability to
obtain that strong identity fails closed instead of falling back to the legacy
64-bit file index. The target and stage validation handles also supply the
native rename source and omit delete and write sharing, so pathname
substitution or in-place content mutation cannot occur between validation and
either destructive move.

Before the first move, a flushed, fixed 136-byte version-3
`.<exe>.old.state` record binds the inspected old and staged 128-bit file
identities, a SHA-256 digest computed from the exact held rollback handle, the
selected ordinary/full descriptor tier, and a SHA-256 digest of a bounded
canonical semantic descriptor contract. The canonical input contains copied
SID and ordered ACE bytes, ACL state/revision, and the required protection and
full-tier control/SACL state. When `SE_RM_CONTROL_VALID` is set, the full-tier
contract also contains an explicit presence marker and the exact resource
manager control byte; absence and a present zero byte are distinct. It never
persists native self-relative pointers.
The record is created with the same explicit owner-only protected security
policy as the lock and remains open without delete sharing throughout
replacement. Cleanup protectively opens and validates that policy before
parsing or trusting any record field. CRC32 remains only an
accidental-corruption check; authorization comes from the validated Windows
owner and DACL, not from the checksum. Earlier version-1 descriptor-unbound and
version-2 legacy-identity/digest-unbound records fail closed and remain as
evidence. Success flushes the record as completed and
retains both it and `.<exe>.old` until a later cleanup
owns the same trusted lock, holds the record/target/rollback objects against
substitution, and verifies the installed and rollback identities plus the
rollback executable digest. An `.old`
without a trusted record, an untrusted owner or DACL, or any identity mismatch
is recovery evidence and is never deleted or overwritten by cleanup or a new
update. A prepared record blocks a new update and authorizes only a serialized
rollback retry: recovery protectively opens the recorded single-link original,
rejects a reparse point, strong-identity mismatch, executable-digest mismatch,
or descriptor-contract mismatch before any rename, rejects a non-single-link
canonical object, and renames the original handle over an unlocked canonical
name. It then rehashes and recaptures the descriptor and verifies the same
contracts plus the same original strong identity through both the retained
handle and canonical path before deleting the exact record by handle. If the
original is already canonical after a prior rollback but record deletion did
not finish, recovery holds and verifies that exact original handle, executable
digest, and descriptor contract while clearing the record. A sharing lock,
remaining hard link, missing original, identity/digest mismatch, unavailable
required full tier, or descriptor mismatch keeps the prepared record and any
`.old` intact and keeps cleanup and later updates blocked. Startup surfaces an
authenticated restoration refusal through the `update_recovery_required` /
`update_recovery` machine contract, returns nonzero, and does not dispatch the
requested command. Evidence that cannot authenticate remains fail-closed
without receiving either the recovery-required claim or the ordinary
preservation hint. Synchronous
rollback verifies that same canonical descriptor binding in addition to strong
File ID and rollback SHA-256 before restoring the original or deleting the
prepared record. Successful synchronous rollback therefore follows the same
exact-object rule as startup recovery. Failed rollback retains the original at
`.old`, the prepared record, and any remaining stage while reporting both the
operation and rollback failure.

The verified stage remains protected by its non-delete- and non-write-sharing
handles after its handle-bound digest check through normal installation and the
completed-record write. If an operation has
already failed and rollback must replace the installed stage, only those
destination-stage handles are closed before the handle-bound original is
restored over whatever occupies the canonical name; the trusted original
handle, its identity checks, the lock, and the prepared record remain held.

Startup rollback discovery is Windows-only. On other platforms it returns as a
true no-op before executable or symlink resolution, so an already-running
unlinked executable retains the established help, version, and unrelated
command behavior.

The Go updater's non-Windows replacement first uses a portable same-directory
copy because Linux, macOS, and BSD do not share one handle-only rename API.
After the pre-replacement callback, it opens and inspects the exact staged
regular-file object, then copies only from that open handle into a newly created
sibling file. Replacing the staged pathname cannot change the copy source.
In-place or hard-link writes to that source are accepted only if the copied
stream still has the provenance-authenticated SHA-256. The updater flushes and
rehashes the fresh copy from its still-open handle. Linux then binds that same
inode through `/proc/self/fd` into an owner-only commit directory. Darwin,
FreeBSD, and OpenBSD copy from the authenticated descriptor into a new entry in
that open private directory and authenticate the commit entry's digest, mode,
single-link state, and descriptor identity. The public staging pathname is
removed and its descriptor's zero-link transition is verified before the BSD
path can mutate the canonical target. Both implementations retain the exact
original target as a private same-inode rollback link, use directory-relative
`renameat` for same-filesystem atomic replacement, and authenticate the renamed
object against the canonical directory entry twice across the deterministic
post-validation boundary. On a mismatch, rollback moves the current canonical
entry into that private directory, removes it according to its observed type,
and renames the retained original last. No post-restore pathname check can
create a second rollback-refusal window.

Unix does not provide this updater with a mandatory write-denying file handle,
a mandatory pathname lock, or one syscall that couples SHA-256 validation to a
userspace return. `renameat` changes directory entries but leaves already-open
descriptors writable. Therefore an equally authorized writer that continues
after every boundary can always act after any finite protocol's last digest,
stat, or rename. The acceptance boundary is correspondingly explicit: tests
inject a change after the former final canonical validation and before the new
final validation, and inject a pathname change immediately before rollback.
After that rollback callback completes, restoration of the retained original
is the updater's final canonical-path mutation. This is not a claim that the
updater can stop a separately authorized writer from changing the path again
after the update or failure has been returned.

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

On Windows, `update_recovery_required` means installation did not commit. Do
not delete or replace `.<exe>.old` or `.<exe>.old.state`. Close the process or
tool holding the canonical executable without delete sharing, then launch the
same reviewed executable path again so startup can authenticate and restore
the exact original. Normal commands and later updates remain blocked until
that succeeds. If startup instead reports mismatched or untrusted evidence,
preserve both files for reviewed recovery; do not rename or delete them to
force an update.
