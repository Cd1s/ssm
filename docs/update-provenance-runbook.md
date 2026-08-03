# SSM update provenance runbook

This runbook governs updater, installer, release-maintainer, and emergency
recovery decisions for the planned v2.0.0 release. It does not publish a tag or
release.

[中文](update-provenance-runbook.zh-CN.md) | [Migration guide](migration-v1-to-v2.md)

<!-- ssm-v2-provenance: runbook-begin -->

<!-- ssm-v2-provenance: repository-pin -->

## Repository and manifest pin

The only accepted repository is `Cd1s/ssm`. A selected release must contain
exactly 14 names: `install.sh`, `checksums.txt`, these six binaries, and one
adjacent `.sigstore.json` bundle for each binary:

```text
ssm-linux-amd64
ssm-linux-arm64
ssm-darwin-amd64
ssm-darwin-arm64
ssm-windows-amd64.exe
ssm-windows-arm64.exe
```

Missing, extra, duplicate, or misnamed assets make the selected release
ineligible. Selection never falls back to an older release after trust fails.

<!-- ssm-v2-provenance: workflow-pin -->

## Workflow and exact-tag identity pin

The reviewed workflow path is `.github/workflows/release.yml`. Identity-set
version `release-tag-v1` accepts only this exact subject alternative name:

```text
https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/EXACT_SELECTED_TAG
```

Tag text is authority data. `1.2.3` and `v1.2.3` never authorize one another.
An unversioned branch, different tag, workflow alias, wildcard, or unreviewed
workflow cannot authorize replacement.

<!-- ssm-v2-provenance: issuer-pin -->

## Issuer and certificate-policy pin

The issuer is `https://token.actions.githubusercontent.com`; the build must use
the reviewed GitHub-hosted runner policy and a certificate not-before boundary
of 2026-07-30 00:00:00 UTC for `release-tag-v1`. Alternate issuers,
self-hosted runners, unknown identities, expired/not-yet-valid certificates,
and unreviewed ref claims fail closed.

<!-- ssm-v2-provenance: digest-binding -->

## Digest and subject binding

Each adjacent bundle is Sigstore bundle media type v0.3 with exactly one DSSE
in-toto Statement v1, SLSA provenance v1 predicate, and exactly one subject.
The subject name must equal the selected asset name and its SHA-256 must equal
both the unique `checksums.txt` record and the downloaded bytes.

HTTPS, a checksum, or provenance alone is insufficient. Metadata and bundle
streams are limited to 1 MiB, checksums to 16 KiB, and binaries to 64 MiB;
limit plus one byte is rejected even through redirects or unknown-length
responses. The installer requires `jq`, `head -c`, a SHA-256 tool, and a
current GitHub CLI providing `gh attestation verify`.

<!-- ssm-v2-provenance: identity-rotation -->

## Reviewed identity rotation

Freeze the proposed repository/workflow/issuer identity and add it as a bridge
verifier only after code, synthetic negative matrices, installer behavior, and
all six platforms pass review. Keep old and new reviewed identities in overlap
for at least seven full days and publish one complete six-target release under
the new identity before switching the release workflow.

During overlap, rollback restores the old reviewed identity and publishes only
a release that still passes unchanged digest-and-provenance rules. Retire the
old identity only after released clients accept the new identity. Never use a
wildcard, branch identity, alternate issuer, checksum-only bridge, or
verification skip to shorten rotation.

<!-- ssm-v2-provenance: emergency-recovery -->

## Emergency release recovery

On a broken, missing, malformed, expired, wrong-subject, or wrong-digest bundle,
freeze publication and keep every installed executable unchanged. Preserve the
failed release metadata and non-secret verifier diagnostics. The release owner
must repair or republish the exact 14-name set through a reviewed identity;
clients must not fall back to an older release.

If every accepted identity is no longer usable, review and ship a bridge client
through a still-valid identity first. If no such path exists, require a manual
out-of-band reinstall whose binary, checksum, provenance, tag, and source commit
are independently reviewed. This is an emergency trust decision, not an
updater bypass.

<!-- ssm-v2-provenance: old-executable-recovery-state -->

## Old executable and platform recovery state

Before canonical replacement, trust or authorization failure leaves the old
executable bytes and mode intact and removes staging output. Unix replacement
authenticates descriptor-bound/private sibling state and retains the exact old
object for rollback; it does not claim protection from an equally authorized
writer after every finite acceptance boundary.

Windows keeps the update lock and validated handles through replacement and
rollback. If both forward commit and authenticated rollback refuse after the
old image moves, the result is `update_recovery_required` at
`stage=update_recovery`. Keep the exact `.old` object and owner-only
`.old.state`; startup blocks command dispatch, stdin, and later update work
until serialized recovery verifies File ID, SHA-256, and the selected security
descriptor tier at the canonical path. Do not delete the record by hand.

<!-- ssm-v2-provenance: verification-no-bypass -->

## Verification and no-bypass rule

Run `go run ./cmd/verify release` on the exact clean release commit. Require all
six asset builds, exact checksum inputs, synthetic provenance generation,
identity/digest negative matrices, installer failure preservation, and native
platform replacement tests. `preflight_passed` is evidence only: verification
does not tag, upload, publish, install, or replace a production executable.

There is no verification bypass. `--major --yes` authorizes a reviewed major
migration but cannot authorize a failed digest, provenance, manifest, identity,
or recovery check. Preserve the old executable and evidence, repair the release
through the official workflow, and retry only after authoritative verification
passes.

<!-- ssm-v2-provenance: runbook-end -->
