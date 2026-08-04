# SSM v1 bridge update-provenance runbook

This runbook governs the maintenance bridge updater, installer, future release
candidate, and emergency recovery decisions. It does not announce or publish a
tag or GitHub Release. The v1 bridge must be released separately before any
future v2 migration decision.

## Repository, manifest, and digest pins

The only accepted repository is `Cd1s/ssm`. A selected release must contain
exactly 14 names: `install.sh`, `checksums.txt`, the six supported binaries,
and one adjacent `.sigstore.json` bundle for each binary. Missing, extra,
duplicate, or misnamed entries fail selection; verification never falls back
to an older release after trust fails.

Each Sigstore bundle must contain exactly one SLSA provenance subject. Its name
must be the selected platform asset, and its SHA-256 digest must equal both the
unique `checksums.txt` entry and the downloaded bytes. HTTPS, a checksum, or
provenance alone is insufficient.

## Current exact-tag identity

The current reviewed identity set is `release-tag-v1`. It accepts only:

```text
https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/EXACT_SELECTED_TAG
```

The issuer is `https://token.actions.githubusercontent.com`, the runner must be
GitHub-hosted, and the verified timestamp must be no earlier than
2026-07-30 00:00:00 UTC. A branch ref, wildcard, workflow alias, alternate
issuer, self-hosted runner, tag replay, or additional subject fails closed.

## Reviewed identity rotation

Identity rotation is a reviewed code and release-policy change, never an
operator flag.

1. Freeze the proposed repository, workflow, issuer, SAN form, identity-set
   version, `NotBefore`, proposed `NotAfter` if any, and the reason for change.
2. Review verifier and installer changes plus missing/wrong/early/expired,
   branch, wildcard, replay, issuer, workflow, runner, subject, and digest
   negative tests. `NotBefore` cannot precede approval.
3. Add the new identity beside the current identity. Keep both in overlap for
   at least seven full days and one complete six-target release made by the new
   identity. Do not change the old identity's window in this step.
4. During overlap, rollback restores the old workflow identity and publishes
   only artifacts that pass the unchanged digest-and-provenance policy.
5. Record audit evidence: approving PR and commits, exact verifier/candidate
   output, native CI runs, tag/ref, six asset digests and bundles, and canary
   results. None of this evidence authorizes publication by itself.
6. Set the old identity's explicit `NotAfter` only in a later review. Remove it
   only after released clients accept the new identity, the overlap and canary
   gates pass, and a separate removal approval is recorded.

Never use a branch identity, wildcard, alternate issuer, checksum-only bridge,
or verification skip to shorten rotation.

## Emergency release recovery

For a broken, missing, malformed, expired, wrong-subject, or wrong-digest
bundle, freeze publication and automatic replacement. Keep every installed
executable unchanged and retain the failed non-secret metadata and verifier
diagnostics. Repair or republish the complete 14-name set through a reviewed
identity; clients do not fall back to an older release.

If every accepted identity is unusable, first ship a reviewed bridge verifier
through a still-valid identity. If none exists, require a manual out-of-band
reinstall whose binary, checksum, provenance, exact tag, and source commit are
independently reviewed. This is a new emergency trust decision, not a checksum
fallback or verification bypass.

## Replacement and recovery evidence

Trust, selection, authorization, or preflight failure before canonical
replacement leaves existing executable bytes and mode intact and removes
staging output. Unix replacement retains authenticated old-object evidence for
rollback. Windows retains owner-only authenticated recovery state if forward
commit and rollback are both refused; startup must verify and finish recovery
before normal command dispatch.

The non-publishing bridge candidate, local gates, native Windows/macOS CI, and
two exact-HEAD reviews must pass before merge. A candidate PASS does not tag,
upload, publish, install, replace a live executable, or authorize a Release.
There is no verification bypass.
