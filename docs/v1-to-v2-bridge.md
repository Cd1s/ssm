# v1-to-v2 maintenance bridge

This document describes the migration contract implemented by the v1
maintenance candidate. It does not announce a tag or GitHub Release. A bridge
must be staged and observed before a separate human decision can allow v2 to
become GitHub latest.

## Commands and mutation boundary

`ssm update` and automatic startup update are same-major only. They can install
a newer v1 maintenance release, but merely observing v2 performs no v2 asset
request and leaves the v1 executable unchanged.

`ssm update --major` is the only major-version review command. It selects the
newest supported major release and prints the compatibility contract, release
identity, platform asset, checksum/provenance expectations, and preflight
result. It never downloads or replaces a binary.

`ssm update --major --yes` is the only authorization. Authorization does not
bypass preflight, digest, provenance, or native replacement checks. Failure at
any stage preserves the current v1 executable and encrypted state.

## Compatibility evidence

The review presents all ten approved changes. BC-1..BC-7 and BC-10 describe
behavior that begins only after verified v2 replacement; the bridge does not
backport those runtime semantics.

- **BC-1 — invalid cloud configuration:** a present invalid or unreadable
  `cloud.json` becomes fatal for online inventory operations. Repair it or
  deliberately choose the documented explicit-offline path.
- **BC-2 — cross-alias saved-key dependencies:** scoped publication rejects an
  unsatisfied saved-key prerequisite before network I/O. Publish each reported
  prerequisite transaction in ledger order, then retry the original scope.
- **BC-3 — stream startup NDJSON:** stream initialization failures use the same
  compact NDJSON framing as later results, with one terminal startup record and
  no ready, summary, or footer record.
- **BC-4 — legacy mutations become pending:** legacy remove, key removal, and
  merge/replace import operations create reviewable pending transactions and
  never auto-publish them.
- **BC-5 — bare and empty-ledger push:** bare push is rejected; a deliberate
  empty-ledger `push --all` performs no PUT. Use exact `--only` scopes or a
  reviewed non-empty `--all` snapshot.
- **BC-6 — positive online stream refresh:** online streams require a positive
  refresh interval. Zero refresh is valid only with explicit offline mode and
  one fixed cached snapshot.
- **BC-7 — directory transfer fields:** direct CLI and request-v1 transfer
  results share truthful direction, kind, and stage fields; digest, byte,
  atomicity, and resume fields appear only when that transfer supports them.
- **BC-8 — same-major ordinary update:** automatic and ordinary manual update
  cannot cross a major boundary; only the explicit major command can select a
  supported v2 release.
- **BC-9 — digest plus pinned provenance:** updater and installer replacement
  require the exact 14-entry manifest, SHA-256, pinned keyless provenance, and
  authenticated native replacement described below.
- **BC-10 — non-mutating CI-equivalent checks:** `make check` becomes the
  non-mutating CI-equivalent verification profile; release verification is a
  non-publishing strict superset rather than a release action.

The bridge preflight itself is read-only with respect to v1 encrypted/config
state: it validates cloud syntax, blocks pending transactions/recovery or
sync-conflict evidence, and never rewrites the v1 vault format or publishes it.

Preflight also requires a supported `linux`, `darwin`, or `windows` target on
`amd64` or `arm64`, an exact release manifest, and a writable sibling staging
location suitable for rollback. It performs no release-asset download.

## Release and provenance binding

For the exact selected tag, the authorized path requires all 14 expected
release entries: six legacy binary names, six adjacent `.sigstore.json`
bundles, `checksums.txt`, and `install.sh`. The binary SHA-256 must match the
checksum manifest and the Sigstore subject digest.

The verifier pins:

- repository `Cd1s/ssm`;
- workflow identity
  `Cd1s/ssm/.github/workflows/release.yml@refs/tags/vX.Y.Z`;
- issuer `https://token.actions.githubusercontent.com`;
- a GitHub-hosted runner;
- the exact selected tag ref, never a branch or wildcard identity;
- exactly one subject whose name is the selected platform asset.

Missing or malformed bundles, a different tag, digest, repository, workflow,
issuer, runner, subject name, additional subject, unsupported target, downgrade
or replay evidence all fail closed before executable replacement.

## Replacement and recovery

Unix replacement stages a private sibling file, binds validation to the opened
file, commits without following a substituted path, and preserves or restores
the previous executable on failure. Windows uses handle-verified staging and a
deferred replacement helper where the running image cannot be overwritten;
startup recovery either completes the authenticated transaction or returns an
explicit recovery-required failure. Generic access-denied errors are not
accepted as success.

The future bridge release retains the legacy binary names, checksum layout,
and `install.sh` asset so installed v1.4.3 clients can receive it. The installer
uses the exact selected tag and requires the 14-entry manifest, digest, and
pinned adjacent provenance before replacing an existing installation. It
refuses a selected version below the installed version or outside the installed
major before requesting any binary; only `ssm update --major --yes` can replace
an existing v1 installation with v2. Those same bundles support that separately
authorized major migration. Identity rotation and fail-closed emergency
recovery follow the [bridge provenance runbook](update-provenance-runbook.md).
