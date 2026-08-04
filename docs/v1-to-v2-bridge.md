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

The review presents all ten established boundaries:

- **BC-1 — configuration ownership:** v1 paths and the encrypted vault remain
  unchanged by the bridge; v2 owns its configuration only after migration.
- **BC-2 — inventory mapping:** the bridge does not rewrite v1 inventory or
  import v2 inventory runtime behavior.
- **BC-3 — redirect mapping:** v1 redirects are reviewed as migration input;
  the bridge does not invent or persist v2 redirect state.
- **BC-4 — host-key trust:** existing v1 host trust is preserved; no trust-on-
  first-use or automatic host-key replacement is introduced.
- **BC-5 — encrypted state:** preflight is read-only and never decrypts into a
  new on-disk format or publishes state.
- **BC-6 — cloud configuration:** local v1 cloud configuration is syntax- and
  endpoint-validated without network access or authentication side effects.
- **BC-7 — pending/divergent state:** pending mutations, recovery evidence, or
  sync-conflict evidence blocks migration instead of being silently dropped.
- **BC-8 — release selection:** ordinary update is same-major; only the
  explicit major command can select a supported v2 release.
- **BC-9 — verified replacement:** the selected platform asset must pass the
  exact manifest, SHA-256, provenance, and authenticated native replacement
  checks described below.
- **BC-10 — v2 runtime policy:** v2 runtime policy is not backported into the
  bridge and takes ownership only after an independently verified replacement.

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
and `install.sh` behavior so installed v1.4.3 clients can receive it. Its
additional provenance bundles exist only to support the separately authorized
major migration.
