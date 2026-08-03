---
status: accepted
---

# Separate update authorization from release trust

SSM treats permission to cross a major version and evidence that an artifact is
authentic as separate requirements. Ordinary automatic replacement stays
within the installed major; explicit migration authorizes a cross-major
install, while every replacement must verify digest and keyless build
provenance pinned to the expected repository, release workflow identity, and
OIDC issuer.

## Considered options

- Let ordinary commands install the latest major after checking the adjacent
  SHA-256 file.
- Require explicit approval for every update.
- Automatically install within a major, require migration approval across
  majors, and independently enforce pinned provenance.

An adjacent checksum detects corruption but not a compromised publisher that
replaces both artifact and checksum. Conversely, valid provenance does not
authorize an unattended caller to accept a breaking major migration.

## Consequences

Keyless signing, provenance verification, identity rotation, cross-platform
failure handling, and release-pipeline tests block the initial v2 release.
Failed authorization or trust checks leave the existing executable intact.
The rollout and verification details are recorded in the
[v2 decision log](../plans/ssm-v2-decision-log.md).

A currently mapped Windows executable has one narrower replacement-state
exception. If its original has already moved from the canonical pathname and
both the handle-bound forward commit and authenticated rollback are refused,
the operation fails as `update_recovery_required`; it retains the exact
original evidence, blocks dispatch and later updates, and permits only
authenticated startup restoration. This does not relax authorization or
release trust, does not turn a failed install into success, and does not apply
to preflight, rollback-success, Unix, or post-commit cleanup outcomes.
