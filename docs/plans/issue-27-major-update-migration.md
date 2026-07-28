# Issue 27 major-update migration evidence

This document records BC-8 selection, authorization, preflight, preservation,
and rollout behavior. Authorization to accept a breaking major release remains
separate from digest and provenance trust.

## Old and new selection traces

| Invocation | Release set | v1 behavior before BC-8 | Behavior after BC-8 |
| --- | --- | --- | --- |
| ordinary command, auto-update due | v1.6.0, v2.0.0 | query `/releases/latest`; install v2.0.0 | enumerate supported releases; install v1.6.0 |
| ordinary command, auto-update due | v2.0.0 only | install v2.0.0 | record/report v2.0.0 availability; do not download or replace |
| `ssm update` | v1.6.0, v2.0.0 | install whichever release `/latest` names | install v1.6.0 and report that v2.0.0 requires migration |
| `ssm update` | v2.0.0 only | install v2.0.0 | report v2.0.0 and `ssm update --major`; do not download or replace |
| `ssm update --major` | v2.0.0 | unsupported command mode | emit the complete non-mutating review; not authorized |
| `ssm update --major --yes` | v2.0.0 | unsupported command mode | replace only after the complete review and every automated check passes |

Drafts, prereleases, malformed tags, incomplete versions, older versions, and
missing versions are never selected. The running version must be a stable,
complete semantic version. Candidate ordering returned by the release service
does not affect selection.

The six-hour automatic-update cooldown remains in force. A due check records
the check before network selection, as v1 did. Cross-major availability may be
stored in the private availability flag, but does not count as a same-major
installation or consume later authorization.

## Non-interactive state machine

```text
ordinary auto/manual
  -> enumerate stable releases
  -> select newest newer release in installed major
  -> cross-major target may be reported
  -> digest verification -> atomic same-major replacement

update --major
  -> enumerate stable releases -> choose newest higher-major target
  -> require release notes and declared platform asset
  -> run every automated preflight check
  -> emit review with authorization_state=not_authorized
  -> stop without artifact download

update --major --yes
  -> same review and checks
  -> authorization_state=authorized
  -> any failed check: classified failure, preserve executable
  -> download to adjacent staging path and verify digest
  -> digest/staging failure: classified failure, preserve executable
  -> emit the complete authorized review while the old executable is still installed
  -> atomic replacement
```

No state reads stdin, opens a prompt, or depends on a TTY. `--yes` without
`--major` is invalid and grants nothing. Pending transactions and recovery
intent are inspected only; migration never publishes, drops, rewrites, or
widens their scope.

## Automated and manual checks

| Check | Kind | Blocking rule / limitation |
| --- | --- | --- |
| cloud configuration | automated | absent is unconfigured; present invalid or unreadable blocks |
| publication state | automated | recovery intent or pending inventory transaction blocks |
| divergence | automated | a safely observable sync-conflict record blocks |
| platform asset | automated | the exact current OS/architecture asset must be declared |
| rollback readiness | automated | current executable must be regular/readable and its directory must support adjacent staging |
| legacy bare push consumers | manual | external scripts cannot be discovered completely; review and migrate them |
| zero-refresh online streams | manual | review external callers and choose positive refresh or explicit offline |
| directory transfer fields | manual | review external field/omission consumers against the v2 contract |

The review always names the exact target, includes its release notes, lists
BC-1 through BC-10, distinguishes automated results from external manual
reviews, states authorization, and supplies remediation and rollback guidance.
It never emits cloud contents, vault contents, tokens, credentials, decrypted
state, or master-pass data.

## Byte preservation and trust

Downloads continue to use an adjacent temporary executable. The existing path
is not renamed until the asset digest has matched and the complete authorized
review has been emitted. Authorization and every preflight failure occur before
download. A production callback test observes the original executable from the
review boundary and proves replacement happens only after that callback returns.
Tests compare the complete original byte sequence after missing authorization,
failed preflight, and digest mismatch. Unsupported/missing assets and replacement
errors likewise leave the old path in place. Existing executable permissions and
atomic rename behavior remain unchanged.

Authorization does not authenticate an artifact. SHA-256 verification remains
mandatory here. Pinned keyless provenance is independently required by ADR
0003 and issue 28; `--major --yes` does not waive or imply that trust evidence.

## v1 rollout and rollback examples

Review first on every installation:

```bash
ssm --json update --major >major-review.json
```

Resolve failed automated checks and complete the three external-consumer
reviews. Preserve the deployed v1 executable through validation, then
authorize non-interactively:

```bash
ssm --json update --major --yes
```

For a fleet, gate rollout on `authorized=true`, `installed=true`, ten breaking
change entries, and all automated statuses equal to `passed`. Stop rollout on
any other result. If post-install validation fails, restore the separately
preserved v1 executable through the deployment system; do not use migration
authorization as permission to publish pending inventory or ignore artifact
trust failures.
