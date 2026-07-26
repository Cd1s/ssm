# Repository guidance

This repository develops the public `ssm`/`sshctl` command-line interface. Keep
changes small, preserve compatibility, and verify the behavior that users and
automation depend on.

## Compatibility boundaries

- Treat public CLI behavior and help output as compatibility boundaries.
- Treat stable JSON fields and the canonical `error`, `stage`, `exit`, and
  `hint` taxonomy as compatibility boundaries.
- Treat cross-platform behavior as a compatibility boundary.

## Safety boundaries

- Never expose or commit secrets, passwords, private keys, `cloud.json`,
  `master.pass`, tokens, or decrypted vault contents.
- Never weaken explicit SSH host-key verification.
- Never silently switch to offline inventory.
- Never enlarge scoped `push --only` into bare `push` or `push --all`.

## Development workflow

- Prefer minimal changes, TDD at public seams, and actual verification.
- Never push directly to `agent-headless-sync`; use branches and pull requests.
- Never merge, tag, or release without explicit human approval.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues for `Cd1s/ssm`. See
`docs/agents/issue-tracker.md`.

### Triage labels

Use the five canonical triage labels without repository-specific aliases. See
`docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository with one root `CONTEXT.md` and ADRs under
`docs/adr/`. See `docs/agents/domain.md`.
