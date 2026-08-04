# Agent SSM

> A typed, non-interactive safety rail for agents managing SSH hosts through the encrypted `ssm` vault: exact aliases, verified candidate changes, JSON argv, stdin scripts, and fingerprint-bound host-key updates.

[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-agent--ssm-blueviolet)](SKILL.md)
[![skills.sh](https://skills.sh/b/Cd1s/ssm)](https://skills.sh/Cd1s/ssm)
[![Project](https://img.shields.io/badge/Project-Cd1s%2Fssm-blue)](https://github.com/Cd1s/ssm)

The one official skill supports exact v1.4.3/v1.4.4 and v2.0.0 binaries through
separate compatibility branches. It probes `sshctl --json --version` before
state-aware operations and fails closed on an unlisted version or unsupported
major. Review the [version matrix](references/version-compatibility.md),
[v1→v2 migration guide](../../docs/migration-v1-to-v2.md), and
[update-provenance runbook](../../docs/update-provenance-runbook.md).

## When to use it

Use this skill when an agent needs to:

- inspect the SSH inventory managed by `ssm` / `sshctl`;
- run argv or a file-backed script, or upload a file to a known host alias;
- add, update, or remove a host from the encrypted vault through explicit non-interactive commands;
- recover from sync or SSH host-key problems without leaking credentials.

## What it protects

- SSH credentials stay in the local encrypted vault.
- Sync servers only store opaque encrypted vault blobs.
- Agents must use exact aliases instead of guessing hostnames.
- State-changing single-host operations use typed `sshctl request`, verify candidates, and return scoped transaction IDs; an idempotent no-op returns `changed:false`, `action:"unchanged"`, and omits `transaction_id`.
- Fixed literal argv can use the direct one-shot path; repeated literal argv can keep a headless stream and SSH connection open.
- Dynamic argv is carried as a typed JSON array; scripts use file paths, stdin transport, and syntax preflight.
- Bulk import has no destructive default and full replacement requires `--replace --yes`.
- Secrets such as `master.pass`, private keys, passwords, tokens, and decrypted vault contents must never be printed.

## Quick start

Install the `ssm` CLI first:

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

Install the skill:

```bash
npx skills add Cd1s/ssm -g
```

For release-bound Codex or Hermes deployment, do not install from a moving
branch. Use the [exact-tag install/update procedure](references/install-update.md),
which stages the matching bundle and preserves the prior directory on update.

Or copy `skills/agent-ssm` into your agent skills directory, then ask:

```text
Use agent-ssm to find the exact alias for my web server and run hostname; uname -sr.
```

For pi-agent local installs, the skill directory is commonly:

```text
~/.pi/agent/skills/agent-ssm/
```

## Trigger examples

- "List my SSM aliases matching prod"
- "Run `df -h` on the exact alias for my app server"
- "Add this new VM to ssm non-interactively"
- "Update the SSH port for this existing alias"
- "Remove the temporary test server and push cleanup"
- "Fix the known_hosts mismatch for this ssm alias"

## Expected workflow

```bash
sshctl --json --version
sshctl --json status
sshctl sync
sshctl --json host list
sshctl --json run <exact-alias> --argv hostname
sshctl run <exact-alias> --stream
sshctl request --file ./ssm-request.json
```

Select `references/request-v1-bridge.schema.json` for exact v1.4.3/v1.4.4 and
`references/request-v1.schema.json` for exact v2.0.0. Request schema version
remains 1; only the v2 branch may use request `op:get`. Stop before state-aware
commands on any other version.

Use direct `run --argv` for a simple fixed one-shot, `run --stream` for repeated simple commands, and the selected request schema version 1 for dynamic argv, scripts, put, and host operations. Keep online streams on a positive --refresh interval in both branches; v2 rejects `--refresh=0` without explicit global `--offline`. Add/update requests default to candidate verification; publish a changed result's returned transaction with `sshctl --json push --only <transaction-id>`. If it returns `changed:false`, `action:"unchanged"`, and omits `transaction_id`, do not publish. Never use bare push even on a v1 binary that retains historical compatibility. Use `sshctl --json push --all` only after reviewing every mutation; v2 fixes its non-empty scope at invocation start and makes empty scope an identity-checked no-op or safe divergence failure, never full-blob publication. Only v2 direct/request-v1 transfer results guarantee `direction` and `kind` parity plus explicit directory fields. Detailed compatibility, request, recovery, and legacy import guidance is in `SKILL.md` and `references/`.

Same-major updates remain automatic/manual defaults. v1 ordinary update remains
on major 1 while v2.0.0 is non-latest. Review the exact cross-major candidate
with `ssm update --major`, then authorize only with
`ssm update --major --yes`; this never bypasses pinned digest or provenance
verification. Preserve the old executable, pending transactions, and recovery
intent until exact identities are reconciled, then probe the version again.

## Safety boundaries

The agent must stop and ask before:

- deleting or replacing real host entries;
- running destructive commands on a remote host;
- pushing a changed vault when verification failed;
- replacing the vault with an unreviewed bulk import;
- exposing or reading secret material.

## Files

```text
skills/agent-ssm/
├── SKILL.md                      # Agent-facing workflow and rules
├── README.md                     # Public install and showcase page
├── references/
│   ├── import-json.md            # Guarded legacy bulk import
│   ├── install-update.md         # Exact-tag Codex/Hermes deployment
│   ├── request-v1-bridge.schema.json # v1.4.3/v1.4.4 subset
│   ├── request-v1.schema.json    # v2.0.0 typed request schema v1
│   └── version-compatibility.md  # Required version branch matrix
└── test-prompts.json             # Dry-run prompts for skill validation
```

## Validation

Run the repository-level skill check from the Luban skill, or use the prompts in `test-prompts.json` for dry-run validation. A good response should first identify exact aliases or ask for missing safe inputs; it should not print secrets or use bare `ssh`.
