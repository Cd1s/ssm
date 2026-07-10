# Agent SSM

> A typed, non-interactive safety rail for agents managing SSH hosts through the encrypted `ssm` vault: exact aliases, verified candidate changes, JSON argv, stdin scripts, and fingerprint-bound host-key updates.

[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-agent--ssm-blueviolet)](SKILL.md)
[![skills.sh](https://skills.sh/b/Cd1s/ssm)](https://skills.sh/Cd1s/ssm)
[![Project](https://img.shields.io/badge/Project-Cd1s%2Fssm-blue)](https://github.com/Cd1s/ssm)

## When to use it

Use this skill when an agent needs to:

- inspect the SSH inventory managed by `ssm` / `sshctl`;
- run a command, open a shell, or upload a file to a known host alias;
- add, edit, or remove a host from the encrypted vault without opening the TUI;
- recover from sync or SSH host-key problems without leaking credentials.

## What it protects

- SSH credentials stay in the local encrypted vault.
- Sync servers only store opaque encrypted vault blobs.
- Agents must use exact aliases instead of guessing hostnames.
- Single-host changes use typed `sshctl request` operations and verify candidates before saving.
- Generated argv is carried as a JSON array; scripts use file paths, stdin transport, and syntax preflight.
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
sshctl status
sshctl sync
sshctl host list --json
sshctl request --file ./ssm-request.json
```

Use request schema version 1 for run and host operations. Add/update requests default to candidate verification; push only after success. Detailed request and legacy bulk-import guidance is in `SKILL.md` and `references/import-json.md`.

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
│   └── request-v1.schema.json    # Typed request schema
└── test-prompts.json             # Dry-run prompts for skill validation
```

## Validation

Run the repository-level skill check from the Luban skill, or use the prompts in `test-prompts.json` for dry-run validation. A good response should first identify exact aliases or ask for missing safe inputs; it should not print secrets or use bare `ssh`.
