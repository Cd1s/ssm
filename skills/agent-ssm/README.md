# Agent SSM

> A safety rail for agents that manage SSH hosts through the encrypted `ssm` vault: find the exact alias, operate non-interactively, verify the result, and never expose secrets.

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
- One-host imports must use `--merge` and `--expect-count` to avoid replacing the vault.
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
sshctl list | grep -Ei '<alias-or-host-fragment>'
sshctl run <exact-alias> 'hostname; uname -sr'
```

For add/edit operations, use the guarded import workflow documented in `references/import-json.md`.

## Safety boundaries

The agent must stop and ask before:

- deleting or replacing real host entries;
- running destructive commands on a remote host;
- pushing a changed vault when verification failed;
- importing JSON without `--merge`;
- exposing or reading secret material.

## Files

```text
skills/agent-ssm/
├── SKILL.md                      # Agent-facing workflow and rules
├── README.md                     # Public install and showcase page
├── references/
│   └── import-json.md            # Verified headless add/edit/remove patterns
└── test-prompts.json             # Dry-run prompts for skill validation
```

## Validation

Run the repository-level skill check from the Luban skill, or use the prompts in `test-prompts.json` for dry-run validation. A good response should first identify exact aliases or ask for missing safe inputs; it should not print secrets or use bare `ssh`.
