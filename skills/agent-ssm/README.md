# Agent SSM

> A typed, non-interactive safety rail for agents managing SSH hosts through the encrypted `ssm` vault: exact aliases, verified candidate changes, JSON argv, stdin scripts, and fingerprint-bound host-key updates.

[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-agent--ssm-blueviolet)](SKILL.md)
[![Project](https://img.shields.io/badge/Project-Cd1s%2Fssm-blue)](https://github.com/Cd1s/ssm)

The official skill targets the current GitHub latest `ssm`/`sshctl` v2.0.0
binary. It also supports exact v1.4.3/v1.4.4 binaries through a separate
compatibility branch. It probes `sshctl --json --version` before state-aware
work, then fails closed on an unlisted version or unsupported major. Read the
[version matrix](references/version-compatibility.md),
[v1→v2 migration guide](../../docs/migration-v1-to-v2.md), and
[update-provenance runbook](../../docs/update-provenance-runbook.md).

## When to use it

Use this skill when an agent needs to:

- inspect or search the SSH inventory in the encrypted vault;
- run a fixed argv command, a file-backed script, or a transfer on an exact alias;
- add, update, or remove a host through explicit non-interactive commands;
- recover from sync or host-key problems without exposing credentials.

## What it protects

- SSH credentials stay in the local encrypted vault; the sync server receives encrypted blobs only.
- Agents use exact aliases instead of guessing from suggestions.
- State-changing host operations verify candidates first and return scoped transaction IDs.
- A no-op returns `changed:false`, `action:"unchanged"`, and omits `transaction_id`; do not publish it.
- Fixed literals use direct argv; dynamic input uses a typed JSON request; scripts use paths and optional syntax preflight.
- Secrets such as `master.pass`, private keys, passwords, tokens, and decrypted vault contents are never printed.

## Beginner path

Install the current latest release:

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

Then probe the binary before any inventory operation:

```bash
sshctl --json --version
sshctl --json status
sshctl --json host list
sshctl --json run my-server --argv hostname
```

Replace `my-server` with one exact alias from the host list. Search returns
candidates only; it never selects or connects automatically. If the alias is
new, host key verification is required before accepting it.

## Version-aware workflow

Always run `sshctl --json --version` first and select one branch:

| Exact version | Branch | Request schema |
| --- | --- | --- |
| v2.0.0 (current/latest) | v2 compatibility branch | `references/request-v1.schema.json` |
| v1.4.3 / v1.4.4 | v1 compatibility branch | `references/request-v1-bridge.schema.json` |

Request schema version stays 1. The v2 branch adds strict request `op:get`;
the v1 bridge does not. Use direct `run --argv` for a fixed one-shot,
`run --stream` for repeated simple commands, and the selected schema for
dynamic argv, scripts, transfers, or host mutations.

For online streams, positive --refresh is required; `--refresh=0` is valid only
with explicit global `--offline`. Inspect every NDJSON result and stop on
refresh failure. Never silently switch to stale inventory.

## Safe mutations and publication

Host add/update/upsert requests default to candidate verification. On a changed
success, review the result and publish only its exact transaction:

```bash
sshctl --json push --only <transaction-id>
```

If the result is `changed:false`, `action:"unchanged"`, and omits
`transaction_id`, do not publish. Never use bare push. Use `push --all` only
after reviewing every pending mutation; in v2 its scope is fixed to the
invocation-start pending-ID set.

## Updates

The current v2.0.0 is latest, but ordinary updates remain same-major. A v1.4.3
or v1.4.4 installation stays on major 1 for ordinary `ssm update`; review a
cross-major candidate with:

```bash
ssm update --major
```

Only explicit reviewed authorization crosses the major boundary:

```bash
ssm update --major --yes
```

This never bypasses digest or keyless provenance verification. Preserve the old
executable, encrypted vault, pending transactions, and recovery intent until
the exact post-update version is probed again.

## Safety boundaries

The agent must stop and ask before:

- deleting or replacing a real host entry;
- running a destructive command on a remote host;
- pushing a changed vault when verification failed;
- replacing the vault with an unreviewed bulk import;
- exposing or reading secret material.

On `host_key_unknown` or `host_key_mismatch`, inspect the exact alias, verify
the full observed fingerprint through a trusted channel, and accept only that
fingerprint with `--yes`. Never use a blind key scan or remove known hosts
automatically.

## Files

```text
skills/agent-ssm/
├── SKILL.md                         # Agent-facing workflow and rules
├── README.md                        # Public install and showcase page
├── references/
│   ├── import-json.md               # Guarded legacy bulk import and recovery
│   ├── install-update.md            # Exact-tag Codex/Hermes deployment
│   ├── request-v1-bridge.schema.json # v1.4.3/v1.4.4 subset
│   ├── request-v1.schema.json       # v2.0.0 typed request schema v1
│   └── version-compatibility.md     # Required version branch matrix
└── test-prompts.json                # Dry-run prompts for skill validation
```

## Validation

Run the repository-level skill check from the verification profile, or use the
prompts in `test-prompts.json` for dry-run validation. A good response probes
the exact version first, identifies an exact alias or asks for missing safe
inputs, never prints secrets, and never uses bare `ssh` or bare `push`.
