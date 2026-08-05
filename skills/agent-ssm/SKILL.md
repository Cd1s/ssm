---
name: agent-ssm
description: "Use Cd1s/ssm for non-interactive SSH inventory, execution, transfers, and troubleshooting through an encrypted vault. Trigger for sshctl/ssm work, exact host aliases, request files, scoped pushes, host-key verification, or secret-safe remote automation."
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, automation]
---

# Agent SSM

This is the official skill for the current GitHub latest `ssm`/`sshctl` v2.0.0
binary. It also contains a deliberately separate compatibility branch for the
supported v1.4.3/v1.4.4 binaries. Read the [version compatibility reference](references/version-compatibility.md),
[v1→v2 migration guide](../../docs/migration-v1-to-v2.md), and
[update-provenance runbook](../../docs/update-provenance-runbook.md) before a
cross-major rollout.

Fresh installations use the current GitHub latest Release:

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

## Start here: identify the exact binary first

Run the read-only version probe before inventory, sync, SSH, transfers, updates,
or mutations:

```bash
command -v sshctl
sshctl --json --version
```

Parse one JSON object with `ok:true` and an exact `version`, then select exactly
one branch:

| Exact version | Skill branch | Request schema |
| --- | --- | --- |
| **v2.0.0 (current/latest)** | v2 compatibility branch | `references/request-v1.schema.json` |
| v1.4.3 / v1.4.4 | v1 compatibility branch | `references/request-v1-bridge.schema.json` |

Request schema version remains 1 in both branches. The v2 schema adds strict
`op:get`; the v1 bridge does not. An unlisted version or unsupported major must
fail closed: do not guess flags, fields, schemas, or publication behavior, and
do not issue state-aware commands. Use the [exact-tag skill deployment procedure](references/install-update.md)
to install a matching official skill.

After selecting the branch, begin safe discovery:

```bash
sshctl --help
sshctl <command> --help
sshctl --json status
sshctl --json host list
```

Use exact aliases. Search and suggestions return candidates only; never select
one automatically. Normal `--json` commands emit one JSON value, while explicit
`run --stream` emits one NDJSON value per input line. Classify results with
`ok`, `error`, and `stage`; a remote program may exit 255, so `exit` alone does
not prove SSH transport failure.

## Choose the smallest safe operation

- Fixed, reviewed literal argv: `sshctl --json run <exact-alias> --argv <command> [args...]`.
- Repeated simple argv on one exact alias: keep `sshctl run <exact-alias> --stream` open and send one JSON string array per line. Online streams require a positive --refresh interval (30s by default); `--refresh=0` is valid only with explicit global `--offline`. Inspect every NDJSON result and stop on refresh failure.
- Dynamic, untrusted, or data-dependent argv: use request schema version 1 with `op:"run"` and the schema selected above.
- Shell syntax or a generated script: use `script_file` with optional `script_args` and `shell`; use preflight where supported.
- Secrets: use `secret_files` or credential file options. Values are paths, never secret contents.
- Host changes: use typed `host.add|host.update|host.upsert|host.remove`; verify first, then publish only a changed result's exact `transaction_id`.
- Regular-file upload: use typed `put`; add `resume:"v1"` only when requested and `sha256:true` when integrity verification is required.
- Download: v1 uses direct `sshctl get`; v2 may use direct get or request schema v1 `op:"get"`.
- Fleet work: use `sshctl map` with explicit argv or scripts and inspect every result.
- If a field or flag is uncertain, run the relevant command help or read the selected schema. Never guess.

When a typed request is required, create JSON with a file-writing API and run:

```bash
sshctl request --file ./ssm-request.json
```

`argv`, `script_file`, and compatibility-only `shell_command` are mutually
exclusive. Prefer `argv` for literal arguments and `script_file` for shell
semantics; `shell_command` has quoting and expansion risk.

## Inventory and publication

State-changing successful mutations return a stable `transaction_id`. An
idempotent update/upsert may instead return `changed:false`,
`action:"unchanged"`, and omit `transaction_id`; it creates no transaction, so
do not publish that no-op.

Review the secret-free pending list, then publish one reviewed change with:

```bash
sshctl --json push --only <transaction-id>
```

Bare `push` is invalid in v2 and must not be relied on in v1. Use
`sshctl --json push --all` only after explicit review of every mutation in the
non-empty pending set. In v2, that set is fixed at invocation start; later
transactions remain pending. An empty `--all` scope never publishes a full
local blob: identical local/cached/remote identities return `action:"noop"`,
while missing or divergent identities return `error:"sync_conflict"` and
preserve both sides. Follow [guarded empty-ledger recovery](references/import-json.md)
for pull, reviewed `--merge`, and a new scoped transaction.

Never silently switch to offline inventory. Stop on `sync_pull_failed` unless
the caller explicitly accepts stale data with `--offline`. `cloud.json` is a
path to local configuration, never a value to print or copy into a request.

## Host keys

On `host_key_unknown` or `host_key_mismatch`:

1. Run `sshctl host-key inspect <exact-alias> --json`.
2. Verify the complete `observed_fingerprint` through a trusted channel.
3. With authorization, accept that exact fingerprint using `--fingerprint ... --yes --json`.

Never delete/rescan automatically, accept a changed key blindly, or send
credentials before verification.

## Transfer and result contracts

In the v2 compatibility branch, branch on `direction` (`put`/`get`) and `kind`
(`file`/`directory`). Directory put/get explicitly report
`atomic:false`, `integrity:not_available`, and `resume:unsupported`; directory
get omits `bytes_received`. File get reports `bytes_received`,
`atomic:true`, `integrity:not_checked`, and `resume:unsupported`. Do not infer
guarantees from `action` or an omitted field. The v1 branch must not assume
these v2 fields or request `op:get`.

Resume is regular-file-only and must be explicitly enabled with `--resume=v1`.
Incompatible, corrupt, or ambiguous state returns a classified partial-state
error and never replaces the destination. See [import and recovery guidance](references/import-json.md)
for the related guarded recovery rules.

## Failure rules

- `alias_not_found`: list/search and ask for an exact alias if needed; never execute a suggestion.
- `sync_push_failed`: preserve the verified pending mutation and retry the same scoped transaction ID.
- `dial_*|auth_failed`: diagnose network or credentials, not quoting.
- `remote_failed|remote_script_failed`: transport succeeded; preserve remote exit and structured stderr.
- `interpreter_not_found|script_syntax_error`: correct interpreter or syntax before execution.
- `transfer_timeout|partial_state_*|integrity_failed`: do not publish or append ambiguous data.
- Unknown categories: run `sshctl --json doctor <exact-alias> --deep` after the version branch is selected.

## Updates and rollback

The current v2.0.0 is GitHub latest. Same-major automatic/manual updates remain
the default. A v1.4.3/v1.4.4 ordinary update remains in major 1 even though
v2.0.0 is current/latest. Review a cross-major candidate with:

```bash
ssm update --major
```

Only after the migration guide's automated and manual checks pass may the caller
explicitly authorize the cross-major update:

```bash
ssm update --major --yes
```

The authorization flag never bypasses pinned digest or keyless provenance
verification. Rerun `sshctl --json --version` after replacement and enter the
v2 branch only on exact `2.0.0`. Preserve the old executable, encrypted vault,
pending ledger, `publishing-intent.json`, and recovery evidence until exact
identities are reconciled.

## Hard boundaries

- Never print or read aloud `master.pass`, `cloud.json`, private keys, tokens, passwords, decrypted vault data, or secret-file contents.
- Never put credentials in argv, JSON values, logs, Issues, or commits; only protected file paths may be referenced.
- Never use bare `ssh`/`sshpass`, a TUI, an interactive shell, or terminal prompts for normal remote administration.
- Never guess aliases, repair host keys automatically, silently go offline, or publish unrelated transactions.
- Never continue on an unparseable version, an unlisted version, or an unsupported major; fail closed before state-aware commands.
- Do not claim success without checking the structured result and the requested postcondition.
