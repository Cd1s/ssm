---
name: agent-ssm
description: "Use Cd1s/ssm for non-interactive SSH inventory, execution, transfers, sync, and troubleshooting through an encrypted vault. Trigger for sshctl/ssm work, exact host aliases, request files, scoped pushes, host-key verification, or secret-safe remote automation."
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, automation]
---

# Agent SSM

Requires ssm >= 1.4.3. The CLI help and `references/request-v1.schema.json` are authoritative.

## Start here

```bash
command -v sshctl
sshctl --help
sshctl <command> --help
sshctl --json status
sshctl --json host list
```

Use exact aliases. Never select a suggestion automatically. Normal `--json` commands must produce one JSON value; explicit `run --stream` produces one NDJSON value per input line. Classify results with `ok`, `error`, and `stage`. A remote program may exit 255, so `exit` alone does not prove SSH transport failure.

## Choose the smallest safe operation

- Simple fixed/reviewed literal argv: `sshctl --json run <exact-alias> --argv <command> [args...]`; this is the fastest one-shot path and needs no request file.
- Repeated simple argv on one exact alias: keep `sshctl run <exact-alias> --stream` open and send one JSON string array per line. Inspect every NDJSON result. It refreshes inventory every 30 seconds and must stop on refresh failure.
- Dynamic, untrusted, or data-dependent argv: request v1 `op:"run"` with `argv`.
- Shell syntax or a generated script: `script_file` plus optional `script_args` and `shell`.
- Secrets: `secret_files` or credential file options; values are file paths, never secret contents.
- Host change: typed `host.add|host.update|host.upsert|host.remove`; verify first, then publish only its `transaction_id`.
- Regular-file upload: typed `put`; add `resume:"v1"` only when requested, and `sha256:true` when integrity verification is required.
- Fleet operation: `sshctl map` with explicit argv or scripts; inspect every result.
- Unsure about fields or flags: run the relevant command help or read the request schema. Do not guess.

When the typed request path is required, write JSON with a file-writing API, not shell interpolation, then run:

```bash
sshctl request --file ./ssm-request.json
```

`argv`, `script_file`, and compatibility-only `shell_command` are mutually exclusive. Prefer `argv`; use `script_file` for pipes, redirects, expansion, or multiple lines. `shell_command` has quoting and expansion risk.

## Inventory and sync

Successful mutations return a stable `transaction_id`. Review the secret-free pending list, then use:

```bash
sshctl --json push --only <transaction-id>
```

Never use bare push or `push --all` unless the user explicitly authorizes every pending mutation. Never silently switch to `--offline`; stop on `sync_pull_failed` unless the user accepts stale inventory.

For bulk import only, read `references/import-json.md`. Do not use bulk import for one host.

## Host keys

On `host_key_unknown` or `host_key_mismatch`:

1. Run `sshctl host-key inspect <exact-alias> --json`.
2. Verify `observed_fingerprint` through a trusted channel.
3. With user authorization, accept that exact fingerprint using `--fingerprint ... --yes --json`.

Never delete/rescan automatically, accept a changed key, or send credentials before verification.

## Failure rules

- `alias_not_found`: list/search; ask if more than one candidate matches.
- `sync_push_failed`: keep the verified local mutation pending; retry the same scoped transaction.
- `dial_*|auth_failed`: diagnose network or credentials, not quoting.
- `remote_failed|remote_script_failed`: transport succeeded; preserve remote exit and structured stderr.
- `interpreter_not_found|script_syntax_error`: correct interpreter or syntax before execution.
- `transfer_timeout|partial_state_*|integrity_failed`: do not publish or append ambiguous data.
- Unknown category: `sshctl --json doctor <exact-alias> --deep`.

## Hard boundaries

- Do not print or read aloud `master.pass`, `cloud.json`, private keys, tokens, passwords, decrypted vault data, or secret-file contents.
- Do not place credentials in argv, JSON values, logs, Issues, or commits; only protected file paths may be referenced.
- Do not use bare `ssh`/`sshpass`, a TUI, an interactive shell, or terminal prompts.
- Do not guess aliases, repair host keys automatically, silently go offline, or publish unrelated transactions.
- Do not claim success without checking the structured result and the requested postcondition.
