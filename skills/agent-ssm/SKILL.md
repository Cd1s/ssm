---
name: agent-ssm
description: "Use Cd1s/ssm for non-interactive SSH inventory, execution, transfers, sync, and troubleshooting through an encrypted vault. Trigger for sshctl/ssm work, exact host aliases, request files, scoped pushes, host-key verification, or secret-safe remote automation."
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, automation]
---

# Agent SSM

Requires ssm >= 1.4.3. The CLI help and `references/request-v1.schema.json` are authoritative.
The current source/release is v1.4.3; v2 is a planned migration, not a
published binary. Read the [v1→v2 migration guide](../../docs/migration-v1-to-v2.md)
and [update-provenance runbook](../../docs/update-provenance-runbook.md) before
cross-major rollout.

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
- Repeated simple argv on one exact alias: keep `sshctl run <exact-alias> --stream` open and send one JSON string array per line. Inspect every NDJSON result. Online streams require a positive --refresh interval (30s by default) and must stop on refresh failure; `--refresh=0` is valid only with explicit global `--offline`.
- Dynamic, untrusted, or data-dependent argv: request v1 `op:"run"` with `argv`.
- Shell syntax or a generated script: `script_file` plus optional `script_args` and `shell`.
- Secrets: `secret_files` or credential file options; values are file paths, never secret contents.
- Host change: typed `host.add|host.update|host.upsert|host.remove`; verify first, then publish only a changed result's `transaction_id`. For `changed:false`, `action:"unchanged"`, and omitted `transaction_id`, do not publish.
- Regular-file upload: typed `put`; add `resume:"v1"` only when requested, and `sha256:true` when integrity verification is required.
- Fleet operation: `sshctl map` with explicit argv or scripts; inspect every result.
- Unsure about fields or flags: run the relevant command help or read the request schema. Do not guess.

When the typed request path is required, write JSON with a file-writing API, not shell interpolation, then run:

```bash
sshctl request --file ./ssm-request.json
```

`argv`, `script_file`, and compatibility-only `shell_command` are mutually exclusive. Prefer `argv`; use `script_file` for pipes, redirects, expansion, or multiple lines. `shell_command` has quoting and expansion risk.

## Inventory and sync

State-changing successful mutations return a stable `transaction_id`. An
idempotent update/upsert can return `changed:false`, `action:"unchanged"`, and
omit `transaction_id`; it creates no transaction, so do not publish. For a
changed result, review the secret-free pending list, then use:

```bash
sshctl --json push --only <transaction-id>
```

Bare push is invalid and stops before vault unlock or HTTP. Use the returned ID with `sshctl --json push --only <transaction-id>`, or use `sshctl --json push --all` only when the user explicitly authorizes every mutation in the non-empty invocation-start pending set. An empty `--all` scope identity-checks as a no-op when local, cached, and remote encrypted blobs are identical; otherwise it preserves both sides and fails with `sync_conflict`, never a full-blob publication. Follow `references/import-json.md` for reviewed empty-ledger recovery and `publishing-intent.json` reconciliation. Never silently switch to `--offline`; stop on `sync_pull_failed` unless the user accepts stale inventory.

Transfer results from direct and request-v1 paths identify `direction` and
`kind`. Directory put/get explicitly report `atomic:false`,
`integrity:not_available`, and `resume:unsupported`; directory get omits
`bytes_received`. File get reports `bytes_received`, `atomic:true`,
`integrity:not_checked`, and `resume:unsupported`. Do not infer guarantees from
`action` or an omitted field.

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

## Updates and rollback

Same-major automatic/manual updates remain the default. Review a cross-major
candidate with `ssm update --major`, then use `ssm update --major --yes` only
after the migration guide's automated and manual checks pass. The authorization
flag never bypasses pinned digest/provenance verification. Preserve the old
executable, encrypted vault, pending ledger, `publishing-intent.json`, and any
authenticated recovery state; reconcile exact identities before further
mutation or a v1 reinstall.

## Hard boundaries

- Do not print or read aloud `master.pass`, `cloud.json`, private keys, tokens, passwords, decrypted vault data, or secret-file contents.
- Do not place credentials in argv, JSON values, logs, Issues, or commits; only protected file paths may be referenced.
- Do not use bare `ssh`/`sshpass`, a TUI, an interactive shell, or terminal prompts.
- Do not guess aliases, repair host keys automatically, silently go offline, or publish unrelated transactions.
- Do not claim success without checking the structured result and the requested postcondition.
