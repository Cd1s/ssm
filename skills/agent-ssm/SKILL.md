---
name: agent-ssm
description: "Manage SSH hosts through Cd1s/ssm with typed requests, verified host transactions, stdin scripts, exact aliases, structured triage, and no secret disclosure."
version: 3.0.0
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, fleet, scripts, automation]
---

# Agent SSM (v1.3+)

Requires **ssm >= 1.3.0**.

Rule: **exact alias -> typed request -> candidate verification -> explicit push; paths for secrets; classify from `error`, never from exit code alone.**

## Machine contract

Prefer global JSON for discovery and the versioned request interface for operations:

```bash
sshctl --json status
sshctl --json sync
sshctl --json host list
sshctl --json host show <exact-alias>
sshctl request --file ./ssm-request.json
```

`sshctl --json ...` emits exactly one JSON value even for argument, unlock, alias, and sync failures. `sshctl request` always emits JSON. For result/error objects, read `ok`, `error`, and `exit`; list operations return one JSON array. A remote command can itself exit 255, so exit 255 without an `error` classification is not proof of a connection failure.

The machine-readable schema is `references/request-v1.schema.json`. The CLI decoder is authoritative and rejects unknown fields or trailing JSON values.

Never guess an alias. If multiple entries match the user's description, ask which one.

## Typed run requests

Create request JSON with the agent's file-writing API. Do not build JSON with shell interpolation. Literal commands use an `argv` array, preserving every boundary without local-shell quoting:

```json
{
  "version": 1,
  "op": "run",
  "alias": "app-prod",
  "argv": ["printf", "%s\n", "value with spaces and ' quotes"],
  "timeout": "15s"
}
```

Then run:

```bash
sshctl request --file ./ssm-request.json
```

Use `shell_command` only when the user explicitly needs shell operators in a short command. Use `script_file` for generated, multi-line, redirected, piped, or expanded shell code. The three fields are mutually exclusive.

```json
{
  "version": 1,
  "op": "run",
  "alias": "app-prod",
  "script_file": "./deploy.sh",
  "script_args": ["release 42"],
  "shell": "bash",
  "secret_files": {"TOKEN": "/secure/token"},
  "preflight": true
}
```

Request scripts default to remote syntax preflight with the same interpreter. `script_syntax_error` means the body was not executed. `remote_script_failed` means syntax passed and execution returned non-zero. Preflight cannot prove runtime dependencies or business behavior.

The script body travels over SSH stdin. Results expose `mode`, `transport`, `interpreter`, `stdin_bytes`, and `script_sha256`, never the body or secret values.

## Add or update a host

Use a typed host request. Add/update/upsert defaults to candidate verification before the encrypted vault is saved:

```json
{
  "version": 1,
  "op": "host.upsert",
  "alias": "staging-api",
  "host": {
    "address": "203.0.113.10",
    "port": 22,
    "user": "root",
    "group": "staging",
    "key_file": "/secure/staging-api.key",
    "verify": true,
    "push": false
  }
}
```

Auth is exactly one of `saved_key`, `key_file` plus optional `key_name`, or `password_file`. Never put a password or private key in JSON. Verify file existence/permissions with metadata only; do not print file contents.

On candidate failure, require `error:"verification_failed"`, `applied:false`, and unchanged local inventory. Do not push. On success, the result includes `applied:true`, a `verification` object, and `sync_pending:true`. Push only when the user requested synchronization:

```bash
sshctl --json push
```

The compatible direct form is:

```bash
sshctl host upsert <alias> --host <address> --user <user> \
  --key-file </secure/key> --verify --json
```

`--push` is accepted only together with `--verify`. If it returns `sync_push_failed`, the local verified change remains pending.

If remote refresh returns `sync_pull_failed`, stop. Use `--offline` only after the user accepts stale-inventory risk.

## Remove a host

Deletion requires authorization for the exact alias:

```json
{
  "version": 1,
  "op": "host.remove",
  "alias": "zz-ssm-skill-test-demo",
  "host": {"confirm": true, "prune_key": true}
}
```

`prune_key` removes a saved key only after its final host reference is gone. Inspect the list and explicitly push after successful removal when synchronization is requested.

## Parallel fleet

Map remains a direct CLI surface. Use explicit argv or script mode:

```bash
sshctl map host1,host2,host3 --json --argv hostname
sshctl map 'web-*','api-*' -j 8 --json --argv uname -s
sshctl map app --scripts deploy.sh,smoke.sh --preflight --json
sshctl map a,b --scripts s1.sh,s2.sh --plan --json
```

One failure does not hide other results. Inspect each result's `ok`, `exit`, `error`, and `stderr`, not only the process exit.

## Host-key mismatch

Never remove a changed host key and blindly scan a replacement. First observe without sending credentials:

```bash
sshctl host-key inspect <exact-alias> --json
```

Compare `fingerprint` through a trusted channel and obtain user authorization. Then bind acceptance to that exact value:

```bash
sshctl host-key accept <exact-alias> --fingerprint SHA256:<full-value> --yes --json
```

`fingerprint_mismatch` or `fingerprint_changed` must leave the new key untrusted. Cloudflare-proxied HTTP endpoints are not SSH endpoints; use a DNS-only record or direct address.

## Failure triage

1. `alias_not_found` or `host_not_found`: refresh `host list`; do not guess from `candidates`.
2. `dial_*`, `host_key_*`, `auth_failed`: network/identity/auth layer, not quoting.
3. `interpreter_not_found`: retry a portable script with `shell:"sh"` or report the missing shell.
4. `script_syntax_error`: fix generated syntax; the body was not executed.
5. `remote_script_failed`: inspect captured stderr; syntax passed and execution began.
6. Successful connection but wrong arguments: use request `argv`, not `shell_command`.

Use `sshctl --json doctor <alias> --deep` when the category is unclear.

## Unlock and legacy boundaries

`sshctl` reads `SSM_MASTER_PASS_FILE` or defaults to `~/.config/ssm/master.pass`. `SSM_MASTER_PASS` is unsupported. Never print `master.pass` or `cloud.json`.

Do not use TUI commands (`ssm add/edit`) in an agent session. Do not use `import-json` for one host. Bulk migration requires explicit `--merge`; full replacement requires `--replace --yes` and reviewed user authorization.

## Never

- print `master.pass`, `cloud.json`, private keys, passwords, tokens, decrypted vault data, or secret-file contents;
- place credentials inline or in request JSON;
- use bare `ssh`/`sshpass` for normal SSM work;
- guess aliases or auto-select a suggested candidate;
- push after candidate verification failed;
- repair network, auth, or host-key errors by changing quotes;
- encode a generated script into `bash -c`.
