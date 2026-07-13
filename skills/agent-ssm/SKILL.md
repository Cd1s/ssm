---
name: agent-ssm
description: "Manage SSH hosts and transfers through Cd1s/ssm using strict JSON, typed request files, exact aliases, scoped inventory transactions, verified host keys, resumable uploads, structured triage, and file-path-only secrets. Use for non-interactive SSH inventory, remote execution, host changes, sync/push, troubleshooting, or put operations where credentials and vault data must not be disclosed."
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, fleet, scripts, automation]
---

# Agent SSM (v1.4+)

Requires **ssm >= 1.4.0**.

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

`sshctl --json ...` emits exactly one JSON value even for argument, unlock, alias, and sync failures. `sshctl request` always emits JSON. For result/error objects, read `ok`, `error`, `stage`, and `exit`; list operations return one JSON array. A remote command can itself exit 255, so exit 255 without a transport `error` classification is not proof of a connection failure.

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

Use `shell_command` only as a compatibility path when the user explicitly needs shell operators in a short command. It invokes remote shell parsing, so quoting, globbing, expansion, substitution, and redirection can change meaning. Use `script_file` for generated, multi-line, redirected, piped, or expanded shell code. The three fields are mutually exclusive.

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

Auth is exactly one of `saved_key`, `key_file` plus optional `key_name`, or `password_file`. JSON and argv may contain protected paths, never password/private-key contents. Verify file existence/permissions with metadata only; do not print file contents.

On candidate failure, require `error:"verification_failed"`, `applied:false`, and unchanged local inventory. Do not push. On success, the result includes `applied:true`, a `verification` object, `sync_pending:true`, and a stable `transaction_id`. Inspect the secret-free pending list and publish only the reviewed transaction:

```bash
sshctl --json status
sshctl --json push --only <transaction-id>
```

The push preflight lists exact IDs, aliases, and operations. `push --only` does not publish unrelated mutations. Use `sshctl --json push --all` only when the user deliberately authorizes every pending mutation. Bare `push` is a compatibility alias for push-all; do not use it in new agent workflows.

The compatible direct form is:

```bash
sshctl host upsert <alias> --host <address> --user <user> \
  --key-file </secure/key> --verify --json
```

`--push` is accepted only together with `--verify` and scopes publication to the new transaction. If it returns `sync_push_failed`, the local verified change remains pending.

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

`prune_key` removes a saved key only after its final host reference is gone. Scoped-push the returned `transaction_id` only when synchronization is requested.

## Upload a regular file

Use typed request paths; never embed file contents:

```json
{
  "version": 1,
  "op": "put",
  "alias": "app-prod",
  "local_path": "/secure/artifact.tar",
  "remote_path": "/srv/artifact.tar",
  "resume": "v1",
  "sha256": true,
  "timeout": "2m"
}
```

Without `resume`, regular-file put uses a sibling temporary file, verifies size and optional SHA-256, then atomically publishes. `resume:"v1"` is explicit, regular-file-only, requires remote `sha256sum`, validates version/size/full digest and both prefix digests before append, and reports `bytes_reused`, `bytes_sent`, `resume`, and `integrity`. Never claim directory resume.

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

Compare `observed_fingerprint` through a trusted channel and obtain user authorization. Review `known_fingerprints` and `classification:new|mismatch|trusted`, then bind acceptance to that exact observed value:

```bash
sshctl host-key accept <exact-alias> --fingerprint SHA256:<full-value> --yes --json
```

`fingerprint_mismatch` or `fingerprint_changed` must leave the new key untrusted. Cloudflare-proxied HTTP endpoints are not SSH endpoints; use a DNS-only record or direct address.

## Failure triage

1. `alias_not_found`: run `sshctl --json host list` or `host search`; never auto-select `candidates`.
2. `sync_pull_failed`: stop; do not silently use cache. Use explicit `--offline` only after stale-state risk is accepted.
3. `sync_push_failed`: the encrypted local mutation remains pending; inspect `status.pending_mutations` and retry the same scoped transaction.
4. `host_key_unknown|host_key_mismatch`: inspect, verify out-of-band, exact-accept; never remove/rescan automatically.
5. `dial_*|auth_failed`: network/identity/auth layer, not quoting.
6. `remote_failed|remote_script_failed`: transport succeeded and the remote program ran; inspect structured stderr/stage and preserve its exit, including 255.
7. `interpreter_not_found|script_syntax_error`: choose an available shell or fix syntax; syntax failure means the body did not execute.
8. `transfer_timeout|partial_state_*|integrity_failed`: use byte/resume/integrity fields; never publish or append ambiguous state.
9. Successful connection but wrong arguments: use request `argv`, not `shell_command`.

Use `sshctl --json doctor <alias> --deep` when the category is unclear.

## Unlock and legacy boundaries

`sshctl` reads `SSM_MASTER_PASS_FILE` or defaults to `~/.config/ssm/master.pass`. `SSM_MASTER_PASS` is unsupported. Never print `master.pass` or `cloud.json`.

The project has no TUI or interactive shell. Use `sshctl host` or typed requests for connection changes. Do not use `import-json` for one host. Bulk migration requires explicit `--merge`; full replacement requires `--replace --yes` and reviewed user authorization.

Direct `sshctl run <alias> '<shell string>'` and request `shell_command` exist only for compatibility. Warn that local/remote quoting, globbing, expansion, and substitution can alter arguments or execute unintended code. Prefer request `argv` for literals and `script_file` for shell semantics.

## Never

- print `master.pass`, `cloud.json`, private keys, passwords, tokens, decrypted vault data, or secret-file contents;
- place credentials inline in argv, request JSON, logs, Issues, or commits; request JSON may contain protected file paths only;
- use bare `ssh`/`sshpass` for normal SSM work;
- guess aliases or auto-select a suggested candidate;
- push after candidate verification failed;
- repair network, auth, or host-key errors by changing quotes;
- encode a generated script into `bash -c`;
- silently switch offline, automatically accept a host key, auto-select an alias suggestion, or publish all pending transactions.
