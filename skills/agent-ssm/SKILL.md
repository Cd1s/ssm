---
name: agent-ssm
description: "Manage SSH hosts through Cd1s/ssm: idempotent host CRUD, stdin script runner, literal argv, map/plan/json, sync verification, and structured triage without leaking secrets."
version: 2.1.0
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, fleet, scripts, automation]
---

# Agent SSM (v1.2+)

Requires **ssm >= 1.2.0**.

Rule: **exact alias -> local mutation -> verify -> explicit push; use argv for literals and stdin runner for shell syntax; never print secrets.**

## Inventory first

```bash
sshctl status
sshctl sync
sshctl host list --json
sshctl host show <exact-alias> --json
```

Never guess an alias. If multiple entries match the user's description, ask which one.

## Add or update a host

Prefer retry-safe `upsert` for a complete host declaration:

```bash
sshctl host upsert <alias> \
  --host <hostname-or-unbracketed-ip> --port 22 --user <user> \
  --key-file </secure/private-key> --json
```

For a partial edit, use `update`; omitted fields and auth stay unchanged:

```bash
sshctl host update <alias> --port 2222 --group prod --json
```

Auth is exactly one of `--key <saved-name>`, `--key-file <path> [--key-name <name>]`, or `--password-file <path>`. Never use inline passwords or private keys. Do not use `import-json` for a single host on v1.2+.

Mutations return `sync_pending:true` and remain local. Always verify before pushing:

```bash
sshctl host show <alias> --json
sshctl check <alias> --json
sshctl run <alias> --json --argv hostname
sshctl push
```

If verification fails, do not push. Report the structured error and keep the local state available for correction.

If remote refresh returns `sync_pull_failed`, stop. Use `--offline` only after the user accepts the risk of editing stale local inventory.

## Run without quote failures

Use explicit argv mode for literal commands and arguments, even for one word:

```bash
sshctl run <alias> --json --argv hostname
sshctl run <alias> --json --argv printf '%s\n' "value with spaces and ' quotes"
```

Use the stdin runner for any generated script, shell operator, expansion, redirect, or multi-line operation:

```bash
sshctl run <alias> --json --shell bash -s -- first-arg <<'EOF'
set -euo pipefail
printf 'host=<%s> arg=<%s>\n' "$(hostname)" "$1"
EOF
```

For a local script file, executable permission is not required:

```bash
sshctl plan <alias> --json --shell auto -f ./deploy.sh -- release-42
sshctl run  <alias> --json --shell auto -f ./deploy.sh -- release-42
```

The body travels over SSH stdin, not inside the remote command. SSM normalizes BOM/CRLF, validates the shell shebang, quotes script args, and reports `interpreter`, `stdin_bytes`, and `script_sha256` without returning the body. Never re-encode a generated script into `bash -c`.

Pass secrets from files; they are exported only for the runner and redacted from plan/trace:

```bash
sshctl run <alias> --json --secret TOKEN=@/secure/token -f ./script.sh
```

## Parallel fleet

```bash
sshctl map host1,host2,host3 --json --argv hostname
sshctl map 'web-*','api-*' -j 8 --json --argv uname -s
sshctl map app --scripts deploy.sh,smoke.sh --json
sshctl map a,b --scripts s1.sh,s2.sh --plan --json
```

One failure does not hide other results. Treat each result object's `ok`, `exit`, `error`, and `stderr` independently.

## Remove a host

Deletion requires user authorization unless the request already clearly authorizes that exact alias:

```bash
sshctl host remove <exact-alias> --yes --prune-key --json
sshctl host list --json
sshctl push
```

`--prune-key` removes the key only when no other host references it.

## Failure triage

1. `alias_not_found` or `host_not_found`: refresh `host list --json`; do not guess.
2. `dial_*`, `host_key_*`, or exit 255: network/identity/auth layer, not quoting.
3. `interpreter_not_found`: retry a POSIX script with `--shell sh`, or report the missing requested shell.
4. `remote_script_failed`: inspect captured `stderr`; the script reached the interpreter.
5. Wrong argv/output after a successful check: use `--argv`, or move shell syntax into `-s/-f`.

Use `sshctl doctor <alias> --deep --json` when the category is unclear.

## Never

- print or read aloud `master.pass`, `cloud.json`, private keys, passwords, tokens, or decrypted vault data;
- place passwords/private keys inline or generate temporary import JSON for one host;
- use bare `ssh`/`sshpass` for normal SSM work;
- push a changed vault after host verification failed;
- retry network, alias, or host-key errors by changing quotes.
