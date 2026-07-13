# ssm

Non-interactive SSH vault management CLI for agents and automation. Neither `ssm` nor `sshctl` starts a TUI, opens an interactive shell, or waits for terminal input. SSH hosts live in a local encrypted vault, sync moves only encrypted data, and real SSH connections always start from the current machine.

[中文](README.md) | [English](README.en.md)

## Install

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

The installer downloads the matching program from `Cd1s/ssm`, installs `/usr/local/bin/ssm`, and creates `/usr/local/bin/sshctl -> /usr/local/bin/ssm`. `sshctl` is the same binary selected by executable name.

## Commands

```bash
sshctl --json status
sshctl --json host list
sshctl sync
sshctl --json doctor <alias> --deep
sshctl check <alias>

# Headless host management (verify the candidate before saving)
sshctl host list --json
sshctl host search prod-web --json       # candidates only; never auto-selects or connects
sshctl host upsert prod-api --host 203.0.113.10 --user root --port 22 --key-file /secure/prod-api.key --verify --json
sshctl host update prod-api --port 2222 --verify --json
sshctl host show prod-api --json
sshctl push --only <transaction-id>
sshctl push --all

# Single host (literal argv or stdin script; connection reuse by default)
sshctl run <alias> --argv hostname
sshctl run <alias> --json hostname
sshctl plan <alias> bash -c 'echo hi'    # dry-run: remote_command + risk
sshctl run <alias> --secret API_KEY=@./key.txt -- printenv API_KEY
sshctl run <alias> --shell bash -s <<'EOF'
echo "any quotes fine"
EOF

# Preferred for agents: typed JSON request; local shell never reparses argv
sshctl request --file ./request.json

# Observe/accept host keys; accept is bound to the full observed fingerprint
sshctl host-key inspect <alias> --json
sshctl host-key accept <alias> --fingerprint SHA256:... --yes --json

# Parallel multi-host / multi-script fleet
sshctl map limee-hk,aws-sg -j 8 hostname
sshctl map 'limee-*' --json uname -s
sshctl map host1,host2 --scripts a.sh,b.sh   # host×script jobs
sshctl run host --scripts a.sh,b.sh          # parallel scripts on one host

# File or directory trees
sshctl put <alias> ./dir /remote/dir
sshctl put <alias> ./artifact.tar /srv/artifact.tar --sha256 --timeout 2m --json
sshctl put <alias> ./artifact.tar /srv/artifact.tar --resume=v1 --timeout 2m --json
sshctl get <alias> /remote/dir ./dir

# Migration soft-links
sshctl redirect set old-alias limee-hk
sshctl run old-alias hostname

sshctl push
```

Normal run/check operations reject both first-use and changed host keys. Never use an automatic `ssh-keygen -R` plus `ssh-keyscan` shortcut. Inspect `observed_fingerprint`, `known_fingerprints`, and `classification:new|mismatch|trusted`, verify through a trusted channel, then explicitly accept the exact same fingerprint with `--yes`.

Regular-file `put` always streams to a private sibling temporary file, verifies the remote byte count, and atomically renames only after successful completion. Add `--sha256` for local/remote SHA-256 verification and `--timeout <duration>` for an explicit deadline. JSON success and failure report `stage`, `bytes_sent`, `integrity`, `atomic`, and `resume`; failures distinguish `local_read_failed`, SSH dial/auth errors, `remote_write_failed`, `transfer_timeout`, and `integrity_failed`. Directory uploads retain the legacy tar behavior and do not claim atomicity or integrity.

Resume is regular-file-only and explicitly enabled with `--resume=v1`; existing put behavior is unchanged when it is absent. v1 requires remote `sha256sum`, binds a private `0600` sibling partial and metadata file to the protocol version, destination-path hash, complete local size, and SHA-256 digest, then verifies the remote prefix against the same local prefix before appending. A changed source starts separate state rather than reusing the old partial; corrupt, missing, or ambiguous state returns `partial_state_mismatch|partial_state_incompatible` and never replaces the destination. A completed size and digest are verified before atomic publish. Interrupted v1 state is retained for retry, while states for the same destination older than seven days are removed opportunistically during a later probe; operators may review and remove the deterministic `.ssm-resume-v1-*` siblings sooner. Results include `bytes_reused` and `bytes_sent`. Directory resume is unsupported.

`status` checks the configured sync endpoint by default and refreshes when its ETag changed. A sync failure returns `error:sync_pull_failed`, `stage:sync_pull`; cached data is never selected silently. Use `sshctl --json status --offline` (or global `--offline`) only when stale data is explicitly acceptable. Offline results include `offline:true`, `remote_state:not_checked`, `freshness`, `cache_age_seconds`, last pull/push times, `pending_changes`, and non-secret `pending_mutations` (`id`, `alias`, `operation`, `created_at`). Mutation results return a stable `transaction_id`. Publish one reviewed change with `push --only <transaction-id>`; its preflight lists the exact alias/operation and unrelated changes stay pending. Use `push --all` (or the legacy bare `push`) only to deliberately publish every pending change.

`sshctl request --file` is the preferred agent entry point. When remote shell semantics are necessary, use a `script_file`, `-f`, or stdin script with `run`; this project does not provide an interactive shell.

### Credential safety boundary

Passwords, private keys, and other secrets must only be referenced through permission-restricted file paths. Never put them or vault contents in JSON, command-line arguments, logs, error reports, GitHub Issues, or commits. `--password-file`, `--key-file`, `--master-pass-file`, and request `secret_files` read the referenced files; structured output never echoes their contents.

Connection-layer JSON failures use `error=dial_*|host_key_mismatch|alias_not_found|...` and normally exit **255**. Do not classify from 255 alone because a remote process can also return 255. Connection reuse is process-scoped and on by default (`SSM_REUSE=0` / `--no-reuse`). Global `sshctl --json ...` also makes argument, unlock, alias, and sync failures emit exactly one JSON value.

### Stable JSON error contract

Failure objects use `ok:false`, `error`, `message`, `hint`, and `exit`, plus `stage` when a failure stage is known. Canonical classes include `alias_not_found`, `invalid_arguments`, `invalid_request`, `sync_pull_failed`, `sync_push_failed`, `dial_timeout|dial_refused|dial_network`, `host_key_unknown|host_key_mismatch`, `auth_failed|no_auth_configured`, `session_failed`, `interpreter_not_found`, `script_syntax_error|remote_script_failed|remote_failed`, and `transfer_failed`. `host_not_found` and `invalid_args` are legacy v1.3-and-earlier values; v1.4 normalizes them to `alias_not_found` and `invalid_arguments`. Classify with `error` and `stage`; use `exit` only for process control.

### Typed agent request (v1.3)

`sshctl request` reads schema version 1 from stdin or `--file`. A run request must select exactly one of `argv`, `shell_command`, or `script_file`; `secret_files` accepts paths only. Agents should create the JSON with a file-writing tool instead of assembling it with shell `echo`.

```json
{
  "version": 1,
  "op": "run",
  "alias": "prod-api",
  "argv": ["printf", "%s\n", "value with spaces and ' quotes"],
  "timeout": "15s"
}
```

Script requests use `script_file`, `script_args`, `shell`, and `secret_files`. They default to a remote syntax preflight using the same interpreter with `-n`; failure returns `script_syntax_error` before the body executes. Results identify `mode`, `transport`, and `preflight`.

Resumable put also uses request schema version 1 with an explicitly versioned resume capability:

```json
{
  "version": 1,
  "op": "put",
  "alias": "prod-api",
  "local_path": "/secure/artifact.tar",
  "remote_path": "/srv/artifact.tar",
  "resume": "v1",
  "sha256": true,
  "timeout": "2m"
}
```

Host requests use `op: host.upsert|host.update|...` plus a nested `host` object. Add/update defaults to `verify:true`:

```json
{
  "version": 1,
  "op": "host.upsert",
  "alias": "prod-api",
  "host": {
    "address": "203.0.113.10",
    "port": 22,
    "user": "root",
    "key_file": "/secure/prod-api.key",
    "verify": true,
    "push": false
  }
}
```

### Agent host management

| Command | Behavior |
|---------|----------|
| `sshctl host list/show ... --json` | Structured inventory without passwords or private keys |
| `sshctl host search <query> --json` | Filter alias/address/user/group; callers must choose when `ambiguous:true` |
| `sshctl host add ...` | Create only; fails if the alias exists |
| `sshctl host update ...` | Change only specified fields; fails if the host is missing |
| `sshctl host upsert ... --verify` | Idempotent declaration; a failed candidate check leaves the vault unchanged |
| `sshctl host remove ... --yes` | Explicit delete; `--prune-key` removes only an unreferenced key |

A new host requires `--host`, `--user`, and one auth source: `--key <saved-name>`, `--key-file <path>`, or `--password-file <path>`. Passwords and keys are never accepted inline, and JSON exposes only `auth`/`key_name`. Upserting an existing host preserves auth when no auth option is given.

Structured host mutations require a successful remote refresh. `--verify` checks the in-memory candidate with `hostname; uname -sr`; failure returns `verification_failed`, `applied:false`, and leaves the encrypted vault unchanged. Success is saved atomically and returns `sync_pending:true`. `--push` requires `--verify`; a sync failure leaves the local change pending and returns `sync_push_failed`. Use `--offline` only when stale local state is explicitly acceptable.

`doctor <alias> --json` returns `resolved_alias` and safe `candidates` on an exact miss, but never selects a candidate or connects. It also reports local/remote vault state, last pull/push, pending state, and non-secret alias/key-name conflict metadata from the latest reviewed merge. When local and remote both diverge from one cached ETag, auto-refresh returns `sync_conflict` and preserves both sides; `sshctl --offline --json doctor` exposes only non-secret blob identifiers in `sync_conflict`. Review `merge_report.conflicts`/`sync_conflict`, then explicitly choose pull or repair local state and push.

### Agent fleet: map (parallel)

| Command | Meaning |
|---------|---------|
| `sshctl map a,b,c -j 8 cmd` | Up to 8 concurrent hosts |
| `sshctl map 'web-*' hostname` | Shell-style alias globs |
| `sshctl map h --scripts s1.sh,s2.sh` | Parallel scripts on one host |
| `sshctl map a,b --scripts s1,s2` | host×script cartesian product |
| `sshctl map ... --plan` / `--json` | Dry-run expand / structured results |

One target failing does **not** drop other targets’ results.

### Remote command quoting

| Form | Behavior | Best for |
|------|----------|----------|
| `sshctl run host --argv cmd arg1` | Always quote each argv, including one argument | Agent-generated literal argv |
| `sshctl run host cmd arg1 arg2` | Multi-arg quoting; one string keeps legacy shell behavior | Compatible calls |
| `sshctl run host -s <<'EOF'` | Body over SSH stdin to a fixed `sh -s` runner | Multi-line, pipes, redirects, quotes |
| `sshctl run host --shell bash -f x.sh -- arg` | Shebang/explicit shell plus exact script args | Bash and generated scripts |
| `sshctl run host --preflight -f x.sh` | Same remote interpreter parses with `-n` first | Prevent syntax-error side effects |
| `sshctl request --file request.json` | argv/script args come from JSON arrays | Preferred agent interface |
| `sshctl run host --json cmd` | Structured result | Agents |
| `sshctl plan host cmd` | Dry-run + risk | Confirm before exec |
| `sshctl run host --secret K=@file cmd` | Secret as remote env; redacted in plan/trace | Secrets |

`-s`, `-f`, and `--scripts` do not require an executable local file and never embed the script body in the SSH command. SSM strips a UTF-8 BOM, normalizes CRLF, rejects NUL/oversized input, and auto-selects `sh/bash/dash/ash/ksh/zsh` from the shebang; no shebang defaults to `sh`. Plan/JSON output includes `interpreter`, `stdin_bytes`, and `script_sha256`, never the body. Syntax preflight proves only that the shell can parse the body; runtime dependencies, permissions, and business logic can still fail.

Legacy bulk import no longer has a destructive default: `ssm import-json` must explicitly use `--merge`, or `--replace --yes` for full-vault replacement. Use host CRUD/request for one host.

## Optional Sync

You can run your own center server to sync the encrypted vault across machines:

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

The center server stores only encrypted vault blobs. It never decrypts SSH passwords or private keys. `sshctl list/run/status` and `ssm list/exec` check the remote ETag before reading the vault and auto-pull when it changed. Agent-facing `sshctl host` mutations deliberately remain local until verification and an explicit `sshctl push`.

## Center Server

```bash
ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
```

Put it behind your own HTTPS reverse proxy:

```text
<sync-server-url> -> 127.0.0.1:18787
```

systemd example:

```ini
[Unit]
Description=SSM encrypted sync server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Agent Prompt

Send this to another machine's agent:

```text
Install SSM from Cd1s/ssm:
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh

If sync is already configured, put master.pass and cloud.json in /root/.config/ssm with chmod 600.
Then run sshctl sync and verify with sshctl status and sshctl list.
Prefer sshctl request --file <json>: put literal arguments in argv, scripts in script_file/script_args, and only paths in secret_files.
Use host.upsert/host.update requests with verify:true; push only after successful verification.
For compatible CLI calls use --argv for literals and --preflight -f for generated scripts; never wrap generated bodies in bash -c.
```

Project agent skill: `skills/agent-ssm/SKILL.md`.

## Auto Update

Version `1.0.0` and later checks GitHub releases from `Cd1s/ssm` by default and replaces the current program when a newer version exists. Manual update:

```bash
ssm update
```

For headless tests, offline environments, or runs that must not touch the network on startup, disable release checks:

```bash
SSM_UPDATE_REPO=off ssm --version
```
