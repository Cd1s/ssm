# ssm

Headless SSH manager for agents. SSH hosts live in a local encrypted vault, sync moves only encrypted data, and real SSH connections always start from the current machine.

[中文](README.md) | [English](README.en.md)

## Install

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

The installer downloads the matching program from `Cd1s/ssm`, installs `/usr/local/bin/ssm`, and creates `/usr/local/bin/sshctl -> /usr/local/bin/ssm`. `sshctl` is the same binary selected by executable name.

## Commands

```bash
sshctl status
sshctl list --json
sshctl sync
sshctl doctor <alias> --deep --json
sshctl check <alias>

# Headless host management (local stage, verify, then explicit push)
sshctl host list --json
sshctl host upsert prod-api --host 203.0.113.10 --user root --port 22 --key-file /secure/prod-api.key --json
sshctl host update prod-api --port 2222 --json
sshctl host show prod-api --json
sshctl check prod-api
sshctl push

# Single host (literal argv or stdin script; connection reuse by default)
sshctl run <alias> --argv hostname
sshctl run <alias> --json hostname
sshctl plan <alias> bash -c 'echo hi'    # dry-run: remote_command + risk
sshctl run <alias> --secret API_KEY=@./key.txt -- printenv API_KEY
sshctl run <alias> --shell bash -s <<'EOF'
echo "any quotes fine"
EOF

# Parallel multi-host / multi-script fleet
sshctl map limee-hk,aws-sg -j 8 hostname
sshctl map 'limee-*' --json uname -s
sshctl map host1,host2 --scripts a.sh,b.sh   # host×script jobs
sshctl run host --scripts a.sh,b.sh          # parallel scripts on one host

# File or directory trees
sshctl put <alias> ./dir /remote/dir
sshctl get <alias> /remote/dir ./dir

# Migration soft-links
sshctl redirect set old-alias limee-hk
sshctl run old-alias hostname

sshctl push
```

Connection failures print `ssm: error=...` and exit **255**. Connection **reuse** is on by default (`SSM_REUSE=0` / `--no-reuse` to disable).

### Agent host management

| Command | Behavior |
|---------|----------|
| `sshctl host list/show ... --json` | Structured inventory without passwords or private keys |
| `sshctl host add ...` | Create only; fails if the alias exists |
| `sshctl host update ...` | Change only specified fields; fails if the host is missing |
| `sshctl host upsert ...` | Idempotent declaration; retries return `changed:false` |
| `sshctl host remove ... --yes` | Explicit delete; `--prune-key` removes only an unreferenced key |

A new host requires `--host`, `--user`, and one auth source: `--key <saved-name>`, `--key-file <path>`, or `--password-file <path>`. Passwords and keys are never accepted inline, and JSON exposes only `auth`/`key_name`. Upserting an existing host preserves auth when no auth option is given.

Structured host mutations require a successful remote refresh before an atomic local save and return `sync_pending:true`; refresh failure stops before writing with `sync_pull_failed`. Use `--offline` only when stale local state is explicitly acceptable. Mutations do not silently auto-push: verify with `sshctl check` or a read-only `run`, then call `sshctl push` so sync failure has a reliable non-zero exit.

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
| `sshctl run host --json cmd` | Structured result | Agents |
| `sshctl plan host cmd` | Dry-run + risk | Confirm before exec |
| `sshctl run host --secret K=@file cmd` | Secret as remote env; redacted in plan/trace | Secrets |

`-s`, `-f`, and `--scripts` do not require an executable local file and never embed the script body in the SSH command. SSM strips a UTF-8 BOM, normalizes CRLF, rejects NUL/oversized input, and auto-selects `sh/bash/dash/ash/ksh/zsh` from the shebang; no shebang defaults to `sh`. Plan/JSON output includes `interpreter`, `stdin_bytes`, and `script_sha256`, never the body.

## Optional Sync

You can run your own center server to sync the encrypted vault across machines:

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

The center server stores only encrypted vault blobs. It never decrypts SSH passwords or private keys. `sshctl list/run/shell/status` and `ssm list/exec/shell` check the remote ETag before reading the vault and auto-pull when it changed. TUI mutations follow auto-sync settings; agent-facing `sshctl host` mutations deliberately remain local until verification and an explicit `sshctl push`.

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
Use sshctl host upsert/update ... --json for host changes; read auth only from --key-file/--password-file. Check first, then push.
Use sshctl run <alias> --argv <command> [args...] for literal argv, and sshctl run <alias> -s <<'EOF' for shell syntax or generated scripts.
Do not wrap generated scripts in bash -c or rebuild nested quoting. Also: shell, put, and get.
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
