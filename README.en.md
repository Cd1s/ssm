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
sshctl list
sshctl sync
sshctl run <alias> hostname
sshctl run <alias> bash -c 'echo "hello"'   # multi-arg is shell-quoted (fewer quote bugs)
sshctl run <alias> -s <<'EOF'               # complex scripts: heredoc, zero quote pain
echo "any quotes fine"
EOF
sshctl <alias> uname -sr                    # SSH-like shorthand for run
sshctl shell <alias>
sshctl put <alias> ./local-file /remote/dir/file   # mkdir -p remote parents
sshctl get <alias> /remote/file ./local-file       # download
sshctl list --json
sshctl push
```

### Remote command quoting (for agents / scripts)

| Form | Behavior | Best for |
|------|----------|----------|
| `sshctl run host cmd arg1 arg2` | Each arg shell-quoted, then joined | Short commands, `bash -c '...'` |
| `sshctl run host 'cmd; cmd2'` | Single arg passed as remote shell script | Pipes, `&&`, classic style |
| `sshctl run host -s <<'EOF' ... EOF` | Script from stdin | Multi-line, any quotes |
| `sshctl run host -f script.sh` | Local file content run remotely | Reusable scripts |
| `sshctl run host --raw a b` | Space-join only (OpenSSH-style) | Compat cases like `ENV=1 cmd` |
| `sshctl host cmd...` / `sshctl host` | Same as `run` / `shell` | Feels like `ssh host` |

## Optional Sync

You can run your own center server to sync the encrypted vault across machines:

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

The center server stores only encrypted vault blobs. It never decrypts SSH passwords or private keys. `sshctl list/run/shell/status` and `ssm list/exec/shell` check the remote ETag before reading the vault and auto-pull when it changed. Local add, edit, and delete operations auto-push by default; `sshctl push` is available for manual upload.

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
Use sshctl run <alias> <command...>, or sshctl run <alias> -s <<'EOF' for multi-line scripts.
Also: sshctl shell <alias>, sshctl put <alias> <local> <remote>. Prefer multi-arg or -s to avoid quote bugs.
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
