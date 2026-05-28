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
sshctl run <alias> 'hostname; uname -s'
sshctl shell <alias>
sshctl put <alias> ./local-file /remote/file
sshctl push
```

## Sync

Private local files:

```text
/root/.config/ssm/connections.enc
/root/.config/ssm/master.pass
/root/.config/ssm/cloud.json
/root/.config/ssm/settings.json
/root/.config/ssm/update_repo
```

Keep the sync server URL private. Use placeholders when registering or logging in:

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

Send this to another machine's agent. Transfer private sync files separately.

```text
Install SSM from Cd1s/ssm:
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh

Create /root/.config/ssm. Put the provided private master.pass and cloud.json there with chmod 600.
Run sshctl sync, then verify with sshctl status and sshctl list.
Use sshctl run <alias> '<command>', sshctl shell <alias>, and sshctl put <alias> <local> <remote>.
Never print sync URLs, passwords, tokens, master.pass, cloud.json, private keys, or vault contents.
```

Project agent skill: `skills/agent-ssm/SKILL.md`.

## Auto Update

Version `1.0.0` and later checks GitHub releases from `Cd1s/ssm` by default and replaces the current program when a newer version exists. Manual update:

```bash
ssm update
```

## Safety

Do not put real sync domains, account names, emails, passwords, tokens, private keys, `master.pass`, `cloud.json`, or vault contents in public docs, logs, commits, release notes, or chat.
