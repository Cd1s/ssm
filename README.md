# ssm

Headless SSH manager for agents. It stores SSH hosts in a local encrypted vault, syncs only the encrypted vault blob through a self-hosted server, and always opens SSH from the local agent machine.

## Install

```bash
curl -fsSL https://github.com/<owner>/<repo>/releases/latest/download/install.sh | SSM_REPO=<owner>/<repo> sh
```

The installer downloads `ssm-<os>-<arch>`, installs `/usr/local/bin/ssm`, creates `/usr/local/bin/sshctl -> /usr/local/bin/ssm`, and stores the release repo in local private settings for auto update.

## Agent Install Prompt

Give this to another agent or machine, replacing placeholders locally:

```text
Install headless SSM from <owner>/<repo>. Run:
curl -fsSL https://github.com/<owner>/<repo>/releases/latest/download/install.sh | SSM_REPO=<owner>/<repo> sh
Then place the provided /root/.config/ssm/master.pass and /root/.config/ssm/cloud.json with chmod 600, run sshctl sync, verify sshctl status and sshctl list. Use sshctl run <alias> '<command>', sshctl shell <alias>, and sshctl put <alias> <local> <remote>. Do not use sshpass, expect, tmux prompt scraping, legacy h* helpers, or print secrets.
```

## Client Use

```bash
sshctl status
sshctl list
sshctl sync
sshctl run <alias> 'hostname; uname -s'
sshctl shell <alias>
sshctl put <alias> ./local-file /remote/file
sshctl push
```

`sshctl` is not a wrapper script. It is the same `ssm` binary running in agent mode by executable name.

## Sync

Local private files:

```text
/root/.config/ssm/connections.enc
/root/.config/ssm/master.pass
/root/.config/ssm/cloud.json
/root/.config/ssm/settings.json
```

The sync server URL is private configuration. Set it during login/register:

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

The sync server stores only encrypted vault bytes. It never decrypts SSH passwords or keys. `ssm list`, `ssm exec`, `ssm shell`, and `sshctl list/run/shell/status` check the remote ETag before reading the vault and pull when the encrypted blob changed. Local edits are uploaded with `ssm push` or `sshctl push`.

## Center Server

Run the encrypted sync server:

```bash
ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
```

Recommended systemd unit:

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

Put it behind your own HTTPS reverse proxy, for example `<sync-server-url> -> 127.0.0.1:18787`.

## Auto Update

Version `1.0.0` and later checks the repo configured in local private settings or `SSM_UPDATE_REPO`. It replaces the current binary when a newer release exists. Manual update:

```bash
SSM_UPDATE_REPO=<owner>/<repo> ssm update
```

Release assets use these names:

```text
ssm-linux-amd64
ssm-linux-arm64
ssm-darwin-amd64
ssm-darwin-arm64
ssm-windows-amd64.exe
ssm-windows-arm64.exe
install.sh
checksums.txt
```

## Agent Skill

Project skill: `skills/agent-ssm/SKILL.md`

Install it into an agent skill directory, then follow it for SSH operations.

## Safety

Do not put domains, account names, emails, passwords, tokens, private keys, `master.pass`, or `cloud.json` in public docs, logs, commits, release notes, or chat.
