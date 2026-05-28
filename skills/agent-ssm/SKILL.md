---
name: agent-ssm
description: Use headless SSM SSH vault to sync server inventory and run SSH commands from the local agent machine.
---

# Agent SSM

Use `/usr/local/bin/sshctl` for SSH. It is the same binary as `/usr/local/bin/ssm`, selected by executable name.

## Install

```bash
curl -fsSL https://github.com/<owner>/<repo>/releases/latest/download/install.sh | SSM_REPO=<owner>/<repo> sh
```

Required private client files:

```text
/root/.config/ssm/master.pass
/root/.config/ssm/cloud.json
/root/.config/ssm/settings.json
```

Set them to mode `600`, then run:

```bash
sshctl sync
sshctl status
sshctl list
```

## Connect

```bash
sshctl run <alias> '<command>'
sshctl shell <alias>
sshctl put <alias> ./local-file /remote/file
```

SSH starts from the local agent machine. The center server is only encrypted sync storage.

## Sync

The sync server URL is private config in `/root/.config/ssm/cloud.json`.

Read commands auto-pull when the remote encrypted vault changed:

```bash
sshctl list
sshctl run <alias> 'hostname'
sshctl shell <alias>
```

After local add/edit/remove, push:

```bash
sshctl push
```

Manual refresh:

```bash
sshctl sync
```

## Rules

- Do not print domains, identities, passwords, private keys, tokens, `master.pass`, or `cloud.json`.
- Do not use `sshpass`, `expect`, or tmux prompt guessing.
- Do not use legacy `hssh/hrun/hopen/hbg/hpeek/hattach/hclose/hstat/hscp`.
- Use `sshctl list` to find exact aliases.
- Use `nohup`, `systemd-run`, `screen`, or target-native supervisors for long remote work.
