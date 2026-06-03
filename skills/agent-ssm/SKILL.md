---
name: agent-ssm
description: Use headless SSM SSH vault to sync server inventory, add/edit hosts non-interactively, and run SSH commands from the local agent machine.
---

# Agent SSM

Use `/usr/local/bin/sshctl` for SSH. It is the same binary as `/usr/local/bin/ssm`, selected by executable name.

SSH starts from the local agent machine. The center server is only encrypted sync storage.

## Install

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

Optional sync files:

```text
/root/.config/ssm/master.pass
/root/.config/ssm/cloud.json
/root/.config/ssm/settings.json
/root/.config/ssm/update_repo
```

Set them to mode `600`, then run:

```bash
sshctl sync
sshctl status
sshctl list
```

## Connect

Always find the exact alias first:

```bash
sshctl list | grep -Ei '<alias-or-host-fragment>'
sshctl run <exact-alias> 'hostname; uname -sr'
sshctl shell <exact-alias>
sshctl put <exact-alias> ./local-file /remote/file
```

If multiple aliases match, show the candidates instead of guessing.

## Add or edit hosts non-interactively

For agent/non-TTY sessions, prefer `ssm import-json --merge` over the interactive TUI.

Important pitfalls learned from real use:

- `ssm import-json <file>` defaults to replace and can overwrite the whole vault. Use `--merge` for one-off add/edit.
- `ssm import-json` should be given `--master-pass-file`; relying on `SSM_MASTER_PASS=... ssm ...` can fail with `/dev/tty` unlock errors in headless sessions.
- If a platform redacts a pasted private key, ask the user to save it to a local file path. Verify file presence/mode only; do not print key material.

Private-key example:

```bash
chmod 600 /path/to/private.key
json=$(mktemp)
cat > "$json" <<'JSON'
{
  "servers": [
    {
      "alias": "example-alias",
      "host": "203.0.113.10",
      "port": 22,
      "user": "root",
      "private_key_path": "/path/to/private.key"
    }
  ]
}
JSON
ssm --master-pass-file ~/.config/ssm/master.pass import-json "$json" --merge --expect-count 1
rm -f "$json"
sshctl list | grep -Ei 'example-alias|203\.0\.113\.10'
sshctl run example-alias 'hostname; uname -sr'
sshctl push
```

Password example:

```json
{
  "servers": [
    {
      "alias": "example-alias",
      "host": "203.0.113.10",
      "port": 22,
      "user": "root",
      "auth_type": "password",
      "password": "..."
    }
  ]
}
```

To edit an existing host, import the same `alias` with updated `host`/`port`/`user`/auth material and `--merge`. Merge replaces same-name connections/keys while preserving other vault entries.

Supported import fields include `alias`, `host_alias`, `name`, `host`, `port`, `user`, `auth_type`, `password`, `private_key`, `private_key_path`, `key_path`, and `notes`.

## Sync

Sync configuration is read from `/root/.config/ssm/cloud.json`.

Read commands auto-pull when the remote encrypted vault changed:

```bash
sshctl list
sshctl run <alias> 'hostname'
sshctl shell <alias>
sshctl status
```

After local add/edit/remove, verify and push:

```bash
sshctl list | grep -Ei '<alias-or-host-fragment>'
sshctl run <alias> 'hostname; uname -sr'
sshctl push
```

Manual refresh:

```bash
sshctl sync
```

## Rules

- Do not print passwords, private keys, tokens, `master.pass`, `cloud.json`, or vault contents.
- Do not use `sshpass`, `expect`, bare `ssh`, or tmux prompt guessing.
- Use `sshctl list` to find exact aliases.
- Use `nohup`, `systemd-run`, `screen`, or target-native supervisors for long remote work.
