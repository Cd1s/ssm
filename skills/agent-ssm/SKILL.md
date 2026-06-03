---
name: agent-ssm
description: "Use when managing SSH hosts through Cd1s/ssm encrypted vault: list exact aliases, add/edit/remove servers non-interactively, sync inventory, and run SSH commands from the local agent machine."
version: 1.2.0
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault]
---

# Agent SSM

SSM is the source of truth for server credentials. SSH connections start from the local agent machine; the sync server only stores encrypted vault blobs.

- Vault: `/root/.config/ssm/connections.enc`
- Master password file: `/root/.config/ssm/master.pass`
- Optional sync config: `/root/.config/ssm/cloud.json`
- Binaries: `/usr/local/bin/ssm` and `/usr/local/bin/sshctl` (same binary, behavior selected by executable name)
- Project: `https://github.com/Cd1s/ssm`

## Common workflow

Find exact aliases before operating:

```bash
sshctl status
sshctl sync
sshctl list | grep -Ei '<alias-or-host-fragment>'
sshctl run <exact-alias> 'hostname; uname -sr'
sshctl shell <exact-alias>
sshctl put <exact-alias> ./local-file /remote/file
```

If multiple aliases match, show candidates or choose only when obvious.

## Add / edit servers non-interactively

Use `ssm import-json --merge`; **never run bare `ssm import-json <file>` for one-host changes** because the default is replace and can overwrite the vault.

Use `--master-pass-file` for `ssm` commands in agent/non-TTY sessions. `SSM_MASTER_PASS=... ssm ...` can fail with `/dev/tty` unlock errors.

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

To modify a server, import the same `alias` with updated fields and `--merge`. Same-name connections/keys are replaced; other vault entries are preserved.

For password auth, import JSON uses `"auth_type": "password"` and `"password": "..."`.

For full import shapes, supported fields, test-add-cleanup pattern, and pitfalls, load `references/import-json.md`.

## Remove servers / cleanup tests

```bash
ssm --master-pass-file ~/.config/ssm/master.pass remove <alias>
ssm --master-pass-file ~/.config/ssm/master.pass keys remove <alias>  # if import created a same-name key
sshctl list | grep -F '<alias>' || echo 'removed'
sshctl push
```

When doing a temporary test server, add with a clearly disposable alias like `zz-ssm-skill-test-*`, verify `sshctl run`, then remove both connection and same-name key and push cleanup.

## Sync behavior

- `sshctl list/run/shell/status` auto-pull if remote encrypted vault changed and sync is configured.
- After local add/edit/remove, verify then explicitly `sshctl push`.
- Manual refresh: `sshctl sync` (pull).

## Rules

- Do not print `master.pass`, `cloud.json`, private keys, passwords, tokens, or decrypted vault contents.
- If a pasted private key is redacted by the platform, ask the user to save it to a local file path; verify only with `stat`, not file content.
- Do not recreate or read old `servers.json`; ssm vault is the source of truth.
- Do not use bare `ssh`, `sshpass`, `expect`, or prompt-guessing wrappers.
- For long remote work, use target-side `nohup`, `systemd-run`, `screen`, or service units.

## Verification checklist

- [ ] `sshctl list` shows the exact alias and host after add/edit.
- [ ] `sshctl run <alias> 'hostname; uname -sr'` succeeds.
- [ ] `sshctl push` succeeds after changes.
- [ ] For cleanup, test alias and same-name key are gone.
- [ ] `sshctl status` reports `vault=present` and, when configured, `sync=configured`.
