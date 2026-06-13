---
name: agent-ssm
description: "Use when an agent manages SSH hosts with Cd1s/ssm: find exact aliases, add/edit/remove hosts safely, sync encrypted vaults, run sshctl commands, and never leak secrets."
version: 1.4.0
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault]
---

# Agent SSM

Safety rail for `ssm` / `sshctl`.

Rule: **exact alias first; guarded change second; verify before push; never print secrets.**

Facts: project `https://github.com/Cd1s/ssm`; vault `/root/.config/ssm/connections.enc`; pass file `/root/.config/ssm/master.pass`; sync config `/root/.config/ssm/cloud.json`; binaries `/usr/local/bin/ssm` and `/usr/local/bin/sshctl`. Sync stores encrypted blobs only. SSH starts from this machine.

Extra docs: `README.md`, `references/import-json.md`, `test-prompts.json`.

## Workflow

```bash
sshctl status
sshctl sync
sshctl list | grep -Ei '<alias-or-host-fragment>'
sshctl run <exact-alias> 'hostname; uname -sr'
sshctl shell <exact-alias>
sshctl put <exact-alias> ./local-file /remote/file
```

If multiple aliases match, show candidates and stop. Do not guess.

## Add / Edit

Never run bare `ssm import-json <file>` for one-host changes. It can replace the vault.

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

Edit = import same `alias` with new fields. Password auth = add `"auth_type": "password"` and `"password": "..."`. More shapes: `references/import-json.md`.

## Remove

```bash
ssm --master-pass-file ~/.config/ssm/master.pass remove <alias>
ssm --master-pass-file ~/.config/ssm/master.pass keys remove <alias>  # only if same-name key was created
sshctl list | grep -F '<alias>' || echo 'removed'
sshctl push
```

Test aliases must be disposable: `zz-ssm-skill-test-*`.

## Stop Before

- deleting/replacing a real host;
- running destructive remote commands;
- importing JSON that changes more hosts than requested;
- pushing after failed verification;
- accepting changed SSH host keys without user confirmation.

## Never

- print `master.pass`, `cloud.json`, private keys, passwords, tokens, or decrypted vault contents;
- read/recreate old `servers.json`; the vault is source of truth;
- use bare `ssh`, `sshpass`, `expect`, or prompt-guessing wrappers unless explicitly debugging outside SSM;
- store inline private keys in chat, logs, or examples; prefer `private_key_path`.

## Edge Rules

- NAT alias: prefer stable public DNS + SSH port after mapping works; LAN IP only for bootstrap or explicit request.
- Cloudflare-proxied hostnames are not SSH targets; use DNS-only hostname or direct IP/port.
- Reinstalled host key mismatch: after confirmation, clear exact host/port entry, then:

```bash
ssh-keyscan -p <port> -t ed25519,rsa,ecdsa <host> >> ~/.ssh/known_hosts
sshctl run <alias> 'hostname; uname -sr'
```

## Verify

- `sshctl list` shows exact alias/host.
- `sshctl run <alias> 'hostname; uname -sr'` succeeds.
- `sshctl push` succeeds after changes.
- cleanup removes test alias and same-name key.
- `sshctl status` shows `vault=present`; sync is configured when used.
