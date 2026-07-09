---
name: agent-ssm
description: "Use when an agent manages SSH hosts with Cd1s/ssm: find exact aliases, add/edit/remove hosts safely, sync encrypted vaults, run sshctl commands without quote hell, and never leak secrets."
version: 1.6.0
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault]
---

# Agent SSM

Safety rail for `ssm` / `sshctl`.

Rule: **exact alias first; guarded change second; verify before push; never print secrets.**

Facts: project `https://github.com/Cd1s/ssm`; vault `/root/.config/ssm/connections.enc`; pass file `/root/.config/ssm/master.pass`; sync config `/root/.config/ssm/cloud.json`; binaries `/usr/local/bin/ssm` and `/usr/local/bin/sshctl`. Sync stores encrypted blobs only. SSH starts from this machine.

Extra docs: `README.md`, `references/import-json.md`, `test-prompts.json`.

## Prefer quote-safe remote commands

Agents waste tokens on nested-quote failures. Use these patterns **in order**:

### 1. Multi-arg (best for short commands)

Each argv after the alias is shell-quoted before remote join (unlike raw OpenSSH join):

```bash
sshctl run <exact-alias> hostname
sshctl run <exact-alias> uname -sr
sshctl run <exact-alias> bash -c 'echo "hello world"'
sshctl run <exact-alias> printf %s 'value with spaces'
sshctl run <exact-alias> FOO=bar printenv FOO    # env assigns work in multi-arg
# SSH-like shorthand (same as run):
sshctl <exact-alias> bash -c 'echo hi'
# Debug the exact remote line when unsure about quotes:
SSM_TRACE=1 sshctl run <exact-alias> bash -c 'echo hi'
# or: sshctl run <exact-alias> --trace bash -c 'echo hi'
```

Do **not** wrap the whole remote line in extra outer quotes unless it is a **single** shell-script argument.

### Files

```bash
sshctl put <exact-alias> ./local /remote/dir/file   # creates remote parents
sshctl get <exact-alias> /remote/file ./local       # creates local parents
sshctl list --json                                  # machine-readable aliases
```

### 2. Heredoc script (best for multi-line / any quotes)

```bash
sshctl run <exact-alias> -s <<'EOF'
set -e
cd /tmp
echo "any quotes 'fine'"
grep -R "pattern" .
EOF
```

### 3. Local script file

```bash
sshctl run <exact-alias> -f ./remote-job.sh
```

### 4. Single shell-script string (classic)

```bash
sshctl run <exact-alias> 'hostname; uname -sr'
```

Avoid nesting `"` inside `"` or mixing layers. Prefer (1) or (2).

OpenSSH-style unquoted join (only if you need it):

```bash
sshctl run <exact-alias> --raw ENV=1 true
```

## Workflow

```bash
sshctl status
sshctl sync
sshctl list | grep -Ei '<alias-or-host-fragment>'
sshctl run <exact-alias> hostname
sshctl run <exact-alias> uname -sr
sshctl shell <exact-alias>
# or: sshctl <exact-alias>   # opens shell
sshctl put <exact-alias> ./local-file /remote/file
sshctl get <exact-alias> /remote/file ./local-file
```

If multiple aliases match, show candidates and stop. Do not guess.
If an alias is mistyped, read the `Did you mean:` line and re-run with the exact name.

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
sshctl run example-alias hostname
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
- store inline private keys in chat, logs, or examples; prefer `private_key_path`;
- invent nested shell quotes when `-s` or multi-arg would work.

## Edge Rules

- NAT alias: prefer stable public DNS + SSH port after mapping works; LAN IP only for bootstrap or explicit request.
- Cloudflare-proxied hostnames are not SSH targets; use DNS-only hostname or direct IP/port.
- Reinstalled host key mismatch: after confirmation, clear exact host/port entry, then:

```bash
ssh-keyscan -p <port> -t ed25519,rsa,ecdsa <host> >> ~/.ssh/known_hosts
sshctl run <alias> hostname
```

## Verify

- `sshctl list` shows exact alias/host.
- `sshctl run <alias> hostname` succeeds.
- `sshctl push` succeeds after changes.
- cleanup removes test alias and same-name key.
- `sshctl status` shows `vault=present`; sync is configured when used.
