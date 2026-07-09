---
name: agent-ssm
description: "Use when an agent manages SSH hosts with Cd1s/ssm: find exact aliases, add/edit/remove hosts safely, sync encrypted vaults, run quote-safe sshctl commands, triage dial/host-key/alias failures, and never leak secrets."
version: 1.7.0
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault]
---

# Agent SSM

Safety rail for `ssm` / `sshctl` (agent-headless).

Rule: **exact alias first; quote-safe run second; triage failures before retrying quotes; never print secrets.**

Facts: project `https://github.com/Cd1s/ssm`; vault often `~/.config/ssm/connections.enc` (or `/root/.config/ssm` on root agents); binaries `ssm` + `sshctl` (same binary). Sync stores encrypted blobs only. Real SSH always starts from this machine.

Requires **ssm ≥ 1.0.10** for multi-arg quoting, `-s`/`-f`, `get`, structured errors, and `check`.

## Quote-safe remote commands (order of preference)

### 1. Multi-arg (short commands)

Each argv is shell-quoted before remote join (fixed vs 1.0.7 `strings.Join`):

```bash
sshctl run <exact-alias> hostname
sshctl run <exact-alias> printf '%s\n' 'hello world'
sshctl run <exact-alias> bash -c 'echo "hello world"'
sshctl run <exact-alias> FOO=bar printenv FOO
sshctl run <exact-alias> --timeout 10s true
```

### 2. Heredoc `-s` (multi-line / any quotes)

```bash
sshctl run <exact-alias> -s <<'EOF'
set -e
echo "quotes are safe"
printf '%s\n' "a'b"
EOF
```

### 3. Local script file

```bash
sshctl run <exact-alias> -f ./remote-job.sh
```

### 4. Single shell-script string (classic SSH)

```bash
sshctl run <exact-alias> 'hostname; uname -sr'
```

SSM does **not** rewrite a single giant quoted string. If *you* break quotes inside it, that is not an SSM bug — switch to (1) or (2).

Debug exact remote line:

```bash
sshctl run <exact-alias> --trace printf '%s\n' 'hello world'
# or: SSM_TRACE=1 sshctl run ...
```

`--raw` = old OpenSSH space-join (only when you need that).

## Files / inventory

```bash
sshctl list --json
sshctl put <alias> ./local /remote/dir/file    # mkdir -p remote parents
sshctl get <alias> /remote/file ./local        # mkdir -p local parents
```

## Failure triage (do this BEFORE rewriting quotes)

Failures fall into **four buckets**. Do not spend tokens re-quoting when the code says otherwise.

### 0. First probe

```bash
sshctl check <exact-alias>
# or: sshctl check <exact-alias> --json
sshctl list --json | grep -F '<alias-or-fragment>'
```

### 1. Quote / remote command shape — SSM-related

Symptoms: wrong stdout, unexpected shell parse, pipes/`$` broken **and** `sshctl check` is ok.

- Prefer multi-arg or `-s`, not nested `'"'"'` hell.
- Use `--trace` once; if the printed remote command is wrong, fix argv; if it is right, the bug is remote.

### 2. Alias / migration — not SSM quote

```
ssm: error=alias_not_found
ssm: did_you_mean=...
```

Fix: pick exact current alias from `sshctl list --json`. Watchdogs may still point at old names after host moves.

### 3. Network / dial / host key — not SSM quote

```
ssm: error=dial_timeout|dial_refused|dial_network|host_key_mismatch
```

Exit code **255** = connection-layer failure (not remote `exit 1`).

- `dial_*`: host offline, wrong port, firewall, IPv6 route — environment.
- `host_key_mismatch`: reinstall/MITM. **Only after user confirms rebuild:**

```bash
ssh-keygen -R '[host]:port'   # or host if port 22
ssh-keyscan -p <port> -t ed25519,rsa,ecdsa <host> >> ~/.ssh/known_hosts
sshctl check <alias>
```

### 4. Remote system / service broken — not SSM

`check` dials ok but probe empty/fails, or ssh resets, empty command effects: remote OS/libs/sshd unhealthy. Inspect remote health; do not rewrite client quotes.

### Other non-SSM intercepts

Local agent safety layers may block `reboot`/`shutdown` even inside remote commands — that is the agent policy, not SSM.

## Workflow

```bash
sshctl status
sshctl sync
sshctl list --json
sshctl check <exact-alias>
sshctl run <exact-alias> hostname
sshctl put <exact-alias> ./f /remote/f
sshctl get <exact-alias> /remote/f ./f
sshctl push   # after vault edits
```

## Add / Edit

Never bare `ssm import-json <file>` for one-host edits (replace risk). Use `--merge` + `--expect-count`:

```bash
json=$(mktemp)
cat > "$json" <<'JSON'
{"servers":[{"alias":"example-alias","host":"203.0.113.10","port":22,"user":"root","private_key_path":"/path/to/key"}]}
JSON
ssm --master-pass-file ~/.config/ssm/master.pass import-json "$json" --merge --expect-count 1
rm -f "$json"
sshctl check example-alias
sshctl push
```

## Remove

```bash
ssm --master-pass-file ~/.config/ssm/master.pass remove <alias>
sshctl push
```

Disposable test aliases: `zz-ssm-skill-test-*`.

## Stop Before

- deleting/replacing real hosts;
- destructive remote commands;
- import without `--merge` when only one host should change;
- push after failed verify;
- accepting host key changes without user confirmation.

## Never

- print `master.pass`, `cloud.json`, private keys, passwords, tokens, vault plaintext;
- use bare `ssh`/`sshpass`/`expect` unless debugging outside SSM;
- burn tokens re-quoting after `ssm: error=dial_*` or `alias_not_found`;
- invent nested quotes when `-s` or multi-arg works.
