---
name: agent-ssm
description: "Cd1s/ssm agent SSH: quote-safe run, parallel map fleet, plan/json/secrets, redirects, dir sync, doctor triage. Never leak secrets."
version: 2.0.0
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, fleet, parallel]
---

# Agent SSM (v1.1+)

Requires **ssm ≥ 1.1.0**.

Rule: **exact alias → plan if unsure → map for multi-host → triage codes before re-quoting → never print secrets.**

## Parallel fleet (preferred for multi-host / multi-script)

```bash
sshctl map host1,host2,host3 -j 8 hostname
sshctl map 'limee-*','aws-*' --json 'uname -s'
sshctl map app --scripts deploy.sh,smoke.sh -j 4
sshctl map a,b --scripts s1.sh,s2.sh --json   # 2 hosts × 2 scripts = 4 parallel jobs
sshctl map targets --plan 'rm -rf /tmp/x'     # dry-run only
```

One failure does not hide other hosts’ stdout. Exit non-zero if any job fails.

## Single host

```bash
sshctl run <alias> --json hostname
sshctl plan <alias> bash -c 'echo hi'          # remote_command + risk, no dial
sshctl run <alias> --secret TOKEN=@./t -- printenv TOKEN
sshctl run <alias> -s <<'EOF'
set -e
echo "quotes safe"
EOF
sshctl run <alias> --scripts a.sh,b.sh         # parallel scripts on one host
```

## Files / dirs / redirects / doctor

```bash
sshctl put <alias> ./tree /remote/tree
sshctl get <alias> /remote/tree ./tree
sshctl redirect set old-name current-alias
sshctl doctor <alias> --deep --json
sshctl check <alias>
```

## Failure triage

1. `sshctl doctor <alias>` or `check`
2. `ssm: error=alias_not_found` → `list --json` or `redirect set`
3. `dial_*` / `host_key_*` → environment (exit **255**), not quotes
4. Only if check ok and output wrong → `--trace` / fix argv or use `-s`

## Never

- print master.pass, cloud.json, private keys, passwords, `--secret` values
- bare `ssh`/`sshpass` unless debugging outside SSM
- re-quote after `dial_*` or `alias_not_found`
