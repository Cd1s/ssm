# Install or update Agent SSM for Codex and Hermes

Use the one official `agent-ssm` skill name. Obtain the bundle only from the
same reviewed exact tag as the binary contract being deployed. For the staged
v2 release that exact tag is `v2.0.0`; do not copy from a moving default branch
or from an unreviewed working tree.

Before deployment, run the target binary's read-only version probe:

```bash
sshctl --json --version
```

The exact v2.0.0 bundle supports v1.4.3/v1.4.4 through its v1 compatibility
branch and v2.0.0 through its v2 compatibility branch. Any other version or an
unsupported major must fail closed.

From an exact-tag v2.0.0 checkout or verified source archive, install into an
explicit private platform root without touching the running agent's copy during
review:

```bash
sh scripts/install-agent-ssm-skill.sh --platform codex --source skills/agent-ssm --root "${CODEX_HOME:-$HOME/.codex}" --sshctl "$(command -v sshctl)"
sh scripts/install-agent-ssm-skill.sh --platform hermes --source skills/agent-ssm --root "${HERMES_HOME:-$HOME/.hermes}" --sshctl "$(command -v sshctl)"
```

The destinations are respectively
`${CODEX_HOME:-$HOME/.codex}/skills/agent-ssm` and
`${HERMES_HOME:-$HOME/.hermes}/skills/agent-ssm`. The helper verifies the
version first, validates the complete bundled file set, rejects symlinked roots
or sources, stages within the destination filesystem, and then publishes the
directory by rename.

For an update, inspect the exact-tag diff and pass `--replace`. The helper moves
the prior directory into a sibling private `.agent-ssm.backup.*` directory and
reports its path; it never silently deletes the prior skill. Validate the new
copy and its version branch before removing any backup.

Release canaries must use temporary Codex and Hermes roots. Do not update the
running bridge agent skill mid-review, and do not read or copy live SSM config,
vault, credentials, inventory, or sync state while testing skill deployment.
