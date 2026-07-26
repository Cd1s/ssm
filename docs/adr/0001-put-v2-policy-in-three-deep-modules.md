---
status: accepted
---

# Put v2 policy in three deep modules

SSM v2 will make a machine contract module, a sync transaction module, and an
inventory transaction module the exclusive owners of their public policy. This
keeps command code limited to parsing, invocation, and command-specific success
payloads while preserving the existing deep cryptography, host-key, SSH pool,
script, transfer, sync-server, and update mechanisms identified by the
[architecture audit](../plans/ssm-v2-architecture-audit.md).

## Considered options

- Keep policy in `cmd/ssm` and split only large files.
- Add wrapper packages while command callers retain classification, refresh,
  projection, and recovery decisions.
- Move each policy family behind one concrete module and require deletion of
  duplicate command-owned policy.

The first two options fail the audit's deletion test: removing their new files
would not force meaningful policy back into multiple callers.

## Consequences

Migration is incomplete until duplicate error switches and writers, refresh
helpers, projection/rebase/mark logic, and rollback policy are removed from
`cmd/ssm`. Concrete modules are preferred over speculative Go interfaces; the
existing deep mechanism modules remain separate. The complete ownership and
verification rules are recorded in the
[v2 decision log](../plans/ssm-v2-decision-log.md).
