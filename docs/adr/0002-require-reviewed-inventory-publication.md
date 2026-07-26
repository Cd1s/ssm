---
status: accepted
---

# Require reviewed inventory publication

Every v2 inventory mutation becomes a reviewable pending transaction, and no
mutation entry point publishes automatically. Publication uses explicit alias
and saved-key dependencies, never widens a requested scope, and keeps a
transaction pending until the intended remote encrypted-blob identity is
confirmed.

## Considered options

- Preserve direct-save and automatic-push behavior for legacy mutations.
- Automatically include transitive prerequisites in `push --only`.
- Mark local state published before remote PUT and compensate on failure.
- Use explicit pending scopes, reject unmet dependencies before network I/O,
  and reconcile durable publishing intent after ambiguous outcomes.

The rejected options can publish unrelated changes or lose a transaction in a
crash window. The selected model favors explicit review and recoverability over
convenience and requires stable transaction IDs throughout retries.

## Consequences

Bare `push` is invalid, `push --all` handles only its invocation-start non-empty
pending snapshot, and empty-ledger divergence requires a separate reviewed
recovery flow. These are approved v2 breaking changes governed by the
[compatibility inventory](../plans/ssm-v2-decision-log.md#explicitly-approved-breaking-change-inventory)
and the hard publication contracts in [CONTEXT.md](../../CONTEXT.md).
