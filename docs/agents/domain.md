# Domain docs

This repository uses a single domain context. Engineering skills should read
the root domain glossary and relevant architectural decision records before
exploring or changing an affected area.

## Before exploring

- Read `CONTEXT.md` at the repository root.
- Read ADRs under `docs/adr/` that touch the area being changed.

If either location does not exist, proceed silently. Domain-modeling work
creates or extends these files only when terminology or a decision is actually
resolved.

## File structure

```text
/
├── CONTEXT.md
├── docs/
│   └── adr/
├── cmd/
└── internal/
```

## Use the glossary's vocabulary

When an issue, proposal, hypothesis, or test names a domain concept, use the
term defined in `CONTEXT.md`. Do not drift to a synonym that the glossary
explicitly avoids.

If a needed concept is absent, first check whether existing repository
language already covers it. Record a genuine unresolved terminology gap for
domain-modeling work rather than inventing a definition.

## Flag ADR conflicts

If proposed work contradicts an existing ADR, identify the ADR and make the
conflict explicit instead of silently overriding the recorded decision.
