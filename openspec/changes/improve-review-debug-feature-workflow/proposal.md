## Why

SSM already has a compact CLI/TUI codebase, but review, bug investigation, and feature work depend too much on reading implementation details directly. Adding explicit project workflow contracts will make changes easier to audit, regressions easier to reproduce, and future capabilities easier to extend without weakening security boundaries.

## What Changes

- Add a review-support workflow that records expected verification commands, security-sensitive areas, and evidence reviewers should look for.
- Add a bug-investigation workflow that standardizes reproduction notes, environment capture, and regression test expectations.
- Add a feature-extension workflow that defines how new CLI, sync, SSH, vault, and TUI behavior should be scoped, specified, tested, and documented.
- Add lightweight repository guidance so OpenSpec artifacts and implementation tasks align with existing Go package boundaries.
- No user-facing CLI behavior is changed by this proposal itself.
- No breaking changes.

## Capabilities

### New Capabilities

- `review-workflow`: Requirements for making changes easy to review, including scope statements, verification evidence, and security review notes.
- `bug-investigation-workflow`: Requirements for reproducible bug reports, regression tests, and diagnostic context that avoids leaking secrets.
- `feature-extension-workflow`: Requirements for planning and implementing new features within SSM's existing CLI, sync, vault, SSH, and TUI architecture.

### Modified Capabilities

- None.

## Impact

- Affects OpenSpec project artifacts under `openspec/`.
- May add or update repository guidance such as `AGENTS.md` and project context in `openspec/config.yaml`.
- Future implementation work may touch tests, documentation, and package-level structure, but this proposal does not require immediate runtime behavior changes.
- No new runtime dependencies are expected.
