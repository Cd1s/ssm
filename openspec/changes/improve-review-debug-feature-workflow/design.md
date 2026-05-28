## Context

SSM is a Go command-line and TUI application with security-sensitive behavior across encrypted vault persistence, optional encrypted sync, SSH execution, file upload, host-key handling, and release updates. The repository currently has working tests and concise docs, but the expectations for review evidence, bug reproduction, and feature planning are implicit.

This change introduces OpenSpec contracts and repository guidance rather than changing runtime behavior. The main stakeholders are maintainers reviewing patches, agents making future changes, and users relying on vault secrecy and stable `sshctl` automation.

## Goals / Non-Goals

**Goals:**

- Make future changes easier to review by requiring scoped change summaries, verification evidence, and security notes.
- Make bugs easier to find and fix by requiring reproducible context, regression tests, and secret-safe diagnostics.
- Make new features easier to add by requiring explicit capability boundaries, CLI compatibility notes, and package-level test plans.
- Keep the workflow lightweight enough for small Go CLI changes.

**Non-Goals:**

- Do not change `ssm` or `sshctl` runtime behavior as part of this workflow proposal.
- Do not introduce a new framework, runtime dependency, or test harness.
- Do not require every tiny documentation-only edit to produce large design artifacts.

## Decisions

1. Store workflow requirements as OpenSpec capability specs.

   Rationale: specs make the expected behavior explicit and archiveable, while keeping implementation details out of the requirements. Alternatives considered: only update `AGENTS.md`, which is useful for agents but less structured and harder to validate over time.

2. Keep implementation guidance in `AGENTS.md` and `openspec/config.yaml`.

   Rationale: OpenSpec artifacts describe what must be true, while repository guidance gives agents concrete commands and project constraints. Alternatives considered: place all guidance in specs, which would mix normative requirements with operational advice.

3. Require verification evidence to scale with risk.

   Rationale: this project has both low-risk docs changes and high-risk sync/vault/SSH changes. A single mandatory heavy workflow would slow small fixes; no workflow would make sensitive changes hard to audit. The requirement is therefore to document appropriate evidence for the touched area.

4. Treat secret safety as a cross-cutting workflow constraint.

   Rationale: the project handles passwords, tokens, private keys, encrypted vault blobs, and SSH output. Bug logs and review notes must be useful without exposing those values. Alternatives considered: rely on existing redaction in runtime code only, which does not cover issue reproduction or developer notes.

## Risks / Trade-offs

- Workflow adds process overhead for small patches -> Mitigation: keep requirements concise and allow evidence to be proportional to risk.
- Specs can drift from implementation conventions -> Mitigation: update `openspec/config.yaml` and `AGENTS.md` together when package structure or verification commands change.
- Review notes may become formulaic -> Mitigation: require area-specific evidence rather than a fixed checklist for every change.
- Bug diagnostics may omit useful details due to secret-safety concerns -> Mitigation: require redacted values, file metadata, status codes, command names, and sanitized error messages instead of raw secrets.

## Migration Plan

1. Add the OpenSpec capability specs for review, bug investigation, and feature extension workflows.
2. Update project context in `openspec/config.yaml` with Go commands, package boundaries, and security-sensitive data types.
3. Keep `AGENTS.md` aligned with the OpenSpec guidance.
4. No runtime deployment or rollback is needed because this change is documentation and workflow only.
