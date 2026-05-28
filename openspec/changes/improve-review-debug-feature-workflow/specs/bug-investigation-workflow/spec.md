## ADDED Requirements

### Requirement: Reproducible Bug Context
Bug investigation work SHALL capture enough context to reproduce or reasonably narrow the issue without exposing secrets.

#### Scenario: CLI bug report
- **WHEN** a bug affects `ssm` or `sshctl` command behavior
- **THEN** the investigation notes include the command shape, exit behavior, relevant flags, and sanitized output or error text

#### Scenario: Environment-dependent bug
- **WHEN** a bug may depend on OS, shell, terminal, config path, network, or remote server behavior
- **THEN** the investigation notes include the relevant environment details that can be shared safely

### Requirement: Secret-Safe Diagnostics
Bug diagnostics SHALL avoid recording raw passwords, private keys, bearer tokens, master passwords, vault plaintext, or unredacted remote secrets.

#### Scenario: Sensitive value appears in evidence
- **WHEN** logs, files, command output, or errors contain a sensitive value
- **THEN** the diagnostic artifact replaces that value with a clear redaction marker while preserving the surrounding technical signal

#### Scenario: Encrypted vault sync issue
- **WHEN** investigating cloud or sync server behavior
- **THEN** diagnostics may include status codes, ETags, blob sizes, timestamps, and hashes but not decrypted vault contents or authentication tokens

### Requirement: Regression Coverage
Bug fixes SHALL include regression coverage for the failing behavior unless the fix is not practically testable.

#### Scenario: Unit-testable bug
- **WHEN** the bug is in parsing, config handling, vault merging, sync server behavior, update logic, or other deterministic code
- **THEN** the fix includes a focused automated test that fails before the fix and passes after it

#### Scenario: External-system bug
- **WHEN** the bug depends on live SSH servers, terminals, GitHub releases, or network conditions that cannot be reliably automated
- **THEN** the fix includes the closest practical automated coverage plus documented manual verification steps

### Requirement: Root Cause Notes
Bug fixes SHALL identify the root cause and the behavior changed by the fix.

#### Scenario: Fix submitted
- **WHEN** a bug fix is ready for review
- **THEN** the summary distinguishes the observed symptom, root cause, code path changed, and regression coverage
