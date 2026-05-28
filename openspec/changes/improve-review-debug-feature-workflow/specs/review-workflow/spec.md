## ADDED Requirements

### Requirement: Scoped Review Summary
Every non-trivial change SHALL include a concise review summary that identifies the touched behavior, affected packages, and user-facing compatibility impact.

#### Scenario: Runtime behavior changes
- **WHEN** a change modifies CLI, TUI, sync, vault, SSH, import, or update behavior
- **THEN** the review summary names the affected behavior, packages, and whether user-facing commands or file formats changed

#### Scenario: Documentation-only changes
- **WHEN** a change only modifies documentation or workflow files
- **THEN** the review summary states that no runtime behavior changed

### Requirement: Verification Evidence
Every change SHALL include verification evidence appropriate to its risk and scope.

#### Scenario: Go source changes
- **WHEN** a change modifies Go source files
- **THEN** verification evidence includes `go test ./...` or an explicit explanation for why it could not be run

#### Scenario: Build-sensitive changes
- **WHEN** a change modifies package wiring, command entrypoints, build flags, dependencies, or platform-specific files
- **THEN** verification evidence includes `go build ./cmd/ssm` or an explicit explanation for why it could not be run

#### Scenario: Untested change path
- **WHEN** a touched behavior cannot be covered by automated tests in the current change
- **THEN** the review notes include the remaining manual verification or residual risk

### Requirement: Security Review Notes
Security-sensitive changes SHALL call out how secrets, encrypted vault data, authentication tokens, private keys, host keys, and remote command output are protected.

#### Scenario: Secret-handling code changes
- **WHEN** a change touches vault persistence, cloud sync credentials, SSH private keys, master password handling, or redaction
- **THEN** the review notes state whether secrets can appear in logs, errors, files, tests, or documentation

#### Scenario: File permission changes
- **WHEN** a change creates or modifies config, vault, key, token, cache, or sync server data files
- **THEN** the review notes identify the expected file or directory permissions

### Requirement: Reviewer Navigation
Changes SHALL be structured so reviewers can locate the key implementation and tests quickly.

#### Scenario: Multi-file implementation
- **WHEN** a change spans multiple packages or command paths
- **THEN** the review summary identifies the main entrypoint file and the primary test file or test command

#### Scenario: Generated or workflow artifacts
- **WHEN** a change adds OpenSpec, agent, or generated workflow files
- **THEN** the review summary separates workflow artifacts from runtime code changes
