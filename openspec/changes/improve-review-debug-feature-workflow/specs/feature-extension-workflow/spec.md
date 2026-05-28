## ADDED Requirements

### Requirement: Capability Boundary
New feature work SHALL define the affected capability boundary before implementation.

#### Scenario: CLI feature
- **WHEN** a feature adds or changes an `ssm` or `sshctl` command
- **THEN** the proposal or task plan identifies command syntax, noninteractive behavior, compatibility impact, and help text updates

#### Scenario: Internal feature
- **WHEN** a feature changes vault, sync, SSH, update, import, or TUI internals
- **THEN** the proposal or task plan identifies the owning package and the package contract being extended

### Requirement: Backward Compatibility
Feature extensions SHALL preserve existing vault formats, config files, and command behavior unless a breaking change is explicitly proposed.

#### Scenario: Persistent data changes
- **WHEN** a feature changes persisted settings, cloud config, vault JSON, encrypted blob handling, or server data files
- **THEN** the design includes compatibility behavior for existing data and any required migration or fallback

#### Scenario: Automation-facing command changes
- **WHEN** a feature changes `sshctl` output, arguments, exit codes, or default config paths
- **THEN** the design states the compatibility impact for agent and script usage

### Requirement: Test Plan By Package
Feature work SHALL include a package-level test plan that matches the implementation risk.

#### Scenario: Deterministic package change
- **WHEN** a feature changes parsing, config, vault, sync server, cloud client request construction, import, or update comparison logic
- **THEN** the task plan includes focused Go tests for the changed package

#### Scenario: Interactive or SSH feature
- **WHEN** a feature changes Bubble Tea UI, terminal session management, live SSH behavior, or file upload behavior
- **THEN** the task plan includes automated coverage where practical and explicit manual verification for the terminal or SSH path

### Requirement: Documentation Update
User-facing feature work SHALL update documentation and help text together.

#### Scenario: New command or flag
- **WHEN** a feature adds a command, flag, environment variable, or config setting
- **THEN** the implementation updates command help and the relevant README or project guidance

#### Scenario: Security-sensitive feature
- **WHEN** a feature affects authentication, sync, encryption, password caching, private keys, host keys, or auto-update
- **THEN** the documentation states the security model or operational caveat without exposing secrets
