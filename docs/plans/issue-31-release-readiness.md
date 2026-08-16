# Issue #31 — SSM v2 final release readiness

This checked-in report is **manifest-derived** and **secret-free**. It is rendered from `verificationManifest()` plus the reviewed final-candidate evidence record; it contains no credentials, private keys, or decrypted vault contents.

The report is a deterministic review artifact, not a release authority. It records the outcome labels and public tool versions observed for the final candidate; Exact-HEAD binding is supplied by the attached PR and native CI evidence and must match the current pushed commit before merge.

Verification performs no merge, tag, release, upload, publication, or real installation. It only evaluates the checked-in source, tests, documentation, and temporary verifier-owned outputs.

## Recorded final candidate results

These secret-free outcomes record the complete Issue #31 command set. Any source, test, manifest, or report change invalidates the record until every command is rerun; the PR evidence supplies the exact commit identity for the rerun.

| exact command | result |
| --- | --- |
| `test -z "$(gofmt -l .)"` | `passed` |
| `go run ./cmd/verify list` | `passed` |
| `go run ./cmd/verify ci` | `passed` |
| `go run ./cmd/verify release` | `preflight_passed` |
| `go test ./... -run 'TestApprovedV2BreakingChangeBaselines\|TestDeepPolicyOwnershipContraction\|TestReleaseProvenanceForEveryTarget\|TestV2MigrationDocumentationContract' -count=1` | `passed` |
| `go test ./...` | `passed` |
| `go test -race ./...` | `passed` |
| `go vet ./...` | `passed` |
| `scripts/ssh_matrix_test.sh` | `passed` |
| `git diff --check` | `passed` |
| `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -exec=true ./...` | `passed` |
| `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./...` | `passed` |
| `CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go test -exec=true ./...` | `passed` |
| `CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go vet ./...` | `passed` |

## Observed final-gate tool versions

The versions below were observed in the Linux final-gate environment. The manifest sections retain the executable per-check prerequisite contracts; native Windows and Darwin outcomes are attached as exact-HEAD CI evidence.

| tool | observed version |
| --- | --- |
| Go | `1.25.13` |
| git | `2.47.3` |
| jq | `1.7` |
| golangci-lint | `2.11.4` |
| Node.js | `20.19.2` |
| npm/npx | `9.2.0` |
| GNU Bash | `5.2.37(1)-release` |
| OpenSSH | `10.0p2 Debian-7+deb13u4` |

## Explicit rehearsal outcomes

These outcomes are exercised directly by the release profile rather than inferred from a summary.

| required outcome | result | direct fixture evidence |
| --- | --- | --- |
| rollback rehearsal | `passed` | internal/update/update_test.go — TestFailedMigrationPreservesExecutable; cmd/ssm/publication_intent_compiled_test.go — TestPublicationIntentCrashMatrix, TestPublicationReconcilesLostResponse, TestPublicationReconcilesFinalizeFailure |
| trust-negative rehearsal | `passed` | internal/update/update_test.go — TestProvenanceIdentityMatrix, TestProvenanceDigestBinding, TestTrustFailurePreservesExecutable, TestChecksumForAssetRequiresMatchingAsset, TestCopyAndVerifyRejectsChecksumMismatch |
| structural contraction | `passed` | cmd/ssm/deep_policy_ownership_test.go — TestDeepPolicyOwnershipContraction, TestDeepPolicyOwnershipAnalyzerAdversarialFixtures |
| clean-tree/no-publication proof | `passed` | cmd/verify/main_test.go — TestProfilesAreNonMutating, TestVerificationChildrenHaveNoInheritedPublicationAuthority, TestProfileDetectsAllRefMutations |

## Manifest profile membership, equivalence, and check counts

Manifest schema version: `1`. Profile order and membership below are the executable order.

| profile | equivalence | check count | purpose |
| --- | --- | ---: | --- |
| `list` | `manifest_only` | 0 | Print this deterministic machine-reviewable manifest. |
| `fast` | `convenience_only` | 3 | Convenience-only developer feedback; not merge- or release-equivalent. |
| `ci` | `merge` | 11 | The complete non-publishing merge verification profile used by Make and GitHub CI. |
| `release` | `initial_v2_release_readiness` | 33 | Non-publishing final SSM v2 release readiness with direct public-contract, migration, coverage, and pinned-provenance verification. |

### `list` membership

- equivalence: `manifest_only`
- check count: `0`
- profile prerequisites: none
- checks: none

### `fast` membership

- equivalence: `convenience_only`
- check count: `3`
- profile prerequisites: `tool:git@any`, `repository:fully-populated-regular-tracked-worktree@stage-0-modes-100644-or-100755-no-sparse`, `repository:safe-local-git-configuration@no-includes-or-executable-command-authority`, `repository:no-nonignored-untracked-paths@git-ls-files-others-exclude-standard-z`
- checks in order: `format`, `vet`, `unit`

### `ci` membership

- equivalence: `merge`
- check count: `11`
- profile prerequisites: `tool:git@any`, `repository:fully-populated-regular-tracked-worktree@stage-0-modes-100644-or-100755-no-sparse`, `repository:safe-local-git-configuration@no-includes-or-executable-command-authority`, `repository:no-nonignored-untracked-paths@git-ls-files-others-exclude-standard-z`
- checks in order: `format`, `lint`, `vet`, `vulnerability`, `build`, `unit`, `race`, `agent-prompts-json`, `request-schema-json`, `ssh-matrix-shell-syntax`, `ssh-matrix`

### `release` membership

- equivalence: `initial_v2_release_readiness`
- check count: `33`
- profile prerequisites: `tool:git@any`, `repository:fully-populated-regular-tracked-worktree@stage-0-modes-100644-or-100755-no-sparse`, `repository:safe-local-git-configuration@no-includes-or-executable-command-authority`, `repository:no-nonignored-untracked-paths@git-ls-files-others-exclude-standard-z`
- checks in order: `format`, `lint`, `vet`, `vulnerability`, `build`, `unit`, `race`, `agent-prompts-json`, `request-schema-json`, `ssh-matrix-shell-syntax`, `ssh-matrix`, `source-version`, `asset-linux-amd64`, `asset-linux-arm64`, `asset-darwin-amd64`, `asset-darwin-arm64`, `asset-windows-amd64`, `asset-windows-arm64`, `updater-selection`, `release-notes`, `install-shell-syntax`, `release-checksums`, `release-provenance`, `provenance-failure-paths`, `checksum-failure-paths`, `v2-public-contracts`, `v2-policy-contracts`, `v2-update-contracts`, `v2-structure-docs`, `v2-release-contracts`, `markdown-contracts`, `coverage-observation`, `v2-readiness-report`

## Release profile exact checks, actions, and tool prerequisites

The `release` profile has equivalence `initial_v2_release_readiness` and `33` checks. Every listed check is rendered from its manifest record; action vectors are not inferred from prose.

Release profile prerequisites: `tool:git@any`, `repository:fully-populated-regular-tracked-worktree@stage-0-modes-100644-or-100755-no-sparse`, `repository:safe-local-git-configuration@no-includes-or-executable-command-authority`, `repository:no-nonignored-untracked-paths@git-ls-files-others-exclude-standard-z`

### 01. `format`

- requirement: `required`
- description: Require gofmt-clean source without rewriting files.
- action: command `{goroot}/bin/gofmt{exe} -l . expect=stdout_empty`
- tool/file/capability prerequisites: `tool:gofmt@go1.25.13`

### 02. `lint`

- requirement: `required`
- description: Run the reviewed golangci-lint baseline.
- action: command `golangci-lint run --new-from-patch {temp}/lint.patch`
- tool/file/capability prerequisites: `tool:golangci-lint@2.11.4`, `git_ref:v1.2.0@commit`, `capability:repository-modules@go-mod-download`
- preparation `lint-patch`: Prepare a no-filter v1.2.0-to-tracked-worktree patch consumed by lint.; working directory `source_repository`; output `{temp}/lint.patch`; action builtin `lint-patch`

### 03. `vet`

- requirement: `required`
- description: Run Go vet across all packages.
- action: command `go vet ./...`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 04. `vulnerability`

- requirement: `required`
- description: Run govulncheck v1.6.0 across all packages.
- action: command `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`, `capability:govulncheck-module@network-or-module-cache`

### 05. `build`

- requirement: `required`
- description: Build ssm into a profile-owned temporary directory.
- action: command `go build -buildvcs=false -o {temp}/ssm{exe} ./cmd/ssm`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 06. `unit`

- requirement: `required`
- description: Run the complete Go unit and integration test suite.
- action: command `go test ./...`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 07. `race`

- requirement: `conditional`
- description: Run the complete Go test suite with the race detector on a natively supported host.
- activation: `native_supported_host_with_cgo_and_c_compiler`
- required contexts: `github_actions_linux`
- action: command `go test -race -timeout=15m ./...`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`, `capability:native-race@supported-host-cgo-c-compiler`

### 08. `agent-prompts-json`

- requirement: `required`
- description: Validate the agent prompt artifact as JSON.
- action: command `jq empty skills/agent-ssm/test-prompts.json`
- tool/file/capability prerequisites: `tool:jq@any`

### 09. `request-schema-json`

- requirement: `required`
- description: Validate the request-v1 schema artifact as JSON.
- action: command `jq empty skills/agent-ssm/references/request-v1.schema.json`
- tool/file/capability prerequisites: `tool:jq@any`

### 10. `ssh-matrix-shell-syntax`

- requirement: `required`
- description: Parse the live SSH matrix script without executing it.
- action: command `bash -n scripts/ssh_matrix_test.sh`
- tool/file/capability prerequisites: `tool:bash@any`

### 11. `ssh-matrix`

- requirement: `conditional`
- description: Run the existing live OpenSSH behavior matrix when its Linux prerequisites are available.
- required contexts: `github_actions_linux`
- action: command `bash scripts/ssh_matrix_test.sh`
- tool/file/capability prerequisites: `platform:linux@any`, `tool:awk@any`, `tool:bash@any`, `tool:cat@any`, `tool:chmod@any`, `tool:cp@any`, `tool:dd@any`, `tool:dirname@any`, `tool:find@any`, `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`, `tool:grep@any`, `tool:head@any`, `tool:id@any`, `tool:ln@any`, `tool:mkdir@any`, `tool:mktemp@any`, `tool:nohup@any`, `tool:printenv@any`, `tool:rm@any`, `tool:script@any`, `tool:sed@any`, `tool:seq@any`, `tool:sh@any`, `tool:sha256sum@any`, `tool:sleep@any`, `tool:ssh@any`, `tool:ssh-keygen@any`, `tool:touch@any`, `executable_alternatives:sshd@SSHD-then-PATH-then-/usr/sbin/sshd [alternatives: environment_executable:SSHD@if-set-required, path_executable:sshd@fallback, system_path:/usr/sbin/sshd@executable-fallback]`, `tool:tr@any`, `tool:wc@any`, `system_path:/dev/null@readable`, `system_path:/dev/zero@readable`, `system_path:/run/sshd@directory`, `system_path:/usr/lib/openssh/sftp-server@executable`

### 12. `source-version`

- requirement: `required`
- description: Validate the source version as a release version.
- action: builtin `source-version`
- tool/file/capability prerequisites: `file:cmd/ssm/main.go@tracked`

### 13. `asset-linux-amd64`

- requirement: `required`
- description: Build the canonical ssm-linux-amd64 release asset in temporary storage.
- action: command `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-linux-amd64 ./cmd/ssm env=GOOS=linux,GOARCH=amd64`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 14. `asset-linux-arm64`

- requirement: `required`
- description: Build the canonical ssm-linux-arm64 release asset in temporary storage.
- action: command `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-linux-arm64 ./cmd/ssm env=GOOS=linux,GOARCH=arm64`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 15. `asset-darwin-amd64`

- requirement: `required`
- description: Build the canonical ssm-darwin-amd64 release asset in temporary storage.
- action: command `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-darwin-amd64 ./cmd/ssm env=GOOS=darwin,GOARCH=amd64`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 16. `asset-darwin-arm64`

- requirement: `required`
- description: Build the canonical ssm-darwin-arm64 release asset in temporary storage.
- action: command `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-darwin-arm64 ./cmd/ssm env=GOOS=darwin,GOARCH=arm64`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 17. `asset-windows-amd64`

- requirement: `required`
- description: Build the canonical ssm-windows-amd64.exe release asset in temporary storage.
- action: command `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-windows-amd64.exe ./cmd/ssm env=GOOS=windows,GOARCH=amd64`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 18. `asset-windows-arm64`

- requirement: `required`
- description: Build the canonical ssm-windows-arm64.exe release asset in temporary storage.
- action: command `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-windows-arm64.exe ./cmd/ssm env=GOOS=windows,GOARCH=arm64`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 19. `updater-selection`

- requirement: `required`
- description: Prove updater selection matches all six release asset names and rejects incomplete or unsupported release manifests without fallback.
- action: command `go test ./internal/update -run ^(TestAssetNameForSupportedPlatforms|TestReleaseAssetSelectionIsStrict|TestInvalidSelectedReleaseDoesNotFallBackOrDownload)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 20. `release-notes`

- requirement: `required`
- description: Require non-empty release notes for the source version.
- action: builtin `release-notes`
- tool/file/capability prerequisites: `file:RELEASE_NOTES.md@tracked`

### 21. `install-shell-syntax`

- requirement: `required`
- description: Parse the published installer without executing it.
- action: command `sh -n install.sh`
- tool/file/capability prerequisites: `tool:sh@any`, `file:install.sh@tracked`

### 22. `release-checksums`

- requirement: `required`
- description: Compute SHA-256 digests for all six assets and install.sh without writing release output.
- action: builtin `release-checksums`
- tool/file/capability prerequisites: `file:install.sh@tracked`

### 23. `release-provenance`

- requirement: `required`
- description: Generate and verify test-owned keyless provenance for all six release assets without publication.
- action: builtin `release-provenance`
- tool/file/capability prerequisites: none

### 24. `provenance-failure-paths`

- requirement: `required`
- description: Exercise pinned certificate/statement identity, exact digest binding, and byte-preserving trust failures through the updater verifier.
- action: command `go test ./internal/update -run ^(TestProvenanceIdentityMatrix|TestProvenanceDigestBinding|TestTrustFailurePreservesExecutable)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 25. `checksum-failure-paths`

- requirement: `required`
- description: Exercise checksum selection, mismatch, and no-replacement failure paths.
- action: command `go test ./internal/update -run ^(TestChecksumForAsset|TestChecksumForAssetRequiresMatchingAsset|TestCopyAndVerifyRejectsChecksumMismatch|TestDownloadVersionVerifiesChecksumBeforeReplace)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 26. `v2-public-contracts`

- requirement: `required`
- description: Run the compiled SSM v2 public, sync, publication, stream, push, and transfer contract fixtures directly.
- action: command `go test ./cmd/ssm -run ^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 27. `v2-policy-contracts`

- requirement: `required`
- description: Run the deep sync and inventory transaction policy fixtures directly.
- action: command `go test ./internal/synctransaction ./internal/inventorytransaction -run ^(TestSyncTransactionPolicy|TestStreamTransactionPolicy|TestInventoryTransactionPolicy)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 28. `v2-update-contracts`

- requirement: `required`
- description: Run explicit migration authorization, same-major selection, preflight, rollback, and executable-preservation fixtures directly.
- action: command `go test ./internal/update -run ^(TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork|TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork|TestSameMajorSelection|TestCrossMajorRequiresExplicitAuthorization|TestFailedMigrationPreservesExecutable)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 29. `v2-structure-docs`

- requirement: `required`
- description: Run three-module contraction, adversarial ownership, bilingual migration documentation, and public help fixtures directly.
- action: command `go test ./cmd/ssm -run ^(TestDeepPolicyOwnershipContraction|TestDeepPolicyOwnershipAnalyzerAdversarialFixtures|TestV2MigrationDocumentationContract|TestSSHCTLCommandHelpNeedsNoUnlockOrTTY|TestRunHelpDocumentsFastStream)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 30. `v2-release-contracts`

- requirement: `required`
- description: Run release superset, non-mutation, no-publication-authority, source grammar, workflow identity, and provenance workflow fixtures directly.
- action: command `go test ./cmd/verify -run ^(TestReleaseStrictlyContainsCI|TestProfilesAreNonMutating|TestVerificationChildrenHaveNoInheritedPublicationAuthority|TestSourceVersionMatchesReleaseWorkflowGrammar|TestReleaseProvenanceForEveryTarget|TestReleaseWorkflowUsesCredentialFreeVerifierPreflightAndManifestParity|TestReleaseWorkflowProducesPinnedProvenance|TestReleaseWorkflowPublishesOnlySelectedTagIdentity|TestReleaseV2ReadinessIsExecutable)$ -count=1`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 31. `markdown-contracts`

- requirement: `required`
- description: Run the pinned Markdown style, table, and link-fragment contract across every public and maintainer document.
- action: command `npx --yes markdownlint-cli2@0.18.1 README.md README.en.md RELEASE_NOTES.md docs/**/*.md skills/**/*.md`
- tool/file/capability prerequisites: `tool:npx@any`

### 32. `coverage-observation`

- requirement: `required`
- description: Emit observed package coverage without enforcing any percentage threshold.
- action: command `go test -cover -count=1 ./...`
- tool/file/capability prerequisites: `tool:go@1.25.13`, `capability:repository-modules@go-mod-download`

### 33. `v2-readiness-report`

- requirement: `required`
- description: Require the checked-in secret-free final readiness report to match the executable manifest and reviewed evidence map.
- action: builtin `v2-readiness-report`
- tool/file/capability prerequisites: `file:docs/plans/issue-31-release-readiness.md@tracked`

## six supported release targets

The target and asset names below come directly from `internal/releaseasset.SupportedTargets` and `releaseasset.Name`; no additional target is implied.

| target | asset name | adjacent provenance bundle |
| --- | --- | --- |
| `linux/amd64` | `ssm-linux-amd64` | `ssm-linux-amd64.sigstore.json` |
| `linux/arm64` | `ssm-linux-arm64` | `ssm-linux-arm64.sigstore.json` |
| `darwin/amd64` | `ssm-darwin-amd64` | `ssm-darwin-amd64.sigstore.json` |
| `darwin/arm64` | `ssm-darwin-arm64` | `ssm-darwin-arm64.sigstore.json` |
| `windows/amd64` | `ssm-windows-amd64.exe` | `ssm-windows-amd64.exe.sigstore.json` |
| `windows/arm64` | `ssm-windows-arm64.exe` | `ssm-windows-arm64.exe.sigstore.json` |

The complete release name set also contains `install.sh` and `checksums.txt`, for 14 exact names including the six adjacent provenance bundles.

## BC-1 through BC-10 evidence map

Each row records the final-candidate result and points to the concrete highest-seam test source and test name that produced it.

| break | result | behavior covered | highest-seam source and test name |
| --- | --- | --- | --- |
| `BC-1` | `passed` | Present invalid cloud configuration is a fatal online sync error; explicit offline reads the cached snapshot. | cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix, TestCompiledSyncStateMatrix |
| `BC-2` | `passed` | Cross-alias saved-key dependencies are rejected before publication and retain a reviewable transaction scope. | cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix; cmd/ssm/inventory_transaction_compiled_test.go — TestScopedPublicationSavedKeyDependencies, TestInventoryTransactionPolicy |
| `BC-3` | `passed` | Stream startup and refresh failures use compact terminal NDJSON with the exact input and network contract. | cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamContract, TestCompiledStreamStartupNetworkPolicy |
| `BC-4` | `passed` | Legacy mutation and import entry points create pending reviewable transactions and never auto-publish. | cmd/ssm/legacy_mutation_compiled_test.go — TestLegacyMutationsCreatePendingTransactions, TestImportCreatesOneAtomicBulkTransaction, TestMutationEntryPointsNeverAutoPublish; cmd/ssm/publication_intent_compiled_test.go — TestPublicationIntentCrashMatrix, TestPublicationReconcilesLostResponse, TestPublicationReconcilesFinalizeFailure |
| `BC-5` | `passed` | Bare and empty publication scopes fail closed; explicit scopes preserve the invocation-start transaction set. | cmd/ssm/push_scope_compiled_test.go — TestPushScopeArgumentsFailBeforePublicationSideEffects, TestPushOnlyEqualsPreservesExactScope, TestEmptyLedgerPushNeverPuts, TestPushAllUsesInvocationStartSnapshot, TestEveryPushPathUsesInventoryTransactions |
| `BC-6` | `passed` | Online stream refresh zero is rejected before network work; explicit offline uses one fixed cached snapshot. | cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamContract, TestCompiledStreamStartupNetworkPolicy, TestStreamOfflineUsesFixedSnapshot |
| `BC-7` | `passed` | Direct and request-v1 transfer outcomes share direction, kind, stage, and truthful file/directory guarantees. | cmd/ssm/transfer_outcome_test.go — TestCompiledTransferOutcomeMatrix, TestTransferDirectAndRequestParity, TestTransferGuaranteesAreTruthful |
| `BC-8` | `passed` | Automatic updates remain same-major; major migration requires explicit authorization and failed migration preserves the executable. | internal/update/migration_test.go — TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork, TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork; internal/update/update_test.go — TestSameMajorSelection, TestCrossMajorRequiresExplicitAuthorization, TestFailedMigrationPreservesExecutable |
| `BC-9` | `passed` | Checksums are insufficient: exact release selection and pinned provenance identity/digest failures preserve installed bytes and mode. | internal/update/update_test.go — TestProvenanceIdentityMatrix, TestProvenanceDigestBinding, TestTrustFailurePreservesExecutable, TestReleaseAssetSelectionIsStrict, TestInvalidSelectedReleaseDoesNotFallBackOrDownload; cmd/verify/main_test.go — TestReleaseProvenanceForEveryTarget; cmd/verify/release_unix_test.go — TestInstallerRejectsProvenanceReplayAndDowngrade, TestInstallerRequiresExactReleaseManifest, TestInstallerPinsProvenanceTrustPolicy |
| `BC-10` | `passed` | make check is the non-mutating verify ci adapter; release is a strict non-publishing superset with deterministic terminal status. | cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix (BC-10 subtest); cmd/verify/main_test.go — TestReleaseStrictlyContainsCI, TestProfilesAreNonMutating, TestVerificationChildrenHaveNoInheritedPublicationAuthority, TestReleaseV2ReadinessIsExecutable |

## Acceptance and public-seam map

The acceptance rows below connect each public seam to the manifest check(s) that run it and to the concrete fixture source/name.

### compiled CLI

- result: `passed`
- manifest check(s): `v2-public-contracts`: command `go test ./cmd/ssm -run ^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$ -count=1`
- evidence: cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix, TestApprovedV2BreakingChangeBaselines

### sync/offline

- result: `passed`
- manifest check(s): `v2-public-contracts`: command `go test ./cmd/ssm -run ^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$ -count=1`; `v2-policy-contracts`: command `go test ./internal/synctransaction ./internal/inventorytransaction -run ^(TestSyncTransactionPolicy|TestStreamTransactionPolicy|TestInventoryTransactionPolicy)$ -count=1`
- evidence: cmd/ssm/compiled_cli_contract_test.go — TestCompiledSyncStateMatrix; cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamStartupNetworkPolicy, TestStreamOfflineUsesFixedSnapshot

### publication/crash/recovery

- result: `passed`
- manifest check(s): `v2-public-contracts`: command `go test ./cmd/ssm -run ^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$ -count=1`
- evidence: cmd/ssm/publication_intent_compiled_test.go — TestPublicationIntentCrashMatrix, TestPublicationReconcilesLostResponse, TestPublicationReconcilesFinalizeFailure; cmd/ssm/push_scope_compiled_test.go — TestPushScopeArgumentsFailBeforePublicationSideEffects, TestEveryPushPathUsesInventoryTransactions

### stream

- result: `passed`
- manifest check(s): `v2-public-contracts`: command `go test ./cmd/ssm -run ^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$ -count=1`; `v2-policy-contracts`: command `go test ./internal/synctransaction ./internal/inventorytransaction -run ^(TestSyncTransactionPolicy|TestStreamTransactionPolicy|TestInventoryTransactionPolicy)$ -count=1`
- evidence: cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamContract, TestCompiledStreamStartupNetworkPolicy, TestStreamRefreshClosesPool, TestStreamOfflineUsesFixedSnapshot; internal/synctransaction/stream_test.go — TestStreamTransactionPolicy

### transfer

- result: `passed`
- manifest check(s): `v2-public-contracts`: command `go test ./cmd/ssm -run ^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$ -count=1`
- evidence: cmd/ssm/transfer_outcome_test.go — TestCompiledTransferOutcomeMatrix, TestTransferDirectAndRequestParity, TestTransferGuaranteesAreTruthful

### update/rollback

- result: `passed`
- manifest check(s): `v2-update-contracts`: command `go test ./internal/update -run ^(TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork|TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork|TestSameMajorSelection|TestCrossMajorRequiresExplicitAuthorization|TestFailedMigrationPreservesExecutable)$ -count=1`
- evidence: internal/update/migration_test.go — TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork, TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork; internal/update/update_test.go — TestSameMajorSelection, TestCrossMajorRequiresExplicitAuthorization, TestFailedMigrationPreservesExecutable

### provenance and trust negatives

- result: `passed`
- manifest check(s): `release-provenance`: builtin `release-provenance`; `provenance-failure-paths`: command `go test ./internal/update -run ^(TestProvenanceIdentityMatrix|TestProvenanceDigestBinding|TestTrustFailurePreservesExecutable)$ -count=1`; `checksum-failure-paths`: command `go test ./internal/update -run ^(TestChecksumForAsset|TestChecksumForAssetRequiresMatchingAsset|TestCopyAndVerifyRejectsChecksumMismatch|TestDownloadVersionVerifiesChecksumBeforeReplace)$ -count=1`; `v2-release-contracts`: command `go test ./cmd/verify -run ^(TestReleaseStrictlyContainsCI|TestProfilesAreNonMutating|TestVerificationChildrenHaveNoInheritedPublicationAuthority|TestSourceVersionMatchesReleaseWorkflowGrammar|TestReleaseProvenanceForEveryTarget|TestReleaseWorkflowUsesCredentialFreeVerifierPreflightAndManifestParity|TestReleaseWorkflowProducesPinnedProvenance|TestReleaseWorkflowPublishesOnlySelectedTagIdentity|TestReleaseV2ReadinessIsExecutable)$ -count=1`
- evidence: internal/update/update_test.go — TestProvenanceIdentityMatrix, TestProvenanceDigestBinding, TestTrustFailurePreservesExecutable, TestChecksumForAssetRequiresMatchingAsset, TestCopyAndVerifyRejectsChecksumMismatch, TestDownloadVersionVerifiesChecksumBeforeReplace; cmd/verify/main_test.go — TestReleaseProvenanceForEveryTarget, TestReleaseWorkflowProducesPinnedProvenance, TestReleaseWorkflowPublishesOnlySelectedTagIdentity

### contraction

- result: `passed`
- manifest check(s): `v2-structure-docs`: command `go test ./cmd/ssm -run ^(TestDeepPolicyOwnershipContraction|TestDeepPolicyOwnershipAnalyzerAdversarialFixtures|TestV2MigrationDocumentationContract|TestSSHCTLCommandHelpNeedsNoUnlockOrTTY|TestRunHelpDocumentsFastStream)$ -count=1`
- evidence: cmd/ssm/deep_policy_ownership_test.go — TestDeepPolicyOwnershipContraction, TestDeepPolicyOwnershipAnalyzerAdversarialFixtures

### docs/help/lint

- result: `passed`
- manifest check(s): `v2-structure-docs`: command `go test ./cmd/ssm -run ^(TestDeepPolicyOwnershipContraction|TestDeepPolicyOwnershipAnalyzerAdversarialFixtures|TestV2MigrationDocumentationContract|TestSSHCTLCommandHelpNeedsNoUnlockOrTTY|TestRunHelpDocumentsFastStream)$ -count=1`; `markdown-contracts`: command `npx --yes markdownlint-cli2@0.18.1 README.md README.en.md RELEASE_NOTES.md docs/**/*.md skills/**/*.md`; `lint`: command `golangci-lint run --new-from-patch {temp}/lint.patch`
- evidence: cmd/ssm/v2_migration_documentation_contract_test.go — TestV2MigrationDocumentationContract; cmd/ssm/help_test.go — TestSSHCTLCommandHelpNeedsNoUnlockOrTTY, TestRunHelpDocumentsFastStream; cmd/verify/manifest.go — lint check and reviewed lint-patch preparation

### observed coverage

- result: `passed`
- manifest check(s): `coverage-observation`: command `go test -cover -count=1 ./...`
- evidence: manifest action `go test -cover -count=1 ./...` emits package observations
- observation: Coverage is observed without a percentage threshold.

### clean-tree/no-publication authority

- result: `passed`
- manifest check(s): `v2-release-contracts`: command `go test ./cmd/verify -run ^(TestReleaseStrictlyContainsCI|TestProfilesAreNonMutating|TestVerificationChildrenHaveNoInheritedPublicationAuthority|TestSourceVersionMatchesReleaseWorkflowGrammar|TestReleaseProvenanceForEveryTarget|TestReleaseWorkflowUsesCredentialFreeVerifierPreflightAndManifestParity|TestReleaseWorkflowProducesPinnedProvenance|TestReleaseWorkflowPublishesOnlySelectedTagIdentity|TestReleaseV2ReadinessIsExecutable)$ -count=1`
- evidence: cmd/verify/main_test.go — TestProfilesAreNonMutating, TestVerificationChildrenHaveNoInheritedPublicationAuthority, TestProfileRejectsNonIgnoredUntrackedPathsBeforeExecution, TestProfileDetectsAllRefMutations
- observation: The profile prerequisite requires a fully populated regular tracked worktree with no non-ignored untracked paths.

## Exact local commands

These are the exact local entry points for Issue #31 review; the release action vectors immediately below are rendered from the manifest.

- `test -z "$(gofmt -l .)"`
- `go run ./cmd/verify list`
- `go run ./cmd/verify ci`
- `go run ./cmd/verify release`
- `go test ./... -run 'TestApprovedV2BreakingChangeBaselines|TestDeepPolicyOwnershipContraction|TestReleaseProvenanceForEveryTarget|TestV2MigrationDocumentationContract' -count=1`
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `scripts/ssh_matrix_test.sh`
- `git diff --check`
- `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -exec=true ./...`
- `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./...`
- `CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go test -exec=true ./...`
- `CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go vet ./...`

### Release command vectors

- `format`: `{goroot}/bin/gofmt{exe} -l . expect=stdout_empty`
- `lint`: `golangci-lint run --new-from-patch {temp}/lint.patch`
- `vet`: `go vet ./...`
- `vulnerability`: `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...`
- `build`: `go build -buildvcs=false -o {temp}/ssm{exe} ./cmd/ssm`
- `unit`: `go test ./...`
- `race`: `go test -race -timeout=15m ./...`
- `agent-prompts-json`: `jq empty skills/agent-ssm/test-prompts.json`
- `request-schema-json`: `jq empty skills/agent-ssm/references/request-v1.schema.json`
- `ssh-matrix-shell-syntax`: `bash -n scripts/ssh_matrix_test.sh`
- `ssh-matrix`: `bash scripts/ssh_matrix_test.sh`
- `asset-linux-amd64`: `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-linux-amd64 ./cmd/ssm env=GOOS=linux,GOARCH=amd64`
- `asset-linux-arm64`: `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-linux-arm64 ./cmd/ssm env=GOOS=linux,GOARCH=arm64`
- `asset-darwin-amd64`: `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-darwin-amd64 ./cmd/ssm env=GOOS=darwin,GOARCH=amd64`
- `asset-darwin-arm64`: `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-darwin-arm64 ./cmd/ssm env=GOOS=darwin,GOARCH=arm64`
- `asset-windows-amd64`: `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-windows-amd64.exe ./cmd/ssm env=GOOS=windows,GOARCH=amd64`
- `asset-windows-arm64`: `go build -buildvcs=false "-ldflags=-s -w -X main.version={version}" -o {temp}/ssm-windows-arm64.exe ./cmd/ssm env=GOOS=windows,GOARCH=arm64`
- `updater-selection`: `go test ./internal/update -run ^(TestAssetNameForSupportedPlatforms|TestReleaseAssetSelectionIsStrict|TestInvalidSelectedReleaseDoesNotFallBackOrDownload)$ -count=1`
- `install-shell-syntax`: `sh -n install.sh`
- `provenance-failure-paths`: `go test ./internal/update -run ^(TestProvenanceIdentityMatrix|TestProvenanceDigestBinding|TestTrustFailurePreservesExecutable)$ -count=1`
- `checksum-failure-paths`: `go test ./internal/update -run ^(TestChecksumForAsset|TestChecksumForAssetRequiresMatchingAsset|TestCopyAndVerifyRejectsChecksumMismatch|TestDownloadVersionVerifiesChecksumBeforeReplace)$ -count=1`
- `v2-public-contracts`: `go test ./cmd/ssm -run ^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$ -count=1`
- `v2-policy-contracts`: `go test ./internal/synctransaction ./internal/inventorytransaction -run ^(TestSyncTransactionPolicy|TestStreamTransactionPolicy|TestInventoryTransactionPolicy)$ -count=1`
- `v2-update-contracts`: `go test ./internal/update -run ^(TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork|TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork|TestSameMajorSelection|TestCrossMajorRequiresExplicitAuthorization|TestFailedMigrationPreservesExecutable)$ -count=1`
- `v2-structure-docs`: `go test ./cmd/ssm -run ^(TestDeepPolicyOwnershipContraction|TestDeepPolicyOwnershipAnalyzerAdversarialFixtures|TestV2MigrationDocumentationContract|TestSSHCTLCommandHelpNeedsNoUnlockOrTTY|TestRunHelpDocumentsFastStream)$ -count=1`
- `v2-release-contracts`: `go test ./cmd/verify -run ^(TestReleaseStrictlyContainsCI|TestProfilesAreNonMutating|TestVerificationChildrenHaveNoInheritedPublicationAuthority|TestSourceVersionMatchesReleaseWorkflowGrammar|TestReleaseProvenanceForEveryTarget|TestReleaseWorkflowUsesCredentialFreeVerifierPreflightAndManifestParity|TestReleaseWorkflowProducesPinnedProvenance|TestReleaseWorkflowPublishesOnlySelectedTagIdentity|TestReleaseV2ReadinessIsExecutable)$ -count=1`
- `markdown-contracts`: `npx --yes markdownlint-cli2@0.18.1 README.md README.en.md RELEASE_NOTES.md docs/**/*.md skills/**/*.md`
- `coverage-observation`: `go test -cover -count=1 ./...`

## Verification boundaries and evidence semantics

- coverage is observed without a percentage threshold; `coverage-observation` emits package observations and does not enforce a numeric gate.
- Clean-tree enforcement is a prerequisite, and verifier actions run in temporary storage with no inherited publication authority.
- This report records final-candidate pass/fail outcomes; attached PR/CI evidence binds those reruns to the exact pushed HEAD and remains authoritative for native jobs.
- Verification performs no merge, tag, release, upload, publication, or real installation.
