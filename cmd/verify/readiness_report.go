package main

import (
	"bytes"
	"fmt"
	"strings"

	"ssm/internal/releaseasset"
)

const v2ReadinessReportPath = "docs/plans/issue-31-release-readiness.md"

// validateV2ReadinessReport verifies the checked-in report against the current
// executable verification manifest. The report is read through the same
// no-follow regular-file primitive used for all tracked verifier inputs.
func validateV2ReadinessReport(repoRoot string) error {
	expected := renderV2ReadinessReport(verificationManifest())
	actual, err := readRegularFileNoFollow(repoRoot, v2ReadinessReportPath)
	if err != nil {
		return fmt.Errorf("read checked-in v2 readiness report: %w", err)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("checked-in v2 readiness report has byte drift from the manifest-derived report")
	}
	return nil
}

type v2ReadinessEvidence struct {
	ID      string
	Summary string
	Sources []string
}

var v2BreakingChangeEvidence = []v2ReadinessEvidence{
	{
		ID:      "BC-1",
		Summary: "Present invalid cloud configuration is a fatal online sync error; explicit offline reads the cached snapshot.",
		Sources: []string{
			"cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix, TestCompiledSyncStateMatrix",
		},
	},
	{
		ID:      "BC-2",
		Summary: "Cross-alias saved-key dependencies are rejected before publication and retain a reviewable transaction scope.",
		Sources: []string{
			"cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix",
			"cmd/ssm/inventory_transaction_compiled_test.go — TestScopedPublicationSavedKeyDependencies, TestInventoryTransactionPolicy",
		},
	},
	{
		ID:      "BC-3",
		Summary: "Stream startup and refresh failures use compact terminal NDJSON with the exact input and network contract.",
		Sources: []string{
			"cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamContract, TestCompiledStreamStartupNetworkPolicy",
		},
	},
	{
		ID:      "BC-4",
		Summary: "Legacy mutation and import entry points create pending reviewable transactions and never auto-publish.",
		Sources: []string{
			"cmd/ssm/legacy_mutation_compiled_test.go — TestLegacyMutationsCreatePendingTransactions, TestImportCreatesOneAtomicBulkTransaction, TestMutationEntryPointsNeverAutoPublish",
			"cmd/ssm/publication_intent_compiled_test.go — TestPublicationIntentCrashMatrix, TestPublicationReconcilesLostResponse, TestPublicationReconcilesFinalizeFailure",
		},
	},
	{
		ID:      "BC-5",
		Summary: "Bare and empty publication scopes fail closed; explicit scopes preserve the invocation-start transaction set.",
		Sources: []string{
			"cmd/ssm/push_scope_compiled_test.go — TestPushScopeArgumentsFailBeforePublicationSideEffects, TestPushOnlyEqualsPreservesExactScope, TestEmptyLedgerPushNeverPuts, TestPushAllUsesInvocationStartSnapshot, TestEveryPushPathUsesInventoryTransactions",
		},
	},
	{
		ID:      "BC-6",
		Summary: "Online stream refresh zero is rejected before network work; explicit offline uses one fixed cached snapshot.",
		Sources: []string{
			"cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamContract, TestCompiledStreamStartupNetworkPolicy, TestStreamOfflineUsesFixedSnapshot",
		},
	},
	{
		ID:      "BC-7",
		Summary: "Direct and request-v1 transfer outcomes share direction, kind, stage, and truthful file/directory guarantees.",
		Sources: []string{
			"cmd/ssm/transfer_outcome_test.go — TestCompiledTransferOutcomeMatrix, TestTransferDirectAndRequestParity, TestTransferGuaranteesAreTruthful",
		},
	},
	{
		ID:      "BC-8",
		Summary: "Automatic updates remain same-major; major migration requires explicit authorization and failed migration preserves the executable.",
		Sources: []string{
			"internal/update/migration_test.go — TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork, TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork",
			"internal/update/update_test.go — TestSameMajorSelection, TestCrossMajorRequiresExplicitAuthorization, TestFailedMigrationPreservesExecutable",
		},
	},
	{
		ID:      "BC-9",
		Summary: "Checksums are insufficient: exact release selection and pinned provenance identity/digest failures preserve installed bytes and mode.",
		Sources: []string{
			"internal/update/update_test.go — TestProvenanceIdentityMatrix, TestProvenanceDigestBinding, TestTrustFailurePreservesExecutable, TestReleaseAssetSelectionIsStrict, TestInvalidSelectedReleaseDoesNotFallBackOrDownload",
			"cmd/verify/main_test.go — TestReleaseProvenanceForEveryTarget",
			"cmd/verify/release_unix_test.go — TestInstallerRejectsProvenanceReplayAndDowngrade, TestInstallerRequiresExactReleaseManifest, TestInstallerPinsProvenanceTrustPolicy",
		},
	},
	{
		ID:      "BC-10",
		Summary: "make check is the non-mutating verify ci adapter; release is a strict non-publishing superset with deterministic terminal status.",
		Sources: []string{
			"cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix (BC-10 subtest)",
			"cmd/verify/main_test.go — TestReleaseStrictlyContainsCI, TestProfilesAreNonMutating, TestVerificationChildrenHaveNoInheritedPublicationAuthority, TestReleaseV2ReadinessIsExecutable",
		},
	},
}

type v2ReadinessAcceptance struct {
	Area        string
	Checks      []string
	Evidence    []string
	Observation string
}

var v2ReadinessAcceptanceMap = []v2ReadinessAcceptance{
	{
		Area:   "compiled CLI",
		Checks: []string{"v2-public-contracts"},
		Evidence: []string{
			"cmd/ssm/compiled_cli_contract_test.go — TestCompiledCLIContractMatrix, TestApprovedV2BreakingChangeBaselines",
		},
	},
	{
		Area:   "sync/offline",
		Checks: []string{"v2-public-contracts", "v2-policy-contracts"},
		Evidence: []string{
			"cmd/ssm/compiled_cli_contract_test.go — TestCompiledSyncStateMatrix",
			"cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamStartupNetworkPolicy, TestStreamOfflineUsesFixedSnapshot",
		},
	},
	{
		Area:   "publication/crash/recovery",
		Checks: []string{"v2-public-contracts"},
		Evidence: []string{
			"cmd/ssm/publication_intent_compiled_test.go — TestPublicationIntentCrashMatrix, TestPublicationReconcilesLostResponse, TestPublicationReconcilesFinalizeFailure",
			"cmd/ssm/push_scope_compiled_test.go — TestPushScopeArgumentsFailBeforePublicationSideEffects, TestEveryPushPathUsesInventoryTransactions",
		},
	},
	{
		Area:   "stream",
		Checks: []string{"v2-public-contracts", "v2-policy-contracts"},
		Evidence: []string{
			"cmd/ssm/compiled_stream_contract_test.go — TestCompiledStreamContract, TestCompiledStreamStartupNetworkPolicy, TestStreamRefreshClosesPool, TestStreamOfflineUsesFixedSnapshot",
			"internal/synctransaction/stream_test.go — TestStreamTransactionPolicy",
		},
	},
	{
		Area:   "transfer",
		Checks: []string{"v2-public-contracts"},
		Evidence: []string{
			"cmd/ssm/transfer_outcome_test.go — TestCompiledTransferOutcomeMatrix, TestTransferDirectAndRequestParity, TestTransferGuaranteesAreTruthful",
		},
	},
	{
		Area:   "update/rollback",
		Checks: []string{"v2-update-contracts"},
		Evidence: []string{
			"internal/update/migration_test.go — TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork, TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork",
			"internal/update/update_test.go — TestSameMajorSelection, TestCrossMajorRequiresExplicitAuthorization, TestFailedMigrationPreservesExecutable",
		},
	},
	{
		Area:   "provenance and trust negatives",
		Checks: []string{"release-provenance", "provenance-failure-paths", "checksum-failure-paths", "v2-release-contracts"},
		Evidence: []string{
			"internal/update/update_test.go — TestProvenanceIdentityMatrix, TestProvenanceDigestBinding, TestTrustFailurePreservesExecutable, TestChecksumForAssetRequiresMatchingAsset, TestCopyAndVerifyRejectsChecksumMismatch, TestDownloadVersionVerifiesChecksumBeforeReplace",
			"cmd/verify/main_test.go — TestReleaseProvenanceForEveryTarget, TestReleaseWorkflowProducesPinnedProvenance, TestReleaseWorkflowPublishesOnlySelectedTagIdentity",
		},
	},
	{
		Area:   "contraction",
		Checks: []string{"v2-structure-docs"},
		Evidence: []string{
			"cmd/ssm/deep_policy_ownership_test.go — TestDeepPolicyOwnershipContraction, TestDeepPolicyOwnershipAnalyzerAdversarialFixtures",
		},
	},
	{
		Area:   "docs/help/lint",
		Checks: []string{"v2-structure-docs", "markdown-contracts", "lint"},
		Evidence: []string{
			"cmd/ssm/v2_migration_documentation_contract_test.go — TestV2MigrationDocumentationContract",
			"cmd/ssm/help_test.go — TestSSHCTLCommandHelpNeedsNoUnlockOrTTY, TestRunHelpDocumentsFastStream",
			"cmd/verify/manifest.go — lint check and reviewed lint-patch preparation",
		},
	},
	{
		Area:   "observed coverage",
		Checks: []string{"coverage-observation"},
		Evidence: []string{
			"manifest action `go test -cover -count=1 ./...` emits package observations",
		},
		Observation: "Coverage is observed without a percentage threshold.",
	},
	{
		Area:   "clean-tree/no-publication authority",
		Checks: []string{"v2-release-contracts"},
		Evidence: []string{
			"cmd/verify/main_test.go — TestProfilesAreNonMutating, TestVerificationChildrenHaveNoInheritedPublicationAuthority, TestProfileRejectsNonIgnoredUntrackedPathsBeforeExecution, TestProfileDetectsAllRefMutations",
		},
		Observation: "The profile prerequisite requires a fully populated regular tracked worktree with no non-ignored untracked paths.",
	},
}

type v2ReadinessResult struct {
	Command string
	Status  string
}

var v2ReadinessFinalResults = []v2ReadinessResult{
	{Command: `test -z "$(gofmt -l .)"`, Status: statusPassed},
	{Command: "go run ./cmd/verify list", Status: statusPassed},
	{Command: "go run ./cmd/verify ci", Status: statusPassed},
	{Command: "go run ./cmd/verify release", Status: statusPreflightPassed},
	{Command: "go test ./... -run 'TestApprovedV2BreakingChangeBaselines|TestDeepPolicyOwnershipContraction|TestReleaseProvenanceForEveryTarget|TestV2MigrationDocumentationContract' -count=1", Status: statusPassed},
	{Command: "go test ./...", Status: statusPassed},
	{Command: "go test -race ./...", Status: statusPassed},
	{Command: "go vet ./...", Status: statusPassed},
	{Command: "scripts/ssh_matrix_test.sh", Status: statusPassed},
	{Command: "git diff --check", Status: statusPassed},
	{Command: "CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -exec=true ./...", Status: statusPassed},
	{Command: "CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./...", Status: statusPassed},
	{Command: "CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go test -exec=true ./...", Status: statusPassed},
	{Command: "CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go vet ./...", Status: statusPassed},
}

type v2ReadinessToolVersion struct {
	Tool    string
	Version string
}

var v2ReadinessObservedToolVersions = []v2ReadinessToolVersion{
	{Tool: "Go", Version: "1.25.13"},
	{Tool: "git", Version: "2.47.3"},
	{Tool: "jq", Version: "1.7"},
	{Tool: "golangci-lint", Version: "2.11.4"},
	{Tool: "Node.js", Version: "20.19.2"},
	{Tool: "npm/npx", Version: "9.2.0"},
	{Tool: "GNU Bash", Version: "5.2.37(1)-release"},
	{Tool: "OpenSSH", Version: "10.0p2 Debian-7+deb13u4"},
}

var v2ReadinessRehearsalOutcomes = []v2ReadinessEvidence{
	{
		ID:      "rollback rehearsal",
		Summary: "passed",
		Sources: []string{
			"internal/update/update_test.go — TestFailedMigrationPreservesExecutable",
			"cmd/ssm/publication_intent_compiled_test.go — TestPublicationIntentCrashMatrix, TestPublicationReconcilesLostResponse, TestPublicationReconcilesFinalizeFailure",
		},
	},
	{
		ID:      "trust-negative rehearsal",
		Summary: "passed",
		Sources: []string{
			"internal/update/update_test.go — TestProvenanceIdentityMatrix, TestProvenanceDigestBinding, TestTrustFailurePreservesExecutable, TestChecksumForAssetRequiresMatchingAsset, TestCopyAndVerifyRejectsChecksumMismatch",
		},
	},
	{
		ID:      "structural contraction",
		Summary: "passed",
		Sources: []string{
			"cmd/ssm/deep_policy_ownership_test.go — TestDeepPolicyOwnershipContraction, TestDeepPolicyOwnershipAnalyzerAdversarialFixtures",
		},
	},
	{
		ID:      "clean-tree/no-publication proof",
		Summary: "passed",
		Sources: []string{
			"cmd/verify/main_test.go — TestProfilesAreNonMutating, TestVerificationChildrenHaveNoInheritedPublicationAuthority, TestProfileDetectsAllRefMutations",
		},
	},
}

// renderV2ReadinessReport is intentionally a pure renderer. Keeping the
// manifest-derived portion here (rather than checking in a second manifest
// copy) makes profile drift observable through validateV2ReadinessReport.
func renderV2ReadinessReport(manifest Manifest) []byte {
	var report strings.Builder
	writeReadiness(&report, "# Issue #31 — SSM v2 final release readiness\n\n")
	writeReadiness(&report, "This checked-in report is **manifest-derived** and **secret-free**. It is rendered from `verificationManifest()` plus the reviewed final-candidate evidence record; it contains no credentials, private keys, or decrypted vault contents.\n\n")
	writeReadiness(&report, "The report is a deterministic review artifact, not a release authority. It records the outcome labels and public tool versions observed for the final candidate; Exact-HEAD binding is supplied by the attached PR and native CI evidence and must match the current pushed commit before merge.\n\n")
	writeReadiness(&report, "Verification performs no merge, tag, release, upload, publication, or real installation. It only evaluates the checked-in source, tests, documentation, and temporary verifier-owned outputs.\n\n")

	writeReadiness(&report, "## Recorded final candidate results\n\n")
	writeReadiness(&report, "These secret-free outcomes record the complete Issue #31 command set. Any source, test, manifest, or report change invalidates the record until every command is rerun; the PR evidence supplies the exact commit identity for the rerun.\n\n")
	writeReadiness(&report, "| exact command | result |\n| --- | --- |\n")
	for _, result := range v2ReadinessFinalResults {
		writeReadiness(&report, "| `%s` | `%s` |\n", readinessCell(result.Command), result.Status)
	}
	writeReadiness(&report, "\n")

	writeReadiness(&report, "## Observed final-gate tool versions\n\n")
	writeReadiness(&report, "The versions below were observed in the Linux final-gate environment. The manifest sections retain the executable per-check prerequisite contracts; native Windows and Darwin outcomes are attached as exact-HEAD CI evidence.\n\n")
	writeReadiness(&report, "| tool | observed version |\n| --- | --- |\n")
	for _, tool := range v2ReadinessObservedToolVersions {
		writeReadiness(&report, "| %s | `%s` |\n", readinessCell(tool.Tool), readinessCell(tool.Version))
	}
	writeReadiness(&report, "\n")

	writeReadiness(&report, "## Explicit rehearsal outcomes\n\n")
	writeReadiness(&report, "These outcomes are exercised directly by the release profile rather than inferred from a summary.\n\n")
	writeReadiness(&report, "| required outcome | result | direct fixture evidence |\n| --- | --- | --- |\n")
	for _, outcome := range v2ReadinessRehearsalOutcomes {
		writeReadiness(&report, "| %s | `%s` | %s |\n", readinessCell(outcome.ID), outcome.Summary, readinessCell(strings.Join(outcome.Sources, "; ")))
	}
	writeReadiness(&report, "\n")

	writeReadiness(&report, "## Manifest profile membership, equivalence, and check counts\n\n")
	writeReadiness(&report, "Manifest schema version: `%d`. Profile order and membership below are the executable order.\n\n", manifest.SchemaVersion)
	writeReadiness(&report, "| profile | equivalence | check count | purpose |\n| --- | --- | ---: | --- |\n")
	for _, profile := range manifest.Profiles {
		writeReadiness(
			&report,
			"| `%s` | `%s` | %d | %s |\n",
			readinessCell(profile.Name),
			readinessCell(profile.Equivalence),
			len(profile.Checks),
			readinessCell(profile.Purpose),
		)
	}
	writeReadiness(&report, "\n")
	for _, profile := range manifest.Profiles {
		writeReadiness(&report, "### `%s` membership\n\n", profile.Name)
		writeReadiness(&report, "- equivalence: `%s`\n- check count: `%d`\n", profile.Equivalence, len(profile.Checks))
		writeReadiness(&report, "- profile prerequisites: %s\n", readinessPrerequisites(profile.Prerequisites))
		if len(profile.Checks) == 0 {
			writeReadiness(&report, "- checks: none\n\n")
			continue
		}
		writeReadiness(&report, "- checks in order: %s\n\n", readinessCheckIDs(profile.Checks))
	}

	release, releaseFound := findProfile(manifest, "release")
	writeReadiness(&report, "## Release profile exact checks, actions, and tool prerequisites\n\n")
	if !releaseFound {
		writeReadiness(&report, "The manifest has no `release` profile.\n\n")
	} else {
		writeReadiness(&report, "The `release` profile has equivalence `%s` and `%d` checks. Every listed check is rendered from its manifest record; action vectors are not inferred from prose.\n\n", release.Equivalence, len(release.Checks))
		writeReadiness(&report, "Release profile prerequisites: %s\n\n", readinessPrerequisites(release.Prerequisites))
		for index, check := range release.Checks {
			writeReadiness(&report, "### %02d. `%s`\n\n", index+1, check.ID)
			writeReadiness(&report, "- requirement: `%s`\n- description: %s\n", check.Requirement, check.Description)
			if check.Activation != "" {
				writeReadiness(&report, "- activation: `%s`\n", check.Activation)
			}
			if len(check.RequiredContexts) != 0 {
				writeReadiness(&report, "- required contexts: `%s`\n", strings.Join(check.RequiredContexts, "`, `"))
			}
			writeReadiness(&report, "- action: %s\n", readinessAction(check.Action))
			writeReadiness(&report, "- tool/file/capability prerequisites: %s\n", readinessPrerequisites(check.Prerequisites))
			for _, preparation := range check.Preparations {
				writeReadiness(&report, "- preparation `%s`: %s; working directory `%s`; output `%s`; action %s\n", preparation.ID, preparation.Description, preparation.WorkingDirectory, preparation.Output, readinessAction(preparation.Action))
			}
			writeReadiness(&report, "\n")
		}
	}

	writeReadiness(&report, "## six supported release targets\n\n")
	writeReadiness(&report, "The target and asset names below come directly from `internal/releaseasset.SupportedTargets` and `releaseasset.Name`; no additional target is implied.\n\n")
	writeReadiness(&report, "| target | asset name | adjacent provenance bundle |\n| --- | --- | --- |\n")
	for _, target := range releaseasset.SupportedTargets() {
		asset := releaseasset.Name(target.GOOS, target.GOARCH)
		writeReadiness(&report, "| `%s/%s` | `%s` | `%s` |\n", target.GOOS, target.GOARCH, asset, releaseasset.ProvenanceName(asset))
	}
	writeReadiness(&report, "\nThe complete release name set also contains `install.sh` and `checksums.txt`, for 14 exact names including the six adjacent provenance bundles.\n\n")

	writeReadiness(&report, "## BC-1 through BC-10 evidence map\n\n")
	writeReadiness(&report, "Each row records the final-candidate result and points to the concrete highest-seam test source and test name that produced it.\n\n")
	writeReadiness(&report, "| break | result | behavior covered | highest-seam source and test name |\n| --- | --- | --- | --- |\n")
	for _, evidence := range v2BreakingChangeEvidence {
		writeReadiness(&report, "| `%s` | `%s` | %s | %s |\n", evidence.ID, statusPassed, readinessCell(evidence.Summary), readinessCell(strings.Join(evidence.Sources, "; ")))
	}
	writeReadiness(&report, "\n")

	writeReadiness(&report, "## Acceptance and public-seam map\n\n")
	writeReadiness(&report, "The acceptance rows below connect each public seam to the manifest check(s) that run it and to the concrete fixture source/name.\n\n")
	for _, acceptance := range v2ReadinessAcceptanceMap {
		writeReadiness(&report, "### %s\n\n", acceptance.Area)
		writeReadiness(&report, "- result: `%s`\n", statusPassed)
		writeReadiness(&report, "- manifest check(s): %s\n", readinessCheckReferences(manifest, acceptance.Checks))
		writeReadiness(&report, "- evidence: %s\n", strings.Join(acceptance.Evidence, "; "))
		if acceptance.Observation != "" {
			writeReadiness(&report, "- observation: %s\n", acceptance.Observation)
		}
		writeReadiness(&report, "\n")
	}

	writeReadiness(&report, "## Exact local commands\n\n")
	writeReadiness(&report, "These are the exact local entry points for Issue #31 review; the release action vectors immediately below are rendered from the manifest.\n\n")
	for _, command := range []string{
		`test -z "$(gofmt -l .)"`,
		"go run ./cmd/verify list",
		"go run ./cmd/verify ci",
		"go run ./cmd/verify release",
		"go test ./... -run 'TestApprovedV2BreakingChangeBaselines|TestDeepPolicyOwnershipContraction|TestReleaseProvenanceForEveryTarget|TestV2MigrationDocumentationContract' -count=1",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/ssh_matrix_test.sh",
		"git diff --check",
		"CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -exec=true ./...",
		"CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./...",
		"CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go test -exec=true ./...",
		"CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go vet ./...",
	} {
		writeReadiness(&report, "- `%s`\n", command)
	}
	writeReadiness(&report, "\n### Release command vectors\n\n")
	if releaseFound {
		for _, check := range release.Checks {
			if check.Action.Kind != actionCommand || check.Action.Command == nil {
				continue
			}
			writeReadiness(&report, "- `%s`: `%s`\n", check.ID, readinessCommand(*check.Action.Command))
		}
	}
	writeReadiness(&report, "\n")

	writeReadiness(&report, "## Verification boundaries and evidence semantics\n\n")
	writeReadiness(&report, "- coverage is observed without a percentage threshold; `coverage-observation` emits package observations and does not enforce a numeric gate.\n")
	writeReadiness(&report, "- Clean-tree enforcement is a prerequisite, and verifier actions run in temporary storage with no inherited publication authority.\n")
	writeReadiness(&report, "- This report records final-candidate pass/fail outcomes; attached PR/CI evidence binds those reruns to the exact pushed HEAD and remains authoritative for native jobs.\n")
	writeReadiness(&report, "- Verification performs no merge, tag, release, upload, publication, or real installation.\n")
	writeReadiness(&report, "\n")
	return []byte(strings.TrimSuffix(report.String(), "\n"))
}

func writeReadiness(builder *strings.Builder, format string, args ...any) {
	_, _ = fmt.Fprintf(builder, format, args...)
}

func readinessCell(value string) string {
	return strings.NewReplacer("\\", "\\\\", "|", "\\|", "\n", " ").Replace(value)
}

func readinessCheckIDs(checks []Check) string {
	ids := make([]string, 0, len(checks))
	for _, check := range checks {
		ids = append(ids, "`"+check.ID+"`")
	}
	return strings.Join(ids, ", ")
}

func readinessPrerequisites(prerequisites []Prerequisite) string {
	if len(prerequisites) == 0 {
		return "none"
	}
	values := make([]string, 0, len(prerequisites))
	for _, prerequisite := range prerequisites {
		values = append(values, "`"+readinessPrerequisite(prerequisite)+"`")
	}
	return strings.Join(values, ", ")
}

func readinessPrerequisite(prerequisite Prerequisite) string {
	value := prerequisite.Kind + ":" + prerequisite.Name + "@" + prerequisite.Version
	if len(prerequisite.Alternatives) == 0 {
		return value
	}
	alternatives := make([]string, 0, len(prerequisite.Alternatives))
	for _, alternative := range prerequisite.Alternatives {
		alternatives = append(alternatives, readinessPrerequisite(alternative))
	}
	return value + " [alternatives: " + strings.Join(alternatives, ", ") + "]"
}

func readinessAction(action Action) string {
	switch action.Kind {
	case actionBuiltin:
		return "builtin `" + action.Name + "`"
	case actionCommand:
		if action.Command == nil {
			return "command `<missing command>`"
		}
		return "command `" + readinessCommand(*action.Command) + "`"
	default:
		return "`" + action.Kind + "`"
	}
}

func readinessCommand(command Command) string {
	parts := make([]string, 0, 1+len(command.Args))
	parts = append(parts, command.Executable)
	for _, arg := range command.Args {
		parts = append(parts, readinessCommandToken(arg))
	}
	value := strings.Join(parts, " ")
	if len(command.Env) != 0 {
		value += " env=" + strings.Join(command.Env, ",")
	}
	if command.Expect != "" {
		value += " expect=" + command.Expect
	}
	return value
}

func readinessCommandToken(value string) string {
	if strings.ContainsAny(value, " \t\n\r") {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return value
}

func readinessCheckReferences(manifest Manifest, ids []string) string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		check, found := readinessFindCheck(manifest, id)
		if !found {
			values = append(values, "`"+id+"` (missing from manifest)")
			continue
		}
		values = append(values, "`"+check.ID+"`: "+readinessAction(check.Action))
	}
	return strings.Join(values, "; ")
}

func readinessFindCheck(manifest Manifest, id string) (Check, bool) {
	for _, profile := range manifest.Profiles {
		for _, check := range profile.Checks {
			if check.ID == id {
				return check, true
			}
		}
	}
	return Check{}, false
}
