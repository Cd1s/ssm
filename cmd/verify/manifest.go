package main

import (
	"encoding/json"

	"ssm/internal/releaseasset"
)

const (
	actionCommand = "command"
	actionBuiltin = "builtin"

	requirementRequired    = "required"
	requirementConditional = "conditional"
)

type Manifest struct {
	SchemaVersion int       `json:"schema_version"`
	Profiles      []Profile `json:"profiles"`
}

type Profile struct {
	Name          string         `json:"name"`
	Purpose       string         `json:"purpose"`
	Equivalence   string         `json:"equivalence"`
	Prerequisites []Prerequisite `json:"prerequisites"`
	Checks        []Check        `json:"checks"`
	Extensions    []Extension    `json:"extensions,omitempty"`
}

type Extension struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	RequiredBefore string `json:"required_before"`
}

type Check struct {
	ID               string         `json:"id"`
	Description      string         `json:"description"`
	Requirement      string         `json:"requirement"`
	Activation       string         `json:"activation,omitempty"`
	RequiredContexts []string       `json:"required_contexts,omitempty"`
	Preparations     []Preparation  `json:"preparations,omitempty"`
	Action           Action         `json:"action"`
	Prerequisites    []Prerequisite `json:"prerequisites"`
}

type Preparation struct {
	ID               string `json:"id"`
	Description      string `json:"description"`
	WorkingDirectory string `json:"working_directory"`
	Output           string `json:"output"`
	Action           Action `json:"action"`
}

type Action struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name,omitempty"`
	Command *Command `json:"command,omitempty"`
}

type Command struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	Env        []string `json:"env,omitempty"`
	Expect     string   `json:"expect,omitempty"`
}

type Prerequisite struct {
	Kind         string         `json:"kind"`
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Alternatives []Prerequisite `json:"alternatives,omitempty"`
}

func verificationManifest() Manifest {
	ci := ciChecks()
	release := append(append([]Check(nil), ci...), releaseChecks()...)
	return Manifest{
		SchemaVersion: 1,
		Profiles: []Profile{
			{
				Name:          "list",
				Purpose:       "Print this deterministic machine-reviewable manifest.",
				Equivalence:   "manifest_only",
				Prerequisites: []Prerequisite{},
				Checks:        []Check{},
			},
			{
				Name:          "fast",
				Purpose:       "Convenience-only developer feedback; not merge- or release-equivalent.",
				Equivalence:   "convenience_only",
				Prerequisites: profilePrerequisites(),
				Checks: []Check{
					formatCheck(),
					vetCheck(),
					unitCheck(),
				},
			},
			{
				Name:          "ci",
				Purpose:       "The complete non-publishing merge verification profile used by Make and GitHub CI.",
				Equivalence:   "merge",
				Prerequisites: profilePrerequisites(),
				Checks:        ci,
			},
			{
				Name:          "release",
				Purpose:       "Non-publishing final SSM v2 release readiness with direct public-contract, migration, coverage, and pinned-provenance verification.",
				Equivalence:   "initial_v2_release_readiness",
				Prerequisites: profilePrerequisites(),
				Checks:        release,
			},
		},
	}
}

func profilePrerequisites() []Prerequisite {
	return []Prerequisite{
		{Kind: "tool", Name: "git", Version: "any"},
		{
			Kind:    "repository",
			Name:    "fully-populated-regular-tracked-worktree",
			Version: "stage-0-modes-100644-or-100755-no-sparse",
		},
		{
			Kind:    "repository",
			Name:    "safe-local-git-configuration",
			Version: "no-includes-or-executable-command-authority",
		},
		{
			Kind:    "repository",
			Name:    "no-nonignored-untracked-paths",
			Version: "git-ls-files-others-exclude-standard-z",
		},
	}
}

func ciChecks() []Check {
	return []Check{
		formatCheck(),
		lintCheck(),
		vetCheck(),
		vulnerabilityCheck(),
		buildCheck(),
		unitCheck(),
		raceCheck(),
		agentPromptsJSONCheck(),
		requestSchemaJSONCheck(),
		sshMatrixShellSyntaxCheck(),
		sshMatrixCheck(),
	}
}

func releaseChecks() []Check {
	checks := []Check{
		{
			ID:          "source-version",
			Description: "Validate the source version as a release version.",
			Requirement: requirementRequired,
			Action:      Action{Kind: actionBuiltin, Name: "source-version"},
			Prerequisites: []Prerequisite{
				{Kind: "file", Name: "cmd/ssm/main.go", Version: "tracked"},
			},
		},
	}
	for _, target := range releaseasset.SupportedTargets() {
		checks = append(checks, assetCheck(target.GOOS, target.GOARCH))
	}
	checks = append(checks,
		Check{
			ID:          "updater-selection",
			Description: "Prove updater selection matches all six release asset names and rejects incomplete or unsupported release manifests without fallback.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./internal/update", "-run",
				"^(TestAssetNameForSupportedPlatforms|TestReleaseAssetSelectionIsStrict|TestInvalidSelectedReleaseDoesNotFallBackOrDownload)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "release-notes",
			Description: "Require non-empty release notes for the source version.",
			Requirement: requirementRequired,
			Action:      Action{Kind: actionBuiltin, Name: "release-notes"},
			Prerequisites: []Prerequisite{
				{Kind: "file", Name: "RELEASE_NOTES.md", Version: "tracked"},
			},
		},
		Check{
			ID:          "install-shell-syntax",
			Description: "Parse the published installer without executing it.",
			Requirement: requirementRequired,
			Action: commandAction("sh", []string{
				"-n", "install.sh",
			}, nil, ""),
			Prerequisites: []Prerequisite{
				{Kind: "tool", Name: "sh", Version: "any"},
				{Kind: "file", Name: "install.sh", Version: "tracked"},
			},
		},
		Check{
			ID:          "release-checksums",
			Description: "Compute SHA-256 digests for all six assets and install.sh without writing release output.",
			Requirement: requirementRequired,
			Action:      Action{Kind: actionBuiltin, Name: "release-checksums"},
			Prerequisites: []Prerequisite{
				{Kind: "file", Name: "install.sh", Version: "tracked"},
			},
		},
		Check{
			ID:            "release-provenance",
			Description:   "Generate and verify test-owned keyless provenance for all six release assets without publication.",
			Requirement:   requirementRequired,
			Action:        Action{Kind: actionBuiltin, Name: "release-provenance"},
			Prerequisites: []Prerequisite{},
		},
		Check{
			ID:          "provenance-failure-paths",
			Description: "Exercise pinned certificate/statement identity, exact digest binding, and byte-preserving trust failures through the updater verifier.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./internal/update", "-run",
				"^(TestProvenanceIdentityMatrix|TestProvenanceDigestBinding|TestTrustFailurePreservesExecutable)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "checksum-failure-paths",
			Description: "Exercise checksum selection, mismatch, and no-replacement failure paths.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./internal/update", "-run",
				"^(TestChecksumForAsset|TestChecksumForAssetRequiresMatchingAsset|TestCopyAndVerifyRejectsChecksumMismatch|TestDownloadVersionVerifiesChecksumBeforeReplace)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "v2-public-contracts",
			Description: "Run the compiled SSM v2 public, sync, publication, stream, push, and transfer contract fixtures directly.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./cmd/ssm", "-run",
				"^(TestCompiledCLIContractMatrix|TestApprovedV2BreakingChangeBaselines|TestCompiledSyncStateMatrix|TestCompiledStreamContract|TestCompiledStreamStartupNetworkPolicy|TestStreamRefreshClosesPool|TestStreamOfflineUsesFixedSnapshot|TestInventoryTransactionPolicy|TestScopedPublicationSavedKeyDependencies|TestLegacyMutationsCreatePendingTransactions|TestImportCreatesOneAtomicBulkTransaction|TestMutationEntryPointsNeverAutoPublish|TestPushScopeArgumentsFailBeforePublicationSideEffects|TestPushOnlyEqualsPreservesExactScope|TestEmptyLedgerPushNeverPuts|TestPushAllUsesInvocationStartSnapshot|TestEveryPushPathUsesInventoryTransactions|TestPublicationIntentCrashMatrix|TestPublicationReconcilesLostResponse|TestPublicationReconcilesFinalizeFailure|TestCompiledTransferOutcomeMatrix|TestTransferDirectAndRequestParity|TestTransferGuaranteesAreTruthful)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "v2-policy-contracts",
			Description: "Run the deep sync and inventory transaction policy fixtures directly.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./internal/synctransaction", "./internal/inventorytransaction", "-run",
				"^(TestSyncTransactionPolicy|TestStreamTransactionPolicy|TestInventoryTransactionPolicy)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "v2-update-contracts",
			Description: "Run explicit migration authorization, same-major selection, preflight, rollback, and executable-preservation fixtures directly.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./internal/update", "-run",
				"^(TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork|TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork|TestSameMajorSelection|TestCrossMajorRequiresExplicitAuthorization|TestFailedMigrationPreservesExecutable)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "v2-structure-docs",
			Description: "Run three-module contraction, adversarial ownership, bilingual migration documentation, and public help fixtures directly.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./cmd/ssm", "-run",
				"^(TestDeepPolicyOwnershipContraction|TestDeepPolicyOwnershipAnalyzerAdversarialFixtures|TestV2MigrationDocumentationContract|TestSSHCTLCommandHelpNeedsNoUnlockOrTTY|TestRunHelpDocumentsFastStream)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "v2-release-contracts",
			Description: "Run release superset, non-mutation, no-publication-authority, source grammar, workflow identity, and provenance workflow fixtures directly.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./cmd/verify", "-run",
				"^(TestReleaseStrictlyContainsCI|TestProfilesAreNonMutating|TestVerificationChildrenHaveNoInheritedPublicationAuthority|TestSourceVersionMatchesReleaseWorkflowGrammar|TestReleaseProvenanceForEveryTarget|TestReleaseWorkflowUsesCredentialFreeVerifierPreflightAndManifestParity|TestReleaseWorkflowProducesPinnedProvenance|TestReleaseWorkflowPublishesOnlySelectedTagIdentity|TestReleaseV2ReadinessIsExecutable)$",
				"-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "markdown-contracts",
			Description: "Run the pinned Markdown style, table, and link-fragment contract across every public and maintainer document.",
			Requirement: requirementRequired,
			Action: commandAction("npx", []string{
				"--yes", "markdownlint-cli2@0.18.1", "README.md", "README.en.md", "RELEASE_NOTES.md",
				"docs/**/*.md", "skills/**/*.md",
			}, nil, ""),
			Prerequisites: []Prerequisite{
				{Kind: "tool", Name: "npx", Version: "any"},
			},
		},
		Check{
			ID:          "coverage-observation",
			Description: "Emit observed package coverage without enforcing any percentage threshold.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "-cover", "-count=1", "./...",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		Check{
			ID:          "v2-readiness-report",
			Description: "Require the checked-in secret-free final readiness report to match the executable manifest and reviewed evidence map.",
			Requirement: requirementRequired,
			Action:      Action{Kind: actionBuiltin, Name: "v2-readiness-report"},
			Prerequisites: []Prerequisite{
				{Kind: "file", Name: "docs/plans/issue-31-release-readiness.md", Version: "tracked"},
			},
		},
	)
	return checks
}

func formatCheck() Check {
	return Check{
		ID:          "format",
		Description: "Require gofmt-clean source without rewriting files.",
		Requirement: requirementRequired,
		Action:      commandAction("{goroot}/bin/gofmt{exe}", []string{"-l", "."}, nil, "stdout_empty"),
		Prerequisites: []Prerequisite{
			{Kind: "tool", Name: "gofmt", Version: "go1.25.13"},
		},
	}
}

func lintCheck() Check {
	return Check{
		ID:          "lint",
		Description: "Run the reviewed golangci-lint baseline.",
		Requirement: requirementRequired,
		Preparations: []Preparation{
			{
				ID:               "lint-patch",
				Description:      "Prepare a no-filter v1.2.0-to-tracked-worktree patch consumed by lint.",
				WorkingDirectory: "source_repository",
				Output:           "{temp}/lint.patch",
				Action:           Action{Kind: actionBuiltin, Name: "lint-patch"},
			},
		},
		Action: commandAction("golangci-lint", []string{
			"run", "--new-from-patch", "{temp}/lint.patch",
		}, nil, ""),
		Prerequisites: []Prerequisite{
			{Kind: "tool", Name: "golangci-lint", Version: "2.11.4"},
			{Kind: "git_ref", Name: "v1.2.0", Version: "commit"},
			repositoryModulesPrerequisite(),
		},
	}
}

func vetCheck() Check {
	return Check{
		ID:            "vet",
		Description:   "Run Go vet across all packages.",
		Requirement:   requirementRequired,
		Action:        commandAction("go", []string{"vet", "./..."}, nil, ""),
		Prerequisites: goPrerequisites(),
	}
}

func vulnerabilityCheck() Check {
	check := Check{
		ID:          "vulnerability",
		Description: "Run govulncheck v1.6.0 across all packages.",
		Requirement: requirementRequired,
		Action: commandAction("go", []string{
			"run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0", "./...",
		}, nil, ""),
		Prerequisites: goPrerequisites(),
	}
	check.Prerequisites = append(check.Prerequisites, Prerequisite{
		Kind:    "capability",
		Name:    "govulncheck-module",
		Version: "network-or-module-cache",
	})
	return check
}

func buildCheck() Check {
	return Check{
		ID:          "build",
		Description: "Build ssm into a profile-owned temporary directory.",
		Requirement: requirementRequired,
		Action: commandAction("go", []string{
			"build", "-buildvcs=false", "-o", "{temp}/ssm{exe}", "./cmd/ssm",
		}, nil, ""),
		Prerequisites: goPrerequisites(),
	}
}

func unitCheck() Check {
	return Check{
		ID:            "unit",
		Description:   "Run the complete Go unit and integration test suite.",
		Requirement:   requirementRequired,
		Action:        commandAction("go", []string{"test", "./..."}, nil, ""),
		Prerequisites: goPrerequisites(),
	}
}

func raceCheck() Check {
	check := Check{
		ID:          "race",
		Description: "Run the complete Go test suite with the race detector on a natively supported host.",
		Requirement: requirementConditional,
		Activation:  "native_supported_host_with_cgo_and_c_compiler",
		RequiredContexts: []string{
			"github_actions_linux",
		},
		Action: commandAction(
			"go",
			[]string{"test", "-race", "-timeout=15m", "./..."},
			nil,
			"",
		),
		Prerequisites: goPrerequisites(),
	}
	check.Prerequisites = append(check.Prerequisites, Prerequisite{
		Kind:    "capability",
		Name:    "native-race",
		Version: "supported-host-cgo-c-compiler",
	})
	return check
}

func agentPromptsJSONCheck() Check {
	return Check{
		ID:          "agent-prompts-json",
		Description: "Validate the agent prompt artifact as JSON.",
		Requirement: requirementRequired,
		Action: commandAction("jq", []string{
			"empty", "skills/agent-ssm/test-prompts.json",
		}, nil, ""),
		Prerequisites: []Prerequisite{
			{Kind: "tool", Name: "jq", Version: "any"},
		},
	}
}

func requestSchemaJSONCheck() Check {
	return Check{
		ID:          "request-schema-json",
		Description: "Validate the request-v1 schema artifact as JSON.",
		Requirement: requirementRequired,
		Action: commandAction("jq", []string{
			"empty", "skills/agent-ssm/references/request-v1.schema.json",
		}, nil, ""),
		Prerequisites: []Prerequisite{
			{Kind: "tool", Name: "jq", Version: "any"},
		},
	}
}

func sshMatrixShellSyntaxCheck() Check {
	return Check{
		ID:          "ssh-matrix-shell-syntax",
		Description: "Parse the live SSH matrix script without executing it.",
		Requirement: requirementRequired,
		Action: commandAction("bash", []string{
			"-n", "scripts/ssh_matrix_test.sh",
		}, nil, ""),
		Prerequisites: []Prerequisite{
			{Kind: "tool", Name: "bash", Version: "any"},
		},
	}
}

func sshMatrixCheck() Check {
	return Check{
		ID:          "ssh-matrix",
		Description: "Run the existing live OpenSSH behavior matrix when its Linux prerequisites are available.",
		Requirement: requirementConditional,
		RequiredContexts: []string{
			"github_actions_linux",
		},
		Action: commandAction("bash", []string{
			"scripts/ssh_matrix_test.sh",
		}, nil, ""),
		Prerequisites: []Prerequisite{
			{Kind: "platform", Name: "linux", Version: "any"},
			{Kind: "tool", Name: "awk", Version: "any"},
			{Kind: "tool", Name: "bash", Version: "any"},
			{Kind: "tool", Name: "cat", Version: "any"},
			{Kind: "tool", Name: "chmod", Version: "any"},
			{Kind: "tool", Name: "cp", Version: "any"},
			{Kind: "tool", Name: "dd", Version: "any"},
			{Kind: "tool", Name: "dirname", Version: "any"},
			{Kind: "tool", Name: "find", Version: "any"},
			{Kind: "tool", Name: "go", Version: "1.25.13"},
			repositoryModulesPrerequisite(),
			{Kind: "tool", Name: "grep", Version: "any"},
			{Kind: "tool", Name: "head", Version: "any"},
			{Kind: "tool", Name: "id", Version: "any"},
			{Kind: "tool", Name: "ln", Version: "any"},
			{Kind: "tool", Name: "mkdir", Version: "any"},
			{Kind: "tool", Name: "mktemp", Version: "any"},
			{Kind: "tool", Name: "nohup", Version: "any"},
			{Kind: "tool", Name: "printenv", Version: "any"},
			{Kind: "tool", Name: "rm", Version: "any"},
			{Kind: "tool", Name: "script", Version: "any"},
			{Kind: "tool", Name: "sed", Version: "any"},
			{Kind: "tool", Name: "seq", Version: "any"},
			{Kind: "tool", Name: "sh", Version: "any"},
			{Kind: "tool", Name: "sha256sum", Version: "any"},
			{Kind: "tool", Name: "sleep", Version: "any"},
			{Kind: "tool", Name: "ssh", Version: "any"},
			{Kind: "tool", Name: "ssh-keygen", Version: "any"},
			{Kind: "tool", Name: "touch", Version: "any"},
			{
				Kind:    "executable_alternatives",
				Name:    "sshd",
				Version: "SSHD-then-PATH-then-/usr/sbin/sshd",
				Alternatives: []Prerequisite{
					{Kind: "environment_executable", Name: "SSHD", Version: "if-set-required"},
					{Kind: "path_executable", Name: "sshd", Version: "fallback"},
					{Kind: "system_path", Name: "/usr/sbin/sshd", Version: "executable-fallback"},
				},
			},
			{Kind: "tool", Name: "tr", Version: "any"},
			{Kind: "tool", Name: "wc", Version: "any"},
			{Kind: "system_path", Name: "/dev/null", Version: "readable"},
			{Kind: "system_path", Name: "/dev/zero", Version: "readable"},
			{Kind: "system_path", Name: "/run/sshd", Version: "directory"},
			{Kind: "system_path", Name: "/usr/lib/openssh/sftp-server", Version: "executable"},
		},
	}
}

func assetCheck(goos, goarch string) Check {
	name := releaseasset.Name(goos, goarch)
	return Check{
		ID:          "asset-" + goos + "-" + goarch,
		Description: "Build the canonical " + name + " release asset in temporary storage.",
		Requirement: requirementRequired,
		Action: commandAction("go", []string{
			"build", "-buildvcs=false", "-ldflags=-s -w -X main.version={version}",
			"-o", "{temp}/" + name, "./cmd/ssm",
		}, []string{"GOOS=" + goos, "GOARCH=" + goarch}, ""),
		Prerequisites: goPrerequisites(),
	}
}

func goPrerequisites() []Prerequisite {
	return []Prerequisite{
		{Kind: "tool", Name: "go", Version: "1.25.13"},
		repositoryModulesPrerequisite(),
	}
}

func repositoryModulesPrerequisite() Prerequisite {
	return Prerequisite{
		Kind:    "capability",
		Name:    "repository-modules",
		Version: "go-mod-download",
	}
}

func commandAction(executable string, args, env []string, expect string) Action {
	return Action{
		Kind: actionCommand,
		Command: &Command{
			Executable: executable,
			Args:       args,
			Env:        env,
			Expect:     expect,
		},
	}
}

func renderManifest(manifest Manifest) ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func findProfile(manifest Manifest, name string) (Profile, bool) {
	for _, profile := range manifest.Profiles {
		if profile.Name == name {
			return profile, true
		}
	}
	return Profile{}, false
}
