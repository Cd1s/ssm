package main

import (
	"encoding/json"
)

const (
	actionCommand   = "command"
	actionBuiltin   = "builtin"
	actionExtension = "extension"

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
}

type Check struct {
	ID            string         `json:"id"`
	Description   string         `json:"description"`
	Requirement   string         `json:"requirement"`
	Action        Action         `json:"action"`
	Prerequisites []Prerequisite `json:"prerequisites"`
}

type Action struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name,omitempty"`
	Command *Command `json:"command,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

type Command struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	Env        []string `json:"env,omitempty"`
	Expect     string   `json:"expect,omitempty"`
}

type Prerequisite struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
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
				Purpose:       "Non-publishing release preparation; conditionally unavailable extension seams are never reported as passed.",
				Equivalence:   "non_publishing_release_preparation",
				Prerequisites: profilePrerequisites(),
				Checks:        release,
			},
		},
	}
}

func profilePrerequisites() []Prerequisite {
	return []Prerequisite{
		{Kind: "tool", Name: "git", Version: "any"},
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
	return []Check{
		{
			ID:          "source-version",
			Description: "Validate the source version as a release version.",
			Requirement: requirementRequired,
			Action:      Action{Kind: actionBuiltin, Name: "source-version"},
			Prerequisites: []Prerequisite{
				{Kind: "file", Name: "cmd/ssm/main.go", Version: "tracked"},
			},
		},
		assetCheck("linux", "amd64", ""),
		assetCheck("linux", "arm64", ""),
		assetCheck("darwin", "amd64", ""),
		assetCheck("darwin", "arm64", ""),
		assetCheck("windows", "amd64", ".exe"),
		assetCheck("windows", "arm64", ".exe"),
		{
			ID:          "updater-selection",
			Description: "Prove updater selection matches all six release asset names.",
			Requirement: requirementRequired,
			Action: commandAction("go", []string{
				"test", "./internal/update", "-run", "^TestAssetNameForSupportedPlatforms$", "-count=1",
			}, nil, ""),
			Prerequisites: goPrerequisites(),
		},
		{
			ID:          "release-notes",
			Description: "Require non-empty release notes for the source version.",
			Requirement: requirementRequired,
			Action:      Action{Kind: actionBuiltin, Name: "release-notes"},
			Prerequisites: []Prerequisite{
				{Kind: "file", Name: "RELEASE_NOTES.md", Version: "tracked"},
			},
		},
		{
			ID:          "release-checksums",
			Description: "Compute SHA-256 digests for all six assets and install.sh without writing release output.",
			Requirement: requirementRequired,
			Action:      Action{Kind: actionBuiltin, Name: "release-checksums"},
			Prerequisites: []Prerequisite{
				{Kind: "file", Name: "install.sh", Version: "tracked"},
			},
		},
		{
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
		{
			ID:          "migration-extension",
			Description: "Named seam for later v2 migration contract checks.",
			Requirement: requirementConditional,
			Action: Action{
				Kind:   actionExtension,
				Name:   "v2-migration-contracts",
				Reason: "no migration contract action is implemented by this ticket",
			},
			Prerequisites: []Prerequisite{},
		},
		{
			ID:          "provenance-extension",
			Description: "Named seam for later keyless provenance and trust checks.",
			Requirement: requirementConditional,
			Action: Action{
				Kind:   actionExtension,
				Name:   "keyless-provenance-trust",
				Reason: "no provenance action is implemented by this ticket",
			},
			Prerequisites: []Prerequisite{},
		},
	}
}

func formatCheck() Check {
	return Check{
		ID:          "format",
		Description: "Require gofmt-clean source without rewriting files.",
		Requirement: requirementRequired,
		Action:      commandAction("gofmt", []string{"-l", "."}, nil, "stdout_empty"),
		Prerequisites: []Prerequisite{
			{Kind: "tool", Name: "gofmt", Version: "go1.25.12"},
		},
	}
}

func lintCheck() Check {
	return Check{
		ID:          "lint",
		Description: "Run the reviewed golangci-lint baseline.",
		Requirement: requirementRequired,
		Action: commandAction("golangci-lint", []string{
			"run", "--new-from-rev=v1.2.0",
		}, nil, ""),
		Prerequisites: []Prerequisite{
			{Kind: "tool", Name: "golangci-lint", Version: "2.11.4"},
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
	return Check{
		ID:          "vulnerability",
		Description: "Run govulncheck v1.6.0 across all packages.",
		Requirement: requirementRequired,
		Action: commandAction("go", []string{
			"run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0", "./...",
		}, nil, ""),
		Prerequisites: goPrerequisites(),
	}
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
	return Check{
		ID:            "race",
		Description:   "Run the complete Go test suite with the race detector.",
		Requirement:   requirementRequired,
		Action:        commandAction("go", []string{"test", "-race", "./..."}, nil, ""),
		Prerequisites: goPrerequisites(),
	}
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
		Action: commandAction("bash", []string{
			"scripts/ssh_matrix_test.sh",
		}, nil, ""),
		Prerequisites: []Prerequisite{
			{Kind: "platform", Name: "linux", Version: "any"},
			{Kind: "tool", Name: "bash", Version: "any"},
			{Kind: "tool", Name: "ssh", Version: "any"},
			{Kind: "tool", Name: "ssh-keygen", Version: "any"},
			{Kind: "tool", Name: "sshd", Version: "any"},
			{Kind: "tool", Name: "script", Version: "any"},
			{Kind: "tool", Name: "sha256sum", Version: "any"},
		},
	}
}

func assetCheck(goos, goarch, extension string) Check {
	name := "ssm-" + goos + "-" + goarch + extension
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
		{Kind: "tool", Name: "go", Version: "1.25.12"},
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
