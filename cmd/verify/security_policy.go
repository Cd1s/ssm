package main

// reviewedActionPolicy is the verifier's independent security authority.
//
// Keep these exact builtins and command vectors manually reviewed. This policy
// must never be generated from verificationManifest, ciChecks, releaseChecks,
// or their constructors: changing a manifest action and its JSON golden must
// not grant that action execution authority.
func reviewedActionPolicy() map[string]Action {
	return map[string]Action{
		"format": reviewedCommand(
			"{goroot}/bin/gofmt{exe}",
			[]string{"-l", "."},
			nil,
			"stdout_empty",
		),
		"lint": reviewedCommand(
			"golangci-lint",
			[]string{"run", "--new-from-patch", "{temp}/lint.patch"},
			nil,
			"",
		),
		"vet": reviewedCommand(
			"go",
			[]string{"vet", "./..."},
			nil,
			"",
		),
		"vulnerability": reviewedCommand(
			"go",
			[]string{"run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0", "./..."},
			nil,
			"",
		),
		"build": reviewedCommand(
			"go",
			[]string{"build", "-buildvcs=false", "-o", "{temp}/ssm{exe}", "./cmd/ssm"},
			nil,
			"",
		),
		"unit": reviewedCommand(
			"go",
			[]string{"test", "./..."},
			nil,
			"",
		),
		"race": reviewedCommand(
			"go",
			[]string{"test", "-race", "./..."},
			nil,
			"",
		),
		"agent-prompts-json": reviewedCommand(
			"jq",
			[]string{"empty", "skills/agent-ssm/test-prompts.json"},
			nil,
			"",
		),
		"request-schema-json": reviewedCommand(
			"jq",
			[]string{"empty", "skills/agent-ssm/references/request-v1.schema.json"},
			nil,
			"",
		),
		"ssh-matrix-shell-syntax": reviewedCommand(
			"bash",
			[]string{"-n", "scripts/ssh_matrix_test.sh"},
			nil,
			"",
		),
		"ssh-matrix": reviewedCommand(
			"bash",
			[]string{"scripts/ssh_matrix_test.sh"},
			nil,
			"",
		),
		"source-version": {
			Kind: actionBuiltin,
			Name: "source-version",
		},
		"asset-linux-amd64": reviewedCommand(
			"go",
			[]string{
				"build", "-buildvcs=false", "-ldflags=-s -w -X main.version={version}",
				"-o", "{temp}/ssm-linux-amd64", "./cmd/ssm",
			},
			[]string{"GOOS=linux", "GOARCH=amd64"},
			"",
		),
		"asset-linux-arm64": reviewedCommand(
			"go",
			[]string{
				"build", "-buildvcs=false", "-ldflags=-s -w -X main.version={version}",
				"-o", "{temp}/ssm-linux-arm64", "./cmd/ssm",
			},
			[]string{"GOOS=linux", "GOARCH=arm64"},
			"",
		),
		"asset-darwin-amd64": reviewedCommand(
			"go",
			[]string{
				"build", "-buildvcs=false", "-ldflags=-s -w -X main.version={version}",
				"-o", "{temp}/ssm-darwin-amd64", "./cmd/ssm",
			},
			[]string{"GOOS=darwin", "GOARCH=amd64"},
			"",
		),
		"asset-darwin-arm64": reviewedCommand(
			"go",
			[]string{
				"build", "-buildvcs=false", "-ldflags=-s -w -X main.version={version}",
				"-o", "{temp}/ssm-darwin-arm64", "./cmd/ssm",
			},
			[]string{"GOOS=darwin", "GOARCH=arm64"},
			"",
		),
		"asset-windows-amd64": reviewedCommand(
			"go",
			[]string{
				"build", "-buildvcs=false", "-ldflags=-s -w -X main.version={version}",
				"-o", "{temp}/ssm-windows-amd64.exe", "./cmd/ssm",
			},
			[]string{"GOOS=windows", "GOARCH=amd64"},
			"",
		),
		"asset-windows-arm64": reviewedCommand(
			"go",
			[]string{
				"build", "-buildvcs=false", "-ldflags=-s -w -X main.version={version}",
				"-o", "{temp}/ssm-windows-arm64.exe", "./cmd/ssm",
			},
			[]string{"GOOS=windows", "GOARCH=arm64"},
			"",
		),
		"updater-selection": reviewedCommand(
			"go",
			[]string{
				"test", "./internal/update", "-run",
				"^TestAssetNameForSupportedPlatforms$", "-count=1",
			},
			nil,
			"",
		),
		"release-notes": {
			Kind: actionBuiltin,
			Name: "release-notes",
		},
		"install-shell-syntax": reviewedCommand(
			"sh",
			[]string{"-n", "install.sh"},
			nil,
			"",
		),
		"release-checksums": {
			Kind: actionBuiltin,
			Name: "release-checksums",
		},
		"checksum-failure-paths": reviewedCommand(
			"go",
			[]string{
				"test", "./internal/update", "-run",
				"^(TestChecksumForAsset|TestChecksumForAssetRequiresMatchingAsset|TestCopyAndVerifyRejectsChecksumMismatch|TestDownloadVersionVerifiesChecksumBeforeReplace)$",
				"-count=1",
			},
			nil,
			"",
		),
	}
}

func reviewedPreparationPolicy() map[string]Preparation {
	return map[string]Preparation{
		"lint-patch": {
			ID:               "lint-patch",
			Description:      "Prepare a no-filter v1.2.0-to-tracked-worktree patch consumed by lint.",
			WorkingDirectory: "source_repository",
			Output:           "{temp}/lint.patch",
			Action:           Action{Kind: actionBuiltin, Name: "lint-patch"},
		},
	}
}

func reviewedCommand(executable string, args, env []string, expect string) Action {
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
