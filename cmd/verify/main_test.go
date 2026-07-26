package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestListProfileWritesManifest(t *testing.T) {
	var stdout bytes.Buffer
	if err := runCLI(context.Background(), []string{"list"}, &stdout, io.Discard, runtimeDependencies{}); err != nil {
		t.Fatalf("run list: %v", err)
	}
	want, err := renderManifest(verificationManifest())
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != string(want) {
		t.Fatalf("list output differs from manifest:\n%s", stdout.String())
	}
}

func TestPrerequisitesReportAvailabilityAndVersion(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name         string
		prerequisite Prerequisite
		want         bool
	}{
		{
			name:         "current platform",
			prerequisite: Prerequisite{Kind: "platform", Name: runtime.GOOS, Version: "any"},
			want:         true,
		},
		{
			name:         "tracked file",
			prerequisite: Prerequisite{Kind: "file", Name: "tracked.txt", Version: "tracked"},
			want:         true,
		},
		{
			name:         "pinned Go",
			prerequisite: Prerequisite{Kind: "tool", Name: "go", Version: "1.25.12"},
			want:         true,
		},
		{
			name:         "wrong Go version",
			prerequisite: Prerequisite{Kind: "tool", Name: "go", Version: "0.0.0"},
			want:         false,
		},
		{
			name:         "missing tool",
			prerequisite: Prerequisite{Kind: "tool", Name: "ssm-verifier-tool-that-does-not-exist", Version: "any"},
			want:         false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := checkPrerequisite(repo, test.prerequisite)
			if got.available != test.want {
				t.Fatalf("available = %t (%s), want %t", got.available, got.detail, test.want)
			}
			if !got.available && got.detail == "" {
				t.Fatal("unavailable prerequisite has no explanation")
			}
		})
	}
}

func TestFormatCheckDetectsDriftWithoutRewriting(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, "bad.go")
	before := []byte("package fixture\n\nfunc unformatted( ){ }\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}

	result := (systemActionExecutor{}).Execute(context.Background(), formatCheck().Action, actionContext{
		RepoRoot: repo,
		TempDir:  t.TempDir(),
		Stdout:   io.Discard,
		Stderr:   io.Discard,
	})
	if result.Status != statusFailed {
		t.Fatalf("format status = %q, want %q", result.Status, statusFailed)
	}
	after, err := os.ReadFile(path) //nolint:gosec // path is inside t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("format check rewrote source:\nbefore: %q\nafter:  %q", before, after)
	}
}

func TestReleaseMetadataActions(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "cmd", "ssm"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repo, "cmd", "ssm", "main.go"),
		[]byte("package main\n\nvar version = \"2.3.4\"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repo, "RELEASE_NOTES.md"),
		[]byte("# Release Notes\n\n## v2.3.4\n\n- Verified release.\n\n## v2.3.3\n\n- Older.\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	executor := systemActionExecutor{}
	actionCtx := actionContext{RepoRoot: repo, Stdout: io.Discard, Stderr: io.Discard}
	for _, name := range []string{"source-version", "release-notes"} {
		result := executor.Execute(context.Background(), Action{Kind: actionBuiltin, Name: name}, actionCtx)
		if result.Status != statusPassed {
			t.Fatalf("%s status = %q (%s), want passed", name, result.Status, result.Detail)
		}
	}

	if err := os.WriteFile(
		filepath.Join(repo, "RELEASE_NOTES.md"),
		[]byte("# Release Notes\n\n## v2.3.3\n\n- Stale.\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(
		context.Background(),
		Action{Kind: actionBuiltin, Name: "release-notes"},
		actionCtx,
	)
	if result.Status != statusFailed {
		t.Fatalf("stale release notes status = %q, want failed", result.Status)
	}
}

func TestReleaseChecksumAction(t *testing.T) {
	repo := t.TempDir()
	tempDir := t.TempDir()
	assets := []string{
		"ssm-linux-amd64",
		"ssm-linux-arm64",
		"ssm-darwin-amd64",
		"ssm-darwin-arm64",
		"ssm-windows-amd64.exe",
		"ssm-windows-arm64.exe",
	}
	for _, asset := range assets {
		if err := os.WriteFile(filepath.Join(tempDir, asset), []byte("artifact:"+asset), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "install.sh"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	actionCtx := actionContext{RepoRoot: repo, TempDir: tempDir, Stdout: io.Discard, Stderr: io.Discard}
	executor := systemActionExecutor{}
	action := Action{Kind: actionBuiltin, Name: "release-checksums"}
	if result := executor.Execute(context.Background(), action, actionCtx); result.Status != statusPassed {
		t.Fatalf("checksum status = %q (%s), want passed", result.Status, result.Detail)
	}

	if err := os.Remove(filepath.Join(tempDir, assets[0])); err != nil {
		t.Fatal(err)
	}
	if result := executor.Execute(context.Background(), action, actionCtx); result.Status != statusFailed {
		t.Fatalf("missing-asset checksum status = %q, want failed", result.Status)
	}
}

func TestCIAdaptersUseManifestProfile(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	checkRecipe := makeTargetRecipe(string(makefile), "check")
	if checkRecipe != "go run ./cmd/verify ci" {
		t.Fatalf("Makefile check recipe = %q, want exact manifest adapter", checkRecipe)
	}

	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	const invocation = "run: go run ./cmd/verify ci"
	if count := strings.Count(string(workflow), invocation); count != 1 {
		t.Fatalf("CI manifest invocation count = %d, want 1", count)
	}
	for _, duplicate := range []string{
		`run: test -z "$(gofmt -l .)"`,
		"run: go vet ./...",
		"run: go test ./...",
		"run: go test -race ./...",
		"run: scripts/ssh_matrix_test.sh",
	} {
		if strings.Contains(string(workflow), duplicate) {
			t.Fatalf("CI still duplicates manifest-owned command %q", duplicate)
		}
	}

	matrix, err := os.ReadFile(filepath.Join("..", "..", "scripts", "ssh_matrix_test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(matrix), `BIN="$ROOT/ssm-it"`) {
		t.Fatal("SSH matrix still writes a repository-root binary")
	}
	if !strings.Contains(string(matrix), `BIN="$TMP/ssm-it"`) {
		t.Fatal("SSH matrix binary is not profile-temporary")
	}
	if !strings.Contains(string(matrix), "go build -buildvcs=false") {
		t.Fatal("SSH matrix build still depends on ambient VCS stamping")
	}
}

func TestProfileManifest(t *testing.T) {
	manifest := verificationManifest()

	first, err := renderManifest(manifest)
	if err != nil {
		t.Fatalf("render manifest: %v", err)
	}
	second, err := renderManifest(manifest)
	if err != nil {
		t.Fatalf("render manifest again: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("list output is not deterministic")
	}

	var listed Manifest
	if err := json.Unmarshal(first, &listed); err != nil {
		t.Fatalf("list output is not JSON: %v", err)
	}
	for _, profile := range listed.Profiles {
		for _, check := range profile.Checks {
			if check.ID == "" || check.Requirement == "" || check.Action.Kind == "" {
				t.Fatalf("profile %q has incomplete check metadata: %+v", profile.Name, check)
			}
			if check.Action.Kind == actionCommand &&
				(check.Action.Command == nil || check.Action.Command.Executable == "") {
				t.Fatalf("profile %q check %q has no exact command", profile.Name, check.ID)
			}
		}
	}

	wantPath := filepath.Join("testdata", "profile_membership.json")
	want, err := os.ReadFile(wantPath) //nolint:gosec // fixed checked-in testdata path
	if err != nil {
		t.Fatalf("read membership snapshot: %v", err)
	}
	var wantMembership []profileMembership
	if err := json.Unmarshal(want, &wantMembership); err != nil {
		t.Fatalf("parse membership snapshot: %v", err)
	}
	if got := snapshotMembership(listed); !reflect.DeepEqual(got, wantMembership) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("profile membership changed (-want +got):\nwant:\n%s\ngot:\n%s", want, gotJSON)
	}
}

func TestProfilesAreNonMutating(t *testing.T) {
	manifest := verificationManifest()
	if err := validateNonMutating(manifest); err != nil {
		t.Fatalf("manifest contains a mutating action: %v", err)
	}
	mutating := manifest
	mutating.Profiles = append([]Profile(nil), manifest.Profiles...)
	mutating.Profiles[1].Checks = append([]Check(nil), manifest.Profiles[1].Checks...)
	mutating.Profiles[1].Checks = append(mutating.Profiles[1].Checks, Check{
		ID:          "forbidden-tag",
		Requirement: requirementRequired,
		Action:      commandAction("git", []string{"tag", "v9.9.9"}, nil, ""),
	})
	if err := validateNonMutating(mutating); err == nil {
		t.Fatal("manifest accepted a tag-creating action")
	}

	for _, profileName := range []string{"fast", "ci", "release"} {
		t.Run(profileName, func(t *testing.T) {
			repo := newCleanTestRepository(t)
			sentinel := filepath.Join(repo, "sentinel.txt")
			before, err := os.ReadFile(sentinel) //nolint:gosec // sentinel is inside t.TempDir
			if err != nil {
				t.Fatal(err)
			}

			deps := runtimeDependencies{
				repoRoot: repo,
				stdout:   io.Discard,
				stderr:   io.Discard,
				prerequisites: func(Prerequisite) prerequisiteState {
					return prerequisiteState{available: true}
				},
				actions: actionExecutorFunc(func(_ context.Context, action Action, _ actionContext) checkResult {
					if action.Kind == actionExtension {
						return checkResult{Status: statusUnavailable}
					}
					if action.Kind == actionBuiltin && action.Name == "source-version" {
						return checkResult{Status: statusPassed, Detail: "1.2.3"}
					}
					return checkResult{Status: statusPassed}
				}),
			}
			if _, err := executeProfile(context.Background(), manifest, profileName, deps); err != nil {
				t.Fatalf("execute profile: %v", err)
			}

			after, err := os.ReadFile(sentinel) //nolint:gosec // sentinel is inside t.TempDir
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("tracked content changed: before %q, after %q", before, after)
			}
			if status := gitOutput(t, repo, "status", "--porcelain", "--untracked-files=no"); status != "" {
				t.Fatalf("profile changed tracked state:\n%s", status)
			}
		})
	}

	t.Run("failed check still verifies tracked state", func(t *testing.T) {
		repo := newCleanTestRepository(t)
		sentinel := filepath.Join(repo, "sentinel.txt")
		deps := runtimeDependencies{
			repoRoot: repo,
			stdout:   io.Discard,
			stderr:   io.Discard,
			prerequisites: func(Prerequisite) prerequisiteState {
				return prerequisiteState{available: true}
			},
			actions: actionExecutorFunc(func(_ context.Context, _ Action, _ actionContext) checkResult {
				if err := os.WriteFile(sentinel, []byte("changed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return checkResult{Status: statusFailed, Detail: "injected failure"}
			}),
		}
		_, err := executeProfile(context.Background(), manifest, "fast", deps)
		if err == nil || !strings.Contains(err.Error(), "changed tracked repository state") {
			t.Fatalf("error = %v, want tracked-state failure", err)
		}
	})
}

func TestReleaseStrictlyContainsCI(t *testing.T) {
	manifest := verificationManifest()
	ci, ok := findProfile(manifest, "ci")
	if !ok {
		t.Fatal("ci profile not found")
	}
	release, ok := findProfile(manifest, "release")
	if !ok {
		t.Fatal("release profile not found")
	}
	if len(release.Checks) <= len(ci.Checks) {
		t.Fatalf("release has %d checks, ci has %d; want a strict superset", len(release.Checks), len(ci.Checks))
	}
	if !reflect.DeepEqual(release.Checks[:len(ci.Checks)], ci.Checks) {
		t.Fatal("release does not contain the exact ordered ci profile")
	}
}

type profileMembership struct {
	Name   string   `json:"name"`
	Checks []string `json:"checks"`
}

func snapshotMembership(manifest Manifest) []profileMembership {
	membership := make([]profileMembership, 0, len(manifest.Profiles))
	for _, profile := range manifest.Profiles {
		checks := make([]string, 0, len(profile.Checks))
		for _, check := range profile.Checks {
			checks = append(checks, check.ID)
		}
		membership = append(membership, profileMembership{Name: profile.Name, Checks: checks})
	}
	return membership
}

func newCleanTestRepository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "sentinel.txt"), []byte("unchanged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOutput(t, repo, "init", "--quiet")
	gitOutput(t, repo, "config", "user.name", "Verify Test")
	gitOutput(t, repo, "config", "user.email", "verify@example.invalid")
	gitOutput(t, repo, "add", "sentinel.txt")
	gitOutput(t, repo, "commit", "--quiet", "-m", "test fixture")
	return repo
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...) //nolint:gosec // fixed test helper receives only test-owned git arguments
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func makeTargetRecipe(makefile, target string) string {
	lines := strings.Split(makefile, "\n")
	inTarget := false
	var recipes []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "\t") {
			inTarget = line == target+":" || strings.HasPrefix(line, target+": ")
			continue
		}
		if inTarget {
			recipes = append(recipes, strings.TrimSpace(line))
		}
	}
	return strings.Join(recipes, "\n")
}
