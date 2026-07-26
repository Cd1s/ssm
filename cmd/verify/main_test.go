package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"ssm/internal/update"
)

func TestFailuresNeverReportPassed(t *testing.T) {
	t.Run("unknown profile", func(t *testing.T) {
		var stderr bytes.Buffer
		err := runCLI(
			context.Background(),
			[]string{"not-a-profile"},
			io.Discard,
			&stderr,
			runtimeDependencies{},
		)
		if err == nil {
			t.Fatal("unknown profile succeeded")
		}
		if got, want := stderr.String(), "verify not-a-profile: failed\n"; got != want {
			t.Fatalf("stderr = %q, want %q", got, want)
		}
	})

	tests := []struct {
		name     string
		manifest Manifest
		profile  string
		deps     func(*testing.T) runtimeDependencies
	}{
		{
			name: "manifest validation",
			manifest: func() Manifest {
				manifest := verificationManifest()
				manifest.Profiles[1].Checks[0].Action = commandAction(
					"go",
					[]string{"test", "-c", "-o", "mutated", "./..."},
					nil,
					"",
				)
				return manifest
			}(),
			profile: "fast",
			deps: func(t *testing.T) runtimeDependencies {
				return passingTestDependencies(t, newCleanTestRepository(t))
			},
		},
		{
			name:     "profile prerequisite",
			manifest: verificationManifest(),
			profile:  "fast",
			deps: func(t *testing.T) runtimeDependencies {
				deps := passingTestDependencies(t, newCleanTestRepository(t))
				deps.prerequisites = func(Prerequisite) prerequisiteState {
					return prerequisiteState{detail: "not available"}
				}
				return deps
			},
		},
		{
			name:     "action failure",
			manifest: verificationManifest(),
			profile:  "fast",
			deps: func(t *testing.T) runtimeDependencies {
				deps := passingTestDependencies(t, newCleanTestRepository(t))
				deps.actions = func(context.Context, Action, actionContext) checkResult {
					return checkResult{Status: statusFailed, Detail: "representative failure"}
				}
				return deps
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := executeProfile(
				context.Background(),
				test.manifest,
				test.profile,
				test.deps(t),
			)
			if err == nil {
				t.Fatal("failed invocation returned nil error")
			}
			var output bytes.Buffer
			if err := writeProfileResult(&output, result); err != nil {
				t.Fatalf("write result: %v", err)
			}
			if strings.HasSuffix(output.String(), "verify "+test.profile+": passed\n") {
				t.Fatalf("failure output reports success:\n%s", output.String())
			}
			if !strings.HasSuffix(output.String(), "verify "+test.profile+": failed\n") {
				t.Fatalf("failure output has no deterministic failed summary:\n%s", output.String())
			}
		})
	}
}

func TestPrerequisitesReportAvailabilityAndVersion(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, "untracked.txt"), "fixture\n")

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
			prerequisite: Prerequisite{Kind: "file", Name: "sentinel.txt", Version: "tracked"},
			want:         true,
		},
		{
			name:         "present but untracked file",
			prerequisite: Prerequisite{Kind: "file", Name: "untracked.txt", Version: "tracked"},
			want:         false,
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

	vulnerability := vulnerabilityCheck()
	wantCapability := Prerequisite{
		Kind:    "capability",
		Name:    "govulncheck-module",
		Version: "network-or-module-cache",
	}
	if !containsPrerequisite(vulnerability.Prerequisites, wantCapability) {
		t.Fatalf("vulnerability prerequisites %v do not expose %v", vulnerability.Prerequisites, wantCapability)
	}

	format := formatCheck()
	if format.Action.Command == nil {
		t.Fatal("format action has no command")
	}
	if got, want := format.Action.Command.Executable, "{goroot}/bin/gofmt{exe}"; got != want {
		t.Fatalf("format executable = %q, want %q", got, want)
	}
	fakeBin := t.TempDir()
	writeTestFile(t, filepath.Join(fakeBin, "gofmt"), "#!/bin/sh\nexit 99\n")
	if err := os.Chmod(filepath.Join(fakeBin, "gofmt"), 0o700); err != nil { //nolint:gosec // executable test shim must be runnable
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	state := checkPrerequisite(repo, Prerequisite{Kind: "tool", Name: "gofmt", Version: "go1.25.12"})
	if !state.available {
		t.Fatalf("pinned gofmt unavailable: %s", state.detail)
	}
	if strings.Contains(state.detail, fakeBin) {
		t.Fatalf("gofmt prerequisite resolved unrelated PATH entry: %s", state.detail)
	}
	goRoot := strings.TrimSpace(commandOutput(t, repo, "go", "env", "GOROOT"))
	if !strings.Contains(state.detail, goRoot) {
		t.Fatalf("gofmt prerequisite detail %q does not identify pinned GOROOT %q", state.detail, goRoot)
	}
}

func TestSSHMatrixIsRequiredInOfficialLinuxCI(t *testing.T) {
	manifest := verificationManifest()
	ci, ok := findProfile(manifest, "ci")
	if !ok {
		t.Fatal("ci profile not found")
	}
	var sshMatrix Check
	for _, check := range ci.Checks {
		if check.ID == "ssh-matrix" {
			sshMatrix = check
			break
		}
	}
	if got, want := sshMatrix.RequiredContexts, []string{"github_actions_linux"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ssh-matrix required contexts = %v, want %v", got, want)
	}

	run := func(t *testing.T, officialCI bool, missing Prerequisite) (profileResult, error) {
		t.Helper()
		t.Setenv("GITHUB_ACTIONS", "")
		t.Setenv("RUNNER_OS", "")
		if officialCI {
			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("RUNNER_OS", "Linux")
		}
		deps := passingTestDependencies(t, newCleanTestRepository(t))
		deps.prerequisites = func(prerequisite Prerequisite) prerequisiteState {
			if prerequisite == missing {
				return prerequisiteState{detail: "not found in test context"}
			}
			return prerequisiteState{available: true}
		}
		return executeProfile(context.Background(), manifest, "ci", deps)
	}

	t.Run("local remains conditional", func(t *testing.T) {
		result, err := run(t, false, Prerequisite{Kind: "tool", Name: "sshd", Version: "any"})
		if err != nil {
			t.Fatalf("local ci: %v", err)
		}
		if result.Status != statusCompletedUnavailable {
			t.Fatalf("local status = %q, want %q", result.Status, statusCompletedUnavailable)
		}
	})
	for _, prerequisite := range sshMatrix.Prerequisites {
		t.Run("official CI fails without "+prerequisite.Name, func(t *testing.T) {
			result, err := run(t, true, prerequisite)
			if err == nil {
				t.Fatalf("official CI succeeded without %s", prerequisite.Name)
			}
			if result.Status != statusFailed {
				t.Fatalf("official CI status = %q, want %q", result.Status, statusFailed)
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

	result := executeAction(context.Background(), formatCheck().Action, actionContext{
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

	actionCtx := actionContext{RepoRoot: repo, Stdout: io.Discard, Stderr: io.Discard}
	for _, name := range []string{"source-version", "release-notes"} {
		result := executeAction(context.Background(), Action{Kind: actionBuiltin, Name: name}, actionCtx)
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
	result := executeAction(
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
	action := Action{Kind: actionBuiltin, Name: "release-checksums"}
	if result := executeAction(context.Background(), action, actionCtx); result.Status != statusPassed {
		t.Fatalf("checksum status = %q (%s), want passed", result.Status, result.Detail)
	}

	if err := os.Remove(filepath.Join(tempDir, assets[0])); err != nil {
		t.Fatal(err)
	}
	if result := executeAction(context.Background(), action, actionCtx); result.Status != statusFailed {
		t.Fatalf("missing-asset checksum status = %q, want failed", result.Status)
	}
}

func TestReleaseAssetsMatchProductionUpdater(t *testing.T) {
	release, ok := findProfile(verificationManifest(), "release")
	if !ok {
		t.Fatal("release profile not found")
	}
	want := map[string]string{
		"linux/amd64":   "ssm-linux-amd64",
		"linux/arm64":   "ssm-linux-arm64",
		"darwin/amd64":  "ssm-darwin-amd64",
		"darwin/arm64":  "ssm-darwin-arm64",
		"windows/amd64": "ssm-windows-amd64.exe",
		"windows/arm64": "ssm-windows-arm64.exe",
	}
	got := make(map[string]string)
	for _, check := range release.Checks {
		if !strings.HasPrefix(check.ID, "asset-") {
			continue
		}
		if check.Action.Command == nil {
			t.Fatalf("%s has no command", check.ID)
		}
		env := make(map[string]string)
		for _, entry := range check.Action.Command.Env {
			key, value, ok := strings.Cut(entry, "=")
			if !ok {
				t.Fatalf("%s has invalid environment %q", check.ID, entry)
			}
			env[key] = value
		}
		goos, goarch := env["GOOS"], env["GOARCH"]
		output := commandArgumentAfter(t, check.Action.Command.Args, "-o")
		manifestName := strings.TrimPrefix(output, "{temp}/")
		updaterName := update.AssetNameFor(goos, goarch)
		if manifestName != updaterName {
			t.Fatalf("%s manifest asset %q differs from updater selection %q", check.ID, manifestName, updaterName)
		}
		got[goos+"/"+goarch] = manifestName
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("release assets = %#v, want %#v", got, want)
	}
}

func TestCIAdaptersUseManifestProfile(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := verificationManifest()
	if err := validateCIAdapters(manifest, string(makefile), string(workflow)); err != nil {
		t.Fatal(err)
	}
	for _, command := range manifestCommandLines(manifest) {
		duplicated := string(workflow) + "\n      - name: Duplicated manifest gate\n        run: " + command + "\n"
		if err := validateCIAdapters(manifest, string(makefile), duplicated); err == nil {
			t.Fatalf("adapter validation accepted duplicated manifest action %q", command)
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

func TestOfficialCIInstallsAndAssertsSSHPrerequisites(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)

	for _, packageName := range []string{
		"bash",
		"coreutils",
		"dash",
		"findutils",
		"gawk",
		"grep",
		"jq",
		"openssh-client",
		"openssh-server",
		"sed",
		"util-linux",
	} {
		if !strings.Contains(workflow, "            "+packageName) {
			t.Errorf("workflow does not explicitly install package %q", packageName)
		}
	}
	for _, command := range []string{
		"awk",
		"bash",
		"cat",
		"chmod",
		"cp",
		"dd",
		"dirname",
		"find",
		"go",
		"grep",
		"head",
		"id",
		"jq",
		"ln",
		"mkdir",
		"mktemp",
		"nohup",
		"rm",
		"script",
		"sed",
		"seq",
		"sh",
		"sha256sum",
		"sleep",
		"ssh",
		"ssh-keygen",
		"sshd",
		"tr",
		"wc",
	} {
		assertion := `command -v ` + command + ` >/dev/null`
		if !strings.Contains(workflow, assertion) {
			t.Errorf("workflow does not assert %q", command)
		}
	}
	for _, assertion := range []string{
		"test -d /run/sshd",
		"test -x /usr/sbin/sshd",
		"test -x /usr/lib/openssh/sftp-server",
	} {
		if !strings.Contains(workflow, assertion) {
			t.Errorf("workflow does not assert system path with %q", assertion)
		}
	}
}

func TestProfileManifest(t *testing.T) {
	var first, second bytes.Buffer
	if err := runCLI(context.Background(), []string{"list"}, &first, io.Discard, runtimeDependencies{}); err != nil {
		t.Fatalf("run list: %v", err)
	}
	if err := runCLI(context.Background(), []string{"list"}, &second, io.Discard, runtimeDependencies{}); err != nil {
		t.Fatalf("run list again: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("list output is not deterministic")
	}

	var listed Manifest
	if err := json.Unmarshal(first.Bytes(), &listed); err != nil {
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

	wantPath := filepath.Join("testdata", "profile_manifest.json")
	want, err := os.ReadFile(wantPath) //nolint:gosec // fixed checked-in testdata path
	if err != nil {
		t.Fatalf("read complete manifest snapshot: %v", err)
	}
	if !bytes.Equal(first.Bytes(), want) {
		t.Fatalf("complete profile manifest changed (-want +got):\nwant:\n%s\ngot:\n%s", want, first.Bytes())
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
	for _, action := range []Action{
		commandAction("go", []string{"test", "-c", "-o", "mutated", "./..."}, nil, ""),
		commandAction("go", []string{"vet", "-json", "-o", "mutated", "./..."}, nil, ""),
	} {
		changed := verificationManifest()
		changed.Profiles[1].Checks[0].Action = action
		if err := validateNonMutating(changed); err == nil {
			t.Fatalf("manifest accepted unreviewed action: %+v", action.Command)
		}
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
				actions: func(_ context.Context, action Action, _ actionContext) checkResult {
					if action.Kind == actionBuiltin && action.Name == "source-version" {
						return checkResult{Status: statusPassed, Detail: "1.2.3"}
					}
					return checkResult{Status: statusPassed}
				},
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
			actions: func(_ context.Context, _ Action, _ actionContext) checkResult {
				if err := os.WriteFile(sentinel, []byte("changed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return checkResult{Status: statusFailed, Detail: "injected failure"}
			},
		}
		_, err := executeProfile(context.Background(), manifest, "fast", deps)
		if err == nil || !strings.Contains(err.Error(), "changed repository state") {
			t.Fatalf("error = %v, want repository-state failure", err)
		}
	})

	t.Run("representative real actions", func(t *testing.T) {
		repo := newGoTestRepository(t)
		before, err := repositorySnapshot(repo)
		if err != nil {
			t.Fatalf("snapshot before: %v", err)
		}
		deps := runtimeDependencies{
			repoRoot: repo,
			stdout:   io.Discard,
			stderr:   io.Discard,
			prerequisites: func(Prerequisite) prerequisiteState {
				return prerequisiteState{available: true}
			},
			actions: executeAction,
		}
		result, err := executeProfile(context.Background(), manifest, "fast", deps)
		if err != nil {
			t.Fatalf("execute real fast profile: %v", err)
		}
		if result.Status != statusPassed {
			t.Fatalf("real fast status = %q, want %q", result.Status, statusPassed)
		}
		after, err := repositorySnapshot(repo)
		if err != nil {
			t.Fatalf("snapshot after: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("real fast profile mutated test-owned repository")
		}
	})
}

func TestRepositorySnapshotDetectsEveryMutationClass(t *testing.T) {
	tests := []struct {
		name   string
		before func(*testing.T, string)
		mutate func(*testing.T, string)
	}{
		{
			name: "tracked content",
			mutate: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "changed\n")
			},
		},
		{
			name: "index",
			mutate: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "staged\n")
				gitOutput(t, repo, "add", "sentinel.txt")
			},
		},
		{
			name: "untracked addition",
			mutate: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "new.txt"), "new\n")
			},
		},
		{
			name: "untracked removal",
			before: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "untracked.txt"), "before\n")
			},
			mutate: func(t *testing.T, repo string) {
				if err := os.Remove(filepath.Join(repo, "untracked.txt")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "untracked content",
			before: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "untracked.txt"), "before\n")
			},
			mutate: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "untracked.txt"), "after\n")
			},
		},
		{
			name: "further dirty tracked content",
			before: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "dirty-before\n")
			},
			mutate: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "dirty-after\n")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := newCleanTestRepository(t)
			if test.before != nil {
				test.before(t, repo)
			}
			before, err := repositorySnapshot(repo)
			if err != nil {
				t.Fatalf("snapshot before: %v", err)
			}
			test.mutate(t, repo)
			after, err := repositorySnapshot(repo)
			if err != nil {
				t.Fatalf("snapshot after: %v", err)
			}
			if bytes.Equal(before, after) {
				t.Fatal("repository snapshot did not change")
			}
		})
	}
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

func TestReleaseExtensionsAreMetadataNotChecks(t *testing.T) {
	release, ok := findProfile(verificationManifest(), "release")
	if !ok {
		t.Fatal("release profile not found")
	}
	for _, check := range release.Checks {
		if check.Action.Kind == "extension" {
			t.Fatalf("release extension %q is modeled as an executable check", check.ID)
		}
	}

	want := []Extension{
		{
			Name:           "migration-extension",
			Description:    "v2 migration contract and failure-path verification",
			RequiredBefore: "initial_v2_release",
		},
		{
			Name:           "provenance-extension",
			Description:    "keyless provenance identity and trust verification",
			RequiredBefore: "initial_v2_release",
		},
	}
	if !reflect.DeepEqual(release.Extensions, want) {
		t.Fatalf("release extensions = %#v, want %#v", release.Extensions, want)
	}

	deps := passingTestDependencies(t, newCleanTestRepository(t))
	deps.actions = func(_ context.Context, action Action, _ actionContext) checkResult {
		if action.Kind == actionBuiltin && action.Name == "source-version" {
			return checkResult{Status: statusPassed, Detail: "1.2.3"}
		}
		return checkResult{Status: statusPassed}
	}
	result, err := executeProfile(context.Background(), verificationManifest(), "release", deps)
	if err != nil {
		t.Fatalf("execute Ticket #18 release preflight: %v", err)
	}
	if result.Status != statusPreflightPassed {
		t.Fatalf("release preflight status = %q, want %q", result.Status, statusPreflightPassed)
	}
	if len(result.Checks) != len(release.Checks) {
		t.Fatalf("release emitted %d check results for %d executable checks", len(result.Checks), len(release.Checks))
	}
	for _, check := range result.Checks {
		if check.Status == statusUnavailable {
			t.Fatalf("release metadata leaked into runtime results: %+v", check)
		}
	}
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

func newGoTestRepository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	writeTestFile(t, filepath.Join(repo, "go.mod"), "module example.invalid/verifyfixture\n\ngo 1.25.12\n")
	writeTestFile(t, filepath.Join(repo, "fixture.go"), "package verifyfixture\n\nfunc Value() int { return 18 }\n")
	writeTestFile(
		t,
		filepath.Join(repo, "fixture_test.go"),
		"package verifyfixture\n\nimport \"testing\"\n\nfunc TestValue(t *testing.T) {\n\tif Value() != 18 {\n\t\tt.Fatal(\"unexpected value\")\n\t}\n}\n",
	)
	gitOutput(t, repo, "init", "--quiet")
	gitOutput(t, repo, "config", "user.name", "Verify Test")
	gitOutput(t, repo, "config", "user.email", "verify@example.invalid")
	gitOutput(t, repo, "add", ".")
	gitOutput(t, repo, "commit", "--quiet", "-m", "test fixture")
	return repo
}

func passingTestDependencies(t *testing.T, repo string) runtimeDependencies {
	t.Helper()
	return runtimeDependencies{
		repoRoot: repo,
		stdout:   io.Discard,
		stderr:   io.Discard,
		prerequisites: func(Prerequisite) prerequisiteState {
			return prerequisiteState{available: true}
		},
		actions: func(context.Context, Action, actionContext) checkResult {
			return checkResult{Status: statusPassed}
		},
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commandArgumentAfter(t *testing.T, args []string, flag string) string {
	t.Helper()
	for index, arg := range args {
		if arg == flag && index+1 < len(args) {
			return args[index+1]
		}
	}
	t.Fatalf("command %q has no %s argument", args, flag)
	return ""
}

func containsPrerequisite(prerequisites []Prerequisite, want Prerequisite) bool {
	for _, prerequisite := range prerequisites {
		if prerequisite == want {
			return true
		}
	}
	return false
}

func commandOutput(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	command := exec.Command(name, args...) //nolint:gosec // test helper receives fixed test-owned commands
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
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

func manifestCommandLines(manifest Manifest) []string {
	seen := make(map[string]bool)
	var commands []string
	for _, profile := range manifest.Profiles {
		for _, check := range profile.Checks {
			if check.Action.Command == nil {
				continue
			}
			command := strings.Join(
				append([]string{check.Action.Command.Executable}, check.Action.Command.Args...),
				" ",
			)
			if !seen[command] {
				seen[command] = true
				commands = append(commands, command)
			}
		}
	}
	return commands
}

func validateCIAdapters(manifest Manifest, makefile, workflow string) error {
	const invocation = "go run ./cmd/verify ci"
	if got := makeTargetRecipe(makefile, "check"); got != invocation {
		return fmt.Errorf("Makefile check recipe = %q, want %q", got, invocation)
	}

	steps := parseWorkflowSteps(workflow)
	invocations := 0
	for _, step := range steps {
		if step.uses != "" &&
			!strings.HasPrefix(step.uses, "actions/checkout@") &&
			!strings.HasPrefix(step.uses, "actions/setup-go@") {
			return fmt.Errorf("workflow executable action %q is not setup or checkout", step.uses)
		}
		if step.run == "" {
			continue
		}
		switch step.name {
		case "Install workflow prerequisites", "Install official golangci-lint prebuilt":
		case "Verify CI profile":
			if strings.TrimSpace(step.run) != invocation {
				return fmt.Errorf("Verify CI profile runs %q, want %q", strings.TrimSpace(step.run), invocation)
			}
			invocations++
		default:
			return fmt.Errorf("workflow run step %q is not an approved setup or manifest adapter", step.name)
		}
	}
	if invocations != 1 {
		return fmt.Errorf("workflow manifest invocation count = %d, want 1", invocations)
	}

	for _, command := range manifestCommandLines(manifest) {
		if strings.Contains(makefile, command) || strings.Contains(workflow, command) {
			return fmt.Errorf("adapter duplicates manifest-owned command %q", command)
		}
	}
	return nil
}

type workflowStep struct {
	name string
	uses string
	run  string
}

func parseWorkflowSteps(workflow string) []workflowStep {
	lines := strings.Split(workflow, "\n")
	var steps []workflowStep
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		if !strings.HasPrefix(line, "      - ") {
			continue
		}
		step := workflowStep{}
		item := strings.TrimSpace(strings.TrimPrefix(line, "      - "))
		switch {
		case strings.HasPrefix(item, "name: "):
			step.name = strings.TrimPrefix(item, "name: ")
		case strings.HasPrefix(item, "uses: "):
			step.uses = strings.TrimPrefix(item, "uses: ")
		}
		for index++; index < len(lines) && !strings.HasPrefix(lines[index], "      - "); index++ {
			field := lines[index]
			trimmed := strings.TrimSpace(field)
			switch {
			case strings.HasPrefix(trimmed, "name: "):
				step.name = strings.TrimPrefix(trimmed, "name: ")
			case strings.HasPrefix(trimmed, "uses: "):
				step.uses = strings.TrimPrefix(trimmed, "uses: ")
			case strings.HasPrefix(field, "        run: "):
				value := strings.TrimPrefix(field, "        run: ")
				if value != "|" {
					step.run = value
					continue
				}
				var script []string
				for index+1 < len(lines) && strings.HasPrefix(lines[index+1], "          ") {
					index++
					script = append(script, strings.TrimPrefix(lines[index], "          "))
				}
				step.run = strings.Join(script, "\n")
			}
		}
		index--
		steps = append(steps, step)
	}
	return steps
}
