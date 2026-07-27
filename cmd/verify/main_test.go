package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"ssm/internal/privatepath"
	"ssm/internal/releaseasset"
	"ssm/internal/update"
)

type injectedReadCloser struct {
	readErr  error
	closeErr error
}

func (reader *injectedReadCloser) Read([]byte) (int, error) {
	return 0, reader.readErr
}

func (reader *injectedReadCloser) Close() error {
	return reader.closeErr
}

func TestSafeReaderJoinsReadAndCleanupFailures(t *testing.T) {
	readErr := errors.New("injected read failure")
	closeErr := errors.New("injected close failure")
	_, err := readAndCloseRegularFile(
		&injectedReadCloser{readErr: readErr, closeErr: closeErr},
		"fixture",
	)
	if !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want joined read and close failures", err)
	}
}

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
				deps.prerequisites = func(context.Context, string, Prerequisite, []string) prerequisiteState {
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

func TestProfileCleanupFailureIsFatal(t *testing.T) {
	deps := passingTestDependencies(t, newCleanTestRepository(t))
	deps.removeAll = func(path string) error {
		if err := os.RemoveAll(path); err != nil { //nolint:gosec // path is created by executeProfile for this injected cleanup seam
			return err
		}
		return fmt.Errorf("injected cleanup failure")
	}

	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "remove profile temporary directory") {
		t.Fatalf("error = %v, want cleanup failure", err)
	}
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
}

func TestPrerequisitesReportAvailabilityAndVersion(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, "untracked.txt"), "fixture\n")
	environment := newTestProcessEnvironment(t)

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
			got := checkPrerequisite(context.Background(), repo, test.prerequisite, environment)
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
	goRoot := strings.TrimSpace(commandOutput(t, repo, "go", "env", "GOROOT"))
	gofmtName := "gofmt" + executableSuffix()
	gofmtData, err := os.ReadFile(filepath.Join(goRoot, "bin", gofmtName)) //nolint:gosec // resolved pinned Go toolchain fixture
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // copied executable fixture must retain owner execute permission on Unix
	if err := os.WriteFile(filepath.Join(fakeBin, gofmtName), gofmtData, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	state := checkPrerequisite(
		context.Background(),
		repo,
		Prerequisite{Kind: "tool", Name: "gofmt", Version: "go1.25.12"},
		newTestProcessEnvironment(t),
	)
	if !state.available {
		t.Fatalf("pinned gofmt unavailable: %s", state.detail)
	}
	if strings.Contains(state.detail, fakeBin) {
		t.Fatalf("gofmt prerequisite resolved unrelated PATH entry: %s", state.detail)
	}
	if !strings.Contains(state.detail, goRoot) {
		t.Fatalf("gofmt prerequisite detail %q does not identify pinned GOROOT %q", state.detail, goRoot)
	}
}

func TestSSHMatrixIsRequiredInOfficialLinuxCI(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires a native Linux host to exercise official Linux prerequisite enforcement")
	}
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
	var sshdAlternatives Prerequisite
	for _, prerequisite := range sshMatrix.Prerequisites {
		if prerequisite.Kind == "executable_alternatives" && prerequisite.Name == "sshd" {
			sshdAlternatives = prerequisite
			break
		}
	}
	if sshdAlternatives.Kind == "" {
		t.Fatal("ssh-matrix has no SSHD executable alternatives prerequisite")
	}
	setProfileChecks(t, &manifest, "ci", []Check{sshMatrix})

	run := func(t *testing.T, officialCI bool, missing Prerequisite) (profileResult, error) {
		t.Helper()
		t.Setenv("GITHUB_ACTIONS", "")
		t.Setenv("RUNNER_OS", "")
		if officialCI {
			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("RUNNER_OS", "Linux")
		}
		deps := passingTestDependencies(t, newCleanTestRepository(t))
		deps.prerequisites = func(_ context.Context, _ string, prerequisite Prerequisite, _ []string) prerequisiteState {
			if reflect.DeepEqual(prerequisite, missing) {
				return prerequisiteState{detail: "not found in test context"}
			}
			return prerequisiteState{available: true}
		}
		return executeProfile(context.Background(), manifest, "ci", deps)
	}

	t.Run("local remains conditional", func(t *testing.T) {
		result, err := run(t, false, sshdAlternatives)
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

func TestRaceActivationIsTruthfulByNativeHost(t *testing.T) {
	race := raceCheck()
	if got, want := race.Requirement, requirementConditional; got != want {
		t.Fatalf("race requirement = %q, want %q", got, want)
	}
	if got, want := race.RequiredContexts, []string{"github_actions_linux"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("race required contexts = %v, want %v", got, want)
	}
	if got, want := race.Activation, "native_supported_host_with_cgo_and_c_compiler"; got != want {
		t.Fatalf("race activation = %q, want %q", got, want)
	}
	wantPrerequisite := Prerequisite{
		Kind:    "capability",
		Name:    "native-race",
		Version: "supported-host-cgo-c-compiler",
	}
	if !containsPrerequisite(race.Prerequisites, wantPrerequisite) {
		t.Fatalf("race prerequisites %v do not expose %v", race.Prerequisites, wantPrerequisite)
	}

	for _, test := range []struct {
		goos, goarch string
		want         bool
	}{
		{goos: "linux", goarch: "amd64", want: true},
		{goos: "linux", goarch: "arm64", want: true},
		{goos: "darwin", goarch: "arm64", want: true},
		{goos: "windows", goarch: "amd64", want: true},
		{goos: "windows", goarch: "arm64", want: false},
		{goos: "linux", goarch: "386", want: false},
	} {
		t.Run(test.goos+"-"+test.goarch, func(t *testing.T) {
			if got := raceSupportedHost(test.goos, test.goarch); got != test.want {
				t.Fatalf("raceSupportedHost(%q, %q) = %t, want %t", test.goos, test.goarch, got, test.want)
			}
		})
	}

	unsupported := raceCapabilityForHost(context.Background(), "windows", "arm64", newTestProcessEnvironment(t))
	if unsupported.available || !strings.Contains(unsupported.detail, "unsupported") {
		t.Fatalf("windows/arm64 race state = %+v, want truthful unsupported result", unsupported)
	}

	if !checkIsRequiredFor(race, executionContext{
		GOOS:          "linux",
		GOARCH:        "amd64",
		GitHubActions: true,
		RunnerOS:      "Linux",
	}) {
		t.Fatal("race is not fail-closed in official Linux merge CI")
	}
	if checkIsRequiredFor(race, executionContext{
		GOOS:          "windows",
		GOARCH:        "arm64",
		GitHubActions: true,
		RunnerOS:      "Windows",
	}) {
		t.Fatal("race is falsely required on unsupported Windows/arm64")
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
		RepoRoot:    repo,
		TempDir:     t.TempDir(),
		Environment: newTestProcessEnvironment(t),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
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

func TestSourceVersionMatchesReleaseWorkflowGrammar(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "ASCII digits", version: "1.2.3", want: statusPassed},
		{name: "leading zeroes", version: "01.002.0003", want: statusPassed},
		{name: "negative sign", version: "-1.2.3", want: statusFailed},
		{name: "positive sign", version: "+1.2.3", want: statusFailed},
		{name: "v prefix", version: "v1.2.3", want: statusFailed},
		{name: "letter suffix", version: "1.2.3x", want: statusFailed},
		{name: "leading whitespace", version: " 1.2.3", want: statusFailed},
		{name: "trailing whitespace", version: "1.2.3 ", want: statusFailed},
		{name: "prerelease", version: "1.2.3-rc.1", want: statusFailed},
		{name: "extra component", version: "1.2.3.4", want: statusFailed},
		{name: "non-ASCII digits", version: "１.２.３", want: statusFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := t.TempDir()
			if err := os.MkdirAll(filepath.Join(repo, "cmd", "ssm"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestFile(
				t,
				filepath.Join(repo, "cmd", "ssm", "main.go"),
				fmt.Sprintf("package main\n\nvar version = %q\n", test.version),
			)
			result := executeBuiltin("source-version", actionContext{RepoRoot: repo})
			if result.Status != test.want {
				t.Fatalf("version %q status = %q (%s), want %q", test.version, result.Status, result.Detail, test.want)
			}
		})
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

func TestAssetAndOutputPathSemanticsByOS(t *testing.T) {
	for _, test := range []struct {
		name       string
		goos       string
		goarch     string
		tempDir    string
		goRoot     string
		wantBinary string
		wantGofmt  string
		wantAsset  string
		wantName   string
	}{
		{
			name:       "linux",
			goos:       "linux",
			goarch:     "amd64",
			tempDir:    "/tmp/verify",
			goRoot:     "/opt/go",
			wantBinary: "/tmp/verify/ssm",
			wantGofmt:  "/opt/go/bin/gofmt",
			wantAsset:  "/tmp/verify/ssm-linux-amd64",
			wantName:   "ssm-linux-amd64",
		},
		{
			name:       "macos",
			goos:       "darwin",
			goarch:     "arm64",
			tempDir:    "/private/tmp/verify",
			goRoot:     "/opt/go",
			wantBinary: "/private/tmp/verify/ssm",
			wantGofmt:  "/opt/go/bin/gofmt",
			wantAsset:  "/private/tmp/verify/ssm-darwin-arm64",
			wantName:   "ssm-darwin-arm64",
		},
		{
			name:       "windows",
			goos:       "windows",
			goarch:     "amd64",
			tempDir:    `C:\verify`,
			goRoot:     `C:\Go`,
			wantBinary: `C:\verify\ssm.exe`,
			wantGofmt:  `C:\Go\bin\gofmt.exe`,
			wantAsset:  `C:\verify\ssm-windows-amd64.exe`,
			wantName:   "ssm-windows-amd64.exe",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			actionCtx := actionContext{TempDir: test.tempDir, GoRoot: test.goRoot}
			if got := expandActionValueForOS("{temp}/ssm{exe}", actionCtx, test.goos); got != test.wantBinary {
				t.Fatalf("host binary path = %q, want %q", got, test.wantBinary)
			}
			if got := expandActionValueForOS("{goroot}/bin/gofmt{exe}", actionCtx, test.goos); got != test.wantGofmt {
				t.Fatalf("gofmt path = %q, want %q", got, test.wantGofmt)
			}

			output := commandArgumentAfter(t, assetCheck(test.goos, test.goarch).Action.Command.Args, "-o")
			if got := expandActionValueForOS(output, actionCtx, test.goos); got != test.wantAsset {
				t.Fatalf("release asset path = %q, want %q", got, test.wantAsset)
			}
			if got := update.AssetNameFor(test.goos, test.goarch); got != test.wantName {
				t.Fatalf("updater asset = %q, want %q", got, test.wantName)
			}
		})
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

func TestRepositoryForcesDeterministicLFWorktrees(t *testing.T) {
	attributes, err := os.ReadFile(filepath.Join("..", "..", ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(attributes), "# Verification and shell tooling require deterministic LF worktrees on every platform.\n* text=auto eol=lf\n"; got != want {
		t.Fatalf(".gitattributes = %q, want %q", got, want)
	}
}

func TestCIWorkflowMatchesReviewedGoldenAndHasReadOnlyCredentialFreeJobs(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "ci.yml"))
	if err != nil {
		t.Fatalf("read checked-in CI workflow golden: %v", err)
	}
	if !bytes.Equal(workflow, golden) {
		t.Fatal("CI workflow differs from the reviewed complete golden")
	}

	text := string(workflow)
	if got, want := strings.Count(text, "    permissions:\n      contents: read\n"), 2; got != want {
		t.Fatalf("job-level contents: read permissions count = %d, want %d", got, want)
	}
	if got, want := strings.Count(text, "      - uses: actions/checkout@v7\n"), 2; got != want {
		t.Fatalf("checkout step count = %d, want %d", got, want)
	}
	if got, want := strings.Count(text, "          persist-credentials: false\n"), 2; got != want {
		t.Fatalf("persist-credentials: false count = %d, want %d", got, want)
	}
	if got, want := strings.Count(text, "        run: go run ./cmd/verify ci\n"), 1; got != want {
		t.Fatalf("exact Linux ci invocation count = %d, want %d", got, want)
	}
	if got, want := strings.Count(text, "        run: go run ./cmd/verify fast\n"), 1; got != want {
		t.Fatalf("exact Windows fast invocation count = %d, want %d", got, want)
	}
	for _, exactUse := range []string{
		"actions/checkout@v7",
		"actions/setup-go@v6",
	} {
		if got, want := strings.Count(text, "uses: "+exactUse), 2; got != want {
			t.Fatalf("%s use count = %d, want %d", exactUse, got, want)
		}
	}
	if !strings.Contains(text, "runs-on: windows-latest") {
		t.Fatal("official native Windows job is absent")
	}
}

func TestReleaseWorkflowUsesCredentialFreeVerifierPreflightAndManifestParity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for description, required := range map[string]string{
		"read-only workflow default": "permissions:\n  contents: read\n",
		"read-only preflight job":    "  preflight:\n    permissions:\n      contents: read\n",
		"credential-free checkout":   "          persist-credentials: false\n",
		"complete history":           "          fetch-depth: 0\n",
		"pinned Go toolchain":        "          go-version: \"1.25.12\"\n",
		"actual release preflight":   "        run: go run ./cmd/verify release\n",
		"build preflight dependency": "  build:\n    needs: preflight\n",
		"isolated publication job":   "  publish:\n    permissions:\n      contents: write\n    needs: [preflight, build]\n",
		"no-filter release build":    `go build -buildvcs=false -ldflags="-s -w -X main.version=$VERSION"`,
		"nonblank release notes":     "grep -q '[^[:space:]]' release-body.md",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release workflow lacks %s surface %q", description, required)
		}
	}
	if got := strings.Count(workflow, "contents: write"); got != 1 {
		t.Errorf("write-authorized permission count = %d, want one explicit publication job", got)
	}
	if got := strings.Count(workflow, "persist-credentials: false"); got != 3 {
		t.Errorf("credential-free checkout count = %d, want preflight, build, and publish", got)
	}

	var gotAssets []string
	for _, line := range strings.Split(workflow, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "asset: ") {
			gotAssets = append(gotAssets, strings.TrimPrefix(line, "asset: "))
		}
	}
	var wantAssets []string
	for _, target := range releaseasset.SupportedTargets() {
		wantAssets = append(wantAssets, releaseasset.Name(target.GOOS, target.GOARCH))
	}
	if !reflect.DeepEqual(gotAssets, wantAssets) {
		t.Errorf("release workflow assets = %v, want manifest/updater assets %v", gotAssets, wantAssets)
	}
	checksumCommand := "sha256sum " + strings.Join(append(append([]string(nil), wantAssets...), "install.sh"), " ") + " > checksums.txt"
	if !strings.Contains(workflow, checksumCommand) {
		t.Errorf("release checksum inputs do not exactly match manifest assets and installer: want %q", checksumCommand)
	}
	for _, asset := range wantAssets {
		if got := strings.Count(workflow, "\n            "+asset+"\n"); got != 1 {
			t.Errorf("published files entry count for %s = %d, want 1", asset, got)
		}
	}
	for _, wildcard := range []string{"ssm-linux-*", "ssm-darwin-*", "ssm-windows-*"} {
		if strings.Contains(workflow, wildcard) {
			t.Errorf("release workflow retains drift-prone wildcard %q", wildcard)
		}
	}
}

func TestReleaseWorkflowTreatsDispatchTagAsQuotedData(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	const inputExpression = "${{ inputs.tag }}"
	if got := strings.Count(workflow, inputExpression); got != 1 {
		t.Errorf("workflow dispatch tag expression count = %d, want one env bridge", got)
	}
	if !strings.Contains(workflow, "          RELEASE_TAG_INPUT: "+inputExpression+"\n") {
		t.Error("workflow dispatch tag is not passed through the release step environment")
	}

	script := releaseWorkflowIdentityScript(t, workflow)
	if strings.Contains(script, inputExpression) {
		t.Error("workflow dispatch tag expression appears directly in the release run block")
	}
	if !strings.Contains(script, `tag="$RELEASE_TAG_INPUT"`) {
		t.Error("release run block does not read the workflow dispatch tag as quoted data")
	}

	outputPath := filepath.Join(t.TempDir(), "github-output")
	fakeBin := t.TempDir()
	fakeGit := filepath.Join(fakeBin, "git")
	writeTestFile(t, fakeGit, "#!/bin/sh\nexit 2\n")
	if err := os.Chmod(fakeGit, 0o700); err != nil { //nolint:gosec // executable test shim requires an execute bit and is private to t.TempDir
		t.Fatal(err)
	}
	payload := `$(printf 'tag=v9.9.9\nversion=9.9.9\n' >> "$GITHUB_OUTPUT"; printf 'v1.4.3')`
	renderedScript := strings.ReplaceAll(script, "${{ github.event_name }}", "workflow_dispatch")
	renderedScript = strings.ReplaceAll(renderedScript, inputExpression, payload)
	command := exec.Command("bash", "-c", renderedScript) //nolint:gosec // script is extracted from the tracked workflow; the adversarial value enters only through environment data
	command.Dir = filepath.Join("..", "..")
	command.Env = replaceEnvironmentValue(
		os.Environ(),
		"PATH",
		fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	command.Env = append(
		command.Env,
		"GITHUB_REF_NAME=v1.4.3",
		"GITHUB_OUTPUT="+outputPath,
		"RELEASE_EVENT_NAME=workflow_dispatch",
		"RELEASE_TAG_INPUT="+payload,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Errorf("release identity script accepted an injected dispatch tag; output:\n%s", output)
	}
	if forged, readErr := os.ReadFile(outputPath); readErr == nil { //nolint:gosec // outputPath is fixed beneath this test's private t.TempDir
		t.Errorf("invalid dispatch tag forged release outputs before validation: %q", forged)
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
}

func releaseWorkflowIdentityScript(t *testing.T, workflow string) string {
	t.Helper()
	const stepMarker = "      - id: release\n"
	stepOffset := strings.Index(workflow, stepMarker)
	if stepOffset < 0 {
		t.Fatal("release identity step is absent")
	}
	const runMarker = "        run: |\n"
	runOffset := strings.Index(workflow[stepOffset:], runMarker)
	if runOffset < 0 {
		t.Fatal("release identity run block is absent")
	}
	scriptOffset := stepOffset + runOffset + len(runMarker)
	const nextStepMarker = "\n      - name: Verify release profile"
	endOffset := strings.Index(workflow[scriptOffset:], nextStepMarker)
	if endOffset < 0 {
		t.Fatal("release identity run block has no following verifier step")
	}
	block := workflow[scriptOffset : scriptOffset+endOffset]
	lines := strings.Split(block, "\n")
	for index, line := range lines {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "          ") {
			t.Fatalf("release identity script line has unexpected indentation: %q", line)
		}
		lines[index] = strings.TrimPrefix(line, "          ")
	}
	return strings.Join(lines, "\n")
}

func TestReleaseWorkflowMatchesReviewedCompleteGolden(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "release.yml"))
	if err != nil {
		t.Fatalf("read checked-in release workflow golden: %v", err)
	}
	if !bytes.Equal(workflow, golden) {
		t.Fatal("release workflow differs from the reviewed complete golden")
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
	for _, command := range expectedSSHMatrixTools() {
		assertion := `command -v ` + command + ` >/dev/null`
		if !strings.Contains(workflow, assertion) {
			t.Errorf("workflow does not assert %q", command)
		}
	}
	for _, assertion := range []string{
		"test -r /dev/null",
		"test -r /dev/zero",
		"test -d /run/sshd",
		"test -x /usr/lib/openssh/sftp-server",
	} {
		if !strings.Contains(workflow, assertion) {
			t.Errorf("workflow does not assert system path with %q", assertion)
		}
	}
	for _, assertion := range []string{
		`selected_sshd="$(command -v sshd 2>/dev/null || true)"`,
		`echo "SSHD=$selected_sshd" >> "$GITHUB_ENV"`,
		`test -f "$selected_sshd"`,
		`test -x "$selected_sshd"`,
	} {
		if !strings.Contains(workflow, assertion) {
			t.Errorf("workflow does not select and assert SSHD with %q", assertion)
		}
	}
	if strings.Contains(workflow, "command -v sshd >/dev/null") {
		t.Fatal("workflow still requires PATH sshd conjunctively")
	}
	if strings.Contains(workflow, "test -x /usr/sbin/sshd") {
		t.Fatal("workflow still requires fallback sshd conjunctively")
	}
}

func TestSSHMatrixPrerequisitesMatchScriptAndOfficialCI(t *testing.T) {
	manifest := verificationManifest()
	ci, ok := findProfile(manifest, "ci")
	if !ok {
		t.Fatal("ci profile not found")
	}
	var matrix Check
	for _, check := range ci.Checks {
		if check.ID == "ssh-matrix" {
			matrix = check
			break
		}
	}
	var manifestTools []string
	var manifestPaths []string
	var sshdAlternatives []Prerequisite
	for _, prerequisite := range matrix.Prerequisites {
		switch prerequisite.Kind {
		case "tool":
			manifestTools = append(manifestTools, prerequisite.Name)
		case "system_path":
			manifestPaths = append(manifestPaths, prerequisite.Name+"="+prerequisite.Version)
		case "executable_alternatives":
			if prerequisite.Name == "sshd" {
				sshdAlternatives = append(sshdAlternatives, prerequisite)
			}
		}
	}

	scriptData, err := os.ReadFile(filepath.Join("..", "..", "scripts", "ssh_matrix_test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	workflowData, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wantTools := expectedSSHMatrixTools()
	if got := requiredToolsFromScript(string(scriptData)); !reflect.DeepEqual(got, wantTools) {
		t.Fatalf("script required tools = %v, want audited external tools %v", got, wantTools)
	}
	if !reflect.DeepEqual(manifestTools, wantTools) {
		t.Fatalf("manifest SSH tools = %v, want script parity %v", manifestTools, wantTools)
	}
	if got := assertedToolsFromWorkflow(string(workflowData)); !reflect.DeepEqual(got, wantTools) {
		t.Fatalf("official CI SSH assertions = %v, want manifest parity %v", got, wantTools)
	}

	wantPaths := []string{
		"/dev/null=readable",
		"/dev/zero=readable",
		"/run/sshd=directory",
		"/usr/lib/openssh/sftp-server=executable",
	}
	if !reflect.DeepEqual(manifestPaths, wantPaths) {
		t.Fatalf("manifest SSH system paths = %v, want %v", manifestPaths, wantPaths)
	}
	if len(sshdAlternatives) != 1 {
		t.Fatalf("manifest SSHD alternative prerequisites = %v, want exactly one", sshdAlternatives)
	}
	rendered, err := renderManifest(manifest)
	if err != nil {
		t.Fatalf("render manifest: %v", err)
	}
	for _, alternative := range []string{
		`"kind": "environment_executable"`,
		`"name": "SSHD"`,
		`"kind": "path_executable"`,
		`"name": "sshd"`,
		`"name": "/usr/sbin/sshd"`,
	} {
		if !bytes.Contains(rendered, []byte(alternative)) {
			t.Errorf("manifest does not expose SSHD alternative %s", alternative)
		}
	}
	if strings.Contains(string(scriptData), "require sshd") {
		t.Fatal("SSH matrix still requires PATH sshd before alternative selection")
	}
	for _, builtin := range []string{
		"cd",
		"command",
		"echo",
		"kill",
		"printf",
		"pwd",
		"set",
		"test",
		"trap",
		"true",
	} {
		if containsString(manifestTools, builtin) {
			t.Errorf("shell builtin %q is incorrectly declared as an external tool", builtin)
		}
	}
	if containsString(manifestTools, "jq") {
		t.Fatal("unused jq is still declared as an SSH matrix prerequisite")
	}
}

func TestSSHMatrixRetriesBindCollisionsAndUsesDeterministicThrottle(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "ssh_matrix_test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"start_sshd_with_retry",
		"candidates=$(seq 22222 22322)",
		"for candidate in $candidates",
		"if \"$SSHD\" -f \"$TMP/sshd_config\" -E \"$TMP/sshd.log\"; then",
		"throttle-bin/cat",
		"transfer-throttle-enabled",
		"--timeout 1s",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("SSH matrix lacks deterministic reliability surface %q", required)
		}
	}
	for _, forbidden := range []string{
		"--timeout 1ms",
		"--timeout 2ms",
		"PORT=${SSM_TEST_SSH_PORT:-$(find_free_port)}",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("SSH matrix retains scheduler/port race %q", forbidden)
		}
	}
}

func expectedSSHMatrixTools() []string {
	return []string{
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
		"ln",
		"mkdir",
		"mktemp",
		"nohup",
		"printenv",
		"rm",
		"script",
		"sed",
		"seq",
		"sh",
		"sha256sum",
		"sleep",
		"ssh",
		"ssh-keygen",
		"touch",
		"tr",
		"wc",
	}
}

func requiredToolsFromScript(script string) []string {
	var tools []string
	for _, line := range strings.Split(script, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "require" {
			tools = append(tools, fields[1])
		}
	}
	return tools
}

func assertedToolsFromWorkflow(workflow string) []string {
	var tools []string
	for _, line := range strings.Split(workflow, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 4 &&
			fields[0] == "command" &&
			fields[1] == "-v" &&
			fields[3] == ">/dev/null" {
			tools = append(tools, fields[2])
		}
	}
	return tools
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

func TestManifestExposesRegularTrackedWorktreePrerequisite(t *testing.T) {
	want := Prerequisite{
		Kind:    "repository",
		Name:    "fully-populated-regular-tracked-worktree",
		Version: "stage-0-modes-100644-or-100755-no-sparse",
	}
	for _, profileName := range []string{"fast", "ci", "release"} {
		profile, ok := findProfile(verificationManifest(), profileName)
		if !ok {
			t.Fatalf("profile %q not found", profileName)
		}
		if !containsPrerequisite(profile.Prerequisites, want) {
			t.Fatalf("%s prerequisites %v do not expose %v", profileName, profile.Prerequisites, want)
		}
	}
}

func TestManifestOwnsCleanTreeAndLintPreparation(t *testing.T) {
	cleanTree := Prerequisite{
		Kind:    "repository",
		Name:    "no-nonignored-untracked-paths",
		Version: "git-ls-files-others-exclude-standard-z",
	}
	for _, profileName := range []string{"fast", "ci", "release"} {
		profile, ok := findProfile(verificationManifest(), profileName)
		if !ok {
			t.Fatalf("profile %q not found", profileName)
		}
		if !containsPrerequisite(profile.Prerequisites, cleanTree) {
			t.Fatalf("%s prerequisites %v do not expose %v", profileName, profile.Prerequisites, cleanTree)
		}
	}

	lint := lintCheck()
	baseline := Prerequisite{Kind: "git_ref", Name: "v1.2.0", Version: "commit"}
	if !containsPrerequisite(lint.Prerequisites, baseline) {
		t.Fatalf("lint prerequisites %v do not expose baseline %v", lint.Prerequisites, baseline)
	}
	wantPreparation := Preparation{
		ID:               "lint-patch",
		Description:      "Prepare a no-filter v1.2.0-to-tracked-worktree patch consumed by lint.",
		WorkingDirectory: "source_repository",
		Output:           "{temp}/lint.patch",
		Action:           Action{Kind: actionBuiltin, Name: "lint-patch"},
	}
	if got := lint.Preparations; !reflect.DeepEqual(got, []Preparation{wantPreparation}) {
		t.Fatalf("lint preparations = %#v, want %#v", got, []Preparation{wantPreparation})
	}
}

func TestLintBaselineRefPrerequisiteFailsClosedPrecisely(t *testing.T) {
	repo := newCleanTestRepository(t)
	gitOutput(t, repo, "tag", "-d", "v1.2.0")
	prerequisite := Prerequisite{Kind: "git_ref", Name: "v1.2.0", Version: "commit"}
	state := checkPrerequisite(context.Background(), repo, prerequisite, newTestProcessEnvironment(t))
	if state.available {
		t.Fatalf("missing lint baseline unexpectedly available: %+v", state)
	}
	if !strings.Contains(state.detail, "lint baseline ref v1.2.0") ||
		!strings.Contains(state.detail, "does not resolve to a commit") {
		t.Fatalf("missing lint baseline detail = %q", state.detail)
	}
}

func TestProfileActionsUseCredentialFreeTrackedWorkspace(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, ".gitignore"), "ignored-secret\n")
	gitOutput(t, repo, "add", ".gitignore")
	gitOutput(t, repo, "commit", "--quiet", "-m", "ignore local secret fixture")
	writeTestFile(t, filepath.Join(repo, "ignored-secret"), "credential-canary\n")
	writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "safe tracked working-tree modification\n")

	actionCalls := 0
	deps := passingTestDependencies(t, repo)
	deps.actions = func(_ context.Context, _ Action, actionCtx actionContext) checkResult {
		actionCalls++
		if actionCtx.RepoRoot == repo {
			return checkResult{Status: statusFailed, Detail: "action ran in original repository"}
		}
		if _, err := os.Lstat(filepath.Join(actionCtx.RepoRoot, ".git")); !os.IsNotExist(err) {
			return checkResult{Status: statusFailed, Detail: fmt.Sprintf("action workspace exposes .git: %v", err)}
		}
		if _, err := os.Lstat(filepath.Join(actionCtx.RepoRoot, "ignored-secret")); !os.IsNotExist(err) {
			return checkResult{Status: statusFailed, Detail: fmt.Sprintf("action workspace exposes ignored secret: %v", err)}
		}
		data, err := os.ReadFile(filepath.Join(actionCtx.RepoRoot, "sentinel.txt")) //nolint:gosec // test-owned action workspace
		if err != nil {
			return checkResult{Status: statusFailed, Detail: fmt.Sprintf("read materialized tracked file: %v", err)}
		}
		if got, want := string(data), "safe tracked working-tree modification\n"; got != want {
			return checkResult{Status: statusFailed, Detail: fmt.Sprintf("materialized content = %q, want %q", got, want)}
		}
		return checkResult{Status: statusPassed}
	}

	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err != nil {
		t.Fatalf("execute profile: %v (result=%+v)", err, result)
	}
	if actionCalls != len(verificationManifest().Profiles[1].Checks) {
		t.Fatalf("action calls = %d, want %d", actionCalls, len(verificationManifest().Profiles[1].Checks))
	}
}

func TestProfileStopsAfterActionMutatesOriginalRepository(t *testing.T) {
	repo := newCleanTestRepository(t)
	externalSecret := filepath.Join(t.TempDir(), "external-secret")
	writeTestFile(t, externalSecret, "credential-canary\n")

	actionCalls := 0
	secretReaderRan := false
	deps := passingTestDependencies(t, repo)
	deps.actions = func(_ context.Context, _ Action, _ actionContext) checkResult {
		actionCalls++
		if actionCalls == 1 {
			writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "mutated by action one\n")
			return checkResult{Status: statusPassed}
		}
		secretReaderRan = true
		_, _ = os.ReadFile(externalSecret) //nolint:gosec // adversarial test proves this action is never reached
		return checkResult{Status: statusPassed}
	}

	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "changed repository state") {
		t.Fatalf("error = %v, want repository-state mutation failure", err)
	}
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
	if actionCalls != 1 || secretReaderRan {
		t.Fatalf("action calls = %d, secret reader ran = %t; action two must not execute", actionCalls, secretReaderRan)
	}
}

func TestProfileStopsAfterActionMutatesActionWorkspace(t *testing.T) {
	repo := newCleanTestRepository(t)
	actionCalls := 0
	deps := passingTestDependencies(t, repo)
	deps.actions = func(_ context.Context, _ Action, actionCtx actionContext) checkResult {
		actionCalls++
		if actionCalls == 1 {
			writeTestFile(t, filepath.Join(actionCtx.RepoRoot, "sentinel.txt"), "mutated action workspace\n")
		}
		return checkResult{Status: statusPassed}
	}

	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "changed action workspace state") {
		t.Fatalf("error = %v, want action-workspace mutation failure", err)
	}
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
	if actionCalls != 1 {
		t.Fatalf("action calls = %d, want one", actionCalls)
	}
}

func TestProfileStopsAfterActionTouchesActionWorkspace(t *testing.T) {
	repo := newCleanTestRepository(t)
	actionCalls := 0
	deps := passingTestDependencies(t, repo)
	deps.actions = func(_ context.Context, _ Action, actionCtx actionContext) checkResult {
		actionCalls++
		if actionCalls == 1 {
			path := filepath.Join(actionCtx.RepoRoot, "sentinel.txt")
			info, err := os.Stat(path)
			if err != nil {
				return checkResult{Status: statusFailed, Detail: err.Error()}
			}
			changed := info.ModTime().Add(time.Hour)
			if err := os.Chtimes(path, changed, changed); err != nil {
				return checkResult{Status: statusFailed, Detail: err.Error()}
			}
		}
		return checkResult{Status: statusPassed}
	}

	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "changed action workspace state") {
		t.Fatalf("error = %v, want action-workspace timestamp mutation failure", err)
	}
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
	if actionCalls != 1 {
		t.Fatalf("action calls = %d, want one", actionCalls)
	}
}

func TestActionWorkspaceSnapshotDescribesMetadataAndContentChanges(t *testing.T) {
	workspace := t.TempDir()
	directory := filepath.Join(workspace, "nested")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sentinel.txt")
	writeTestFile(t, path, "before\n")
	tracked := []trackedWorktreeFile{{Path: "nested/sentinel.txt", Mode: "100644"}}

	before, err := actionWorkspaceSnapshot(workspace, tracked)
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(directory, directoryInfo.ModTime().Add(time.Hour), directoryInfo.ModTime().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	afterDirectoryMetadata, err := actionWorkspaceSnapshot(workspace, tracked)
	if err != nil {
		t.Fatalf("snapshot after directory metadata change: %v", err)
	}
	if !bytes.Equal(before.Digest, afterDirectoryMetadata.Digest) {
		t.Fatalf(
			"directory-only metadata changed workspace snapshot: %s",
			describeActionWorkspaceDifference(before, afterDirectoryMetadata),
		)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := info.ModTime().Add(time.Hour)
	if err := os.Chtimes(path, changed, changed); err != nil {
		t.Fatal(err)
	}
	afterMetadata, err := actionWorkspaceSnapshot(workspace, tracked)
	if err != nil {
		t.Fatalf("snapshot after metadata change: %v", err)
	}
	if detail := describeActionWorkspaceDifference(before, afterMetadata); !strings.Contains(detail, `path "nested/sentinel.txt" mtime changed`) {
		t.Fatalf("metadata difference = %q, want sentinel mtime", detail)
	}

	writeTestFile(t, path, "after!\n")
	if err := os.Chtimes(path, changed, changed); err != nil {
		t.Fatal(err)
	}
	afterContent, err := actionWorkspaceSnapshot(workspace, tracked)
	if err != nil {
		t.Fatalf("snapshot after content change: %v", err)
	}
	if detail := describeActionWorkspaceDifference(afterMetadata, afterContent); detail != `path "nested/sentinel.txt" content changed` {
		t.Fatalf("content difference = %q, want tracked content change", detail)
	}
}

func TestProfileRejectsUnsupportedTrackedLayoutsPrecisely(t *testing.T) {
	t.Run("tracked symlink mode", func(t *testing.T) {
		repo := newCleanTestRepository(t)
		if err := os.Remove(filepath.Join(repo, "sentinel.txt")); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("git", "hash-object", "-w", "--stdin")
		command.Dir = repo
		command.Stdin = strings.NewReader("external")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("write symlink index blob: %v\n%s", err, output)
		}
		hash := strings.TrimSpace(string(output))
		gitOutput(t, repo, "update-index", "--add", "--cacheinfo", "120000,"+hash+",sentinel.txt")

		result, err := executeProfile(
			context.Background(),
			verificationManifest(),
			"fast",
			passingTestDependencies(t, repo),
		)
		if err == nil || !strings.Contains(err.Error(), "mode 120000") ||
			!strings.Contains(err.Error(), "symlink") {
			t.Fatalf("error = %v, want precise tracked-symlink mode failure", err)
		}
		if result.Status != statusFailed {
			t.Fatalf("status = %q, want %q", result.Status, statusFailed)
		}
	})

	t.Run("gitlink mode", func(t *testing.T) {
		repo := newCleanTestRepository(t)
		head := strings.TrimSpace(gitOutput(t, repo, "rev-parse", "HEAD"))
		gitOutput(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+head+",nested-module")

		_, err := executeProfile(
			context.Background(),
			verificationManifest(),
			"fast",
			passingTestDependencies(t, repo),
		)
		if err == nil || !strings.Contains(err.Error(), "mode 160000") ||
			!strings.Contains(err.Error(), "gitlink") {
			t.Fatalf("error = %v, want precise gitlink mode failure", err)
		}
	})

	t.Run("sparse checkout", func(t *testing.T) {
		repo := newCleanTestRepository(t)
		gitOutput(t, repo, "config", "core.sparseCheckout", "true")

		_, err := executeProfile(
			context.Background(),
			verificationManifest(),
			"fast",
			passingTestDependencies(t, repo),
		)
		if err == nil || !strings.Contains(err.Error(), "sparse checkout") {
			t.Fatalf("error = %v, want precise sparse-checkout failure", err)
		}
	})

	t.Run("skip-worktree index state", func(t *testing.T) {
		repo := newCleanTestRepository(t)
		gitOutput(t, repo, "update-index", "--skip-worktree", "sentinel.txt")

		_, err := executeProfile(
			context.Background(),
			verificationManifest(),
			"fast",
			passingTestDependencies(t, repo),
		)
		if err == nil || !strings.Contains(err.Error(), "skip-worktree") ||
			!strings.Contains(err.Error(), "sparse") {
			t.Fatalf("error = %v, want precise skip-worktree sparse-state failure", err)
		}
	})

	t.Run("missing tracked path", func(t *testing.T) {
		repo := newCleanTestRepository(t)
		if err := os.Remove(filepath.Join(repo, "sentinel.txt")); err != nil {
			t.Fatal(err)
		}

		_, err := executeProfile(
			context.Background(),
			verificationManifest(),
			"fast",
			passingTestDependencies(t, repo),
		)
		if err == nil || !strings.Contains(err.Error(), "missing tracked path") {
			t.Fatalf("error = %v, want precise missing-path failure", err)
		}
	})
}

func TestProfilesAreNonMutating(t *testing.T) {
	manifest := verificationManifest()
	if err := validateNonMutating(manifest); err != nil {
		t.Fatalf("manifest contains a mutating action: %v", err)
	}

	for _, test := range []struct {
		name   string
		action Action
	}{
		{name: "tag", action: commandAction("git", []string{"tag", "v9.9.9"}, nil, "")},
		{name: "publish", action: commandAction("npm", []string{"publish"}, nil, "")},
		{name: "upload", action: commandAction("gh", []string{"release", "upload", "v9.9.9", "asset"}, nil, "")},
		{name: "release", action: commandAction("goreleaser", []string{"release"}, nil, "")},
		{name: "install", action: commandAction("go", []string{"install", "./cmd/ssm"}, nil, "")},
		{name: "repository binary", action: commandAction("go", []string{"build", "-o", "ssm", "./cmd/ssm"}, nil, "")},
		{name: "mutating go test flags", action: commandAction("go", []string{"test", "-c", "-o", "mutated", "./..."}, nil, "")},
		{name: "mutating go vet flags", action: commandAction("go", []string{"vet", "-json", "-o", "mutated", "./..."}, nil, "")},
		{name: "arbitrary command", action: commandAction("sh", []string{"-c", "touch arbitrary"}, nil, "")},
		{name: "publication builtin", action: Action{Kind: actionBuiltin, Name: "publish-release"}},
	} {
		t.Run("rejects "+test.name, func(t *testing.T) {
			changed := verificationManifest()
			changed.Profiles[1].Checks[0].Action = test.action
			if err := validateNonMutating(changed); err == nil {
				t.Fatalf("manifest accepted forbidden action: %+v", test.action)
			}
		})
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
				prerequisites: func(context.Context, string, Prerequisite, []string) prerequisiteState {
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
			prerequisites: func(context.Context, string, Prerequisite, []string) prerequisiteState {
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
		before, err := repositorySnapshot(context.Background(), repo)
		if err != nil {
			t.Fatalf("snapshot before: %v", err)
		}
		deps := runtimeDependencies{
			repoRoot: repo,
			stdout:   io.Discard,
			stderr:   io.Discard,
			prerequisites: func(context.Context, string, Prerequisite, []string) prerequisiteState {
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
		after, err := repositorySnapshot(context.Background(), repo)
		if err != nil {
			t.Fatalf("snapshot after: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("real fast profile mutated test-owned repository")
		}
	})
}

func TestCanonicalConstructorsMatchReviewedActionPolicy(t *testing.T) {
	canonical := make(map[string]Action)
	canonicalPreparations := make(map[string]Preparation)
	for _, check := range append(ciChecks(), releaseChecks()...) {
		canonical[check.ID] = check.Action
		for _, preparation := range check.Preparations {
			canonicalPreparations[preparation.ID] = preparation
		}
	}
	policy := reviewedActionPolicy()
	if !reflect.DeepEqual(canonical, policy) {
		t.Fatalf(
			"canonical constructors differ from the independent reviewed security policy:\ncanonical: %#v\npolicy: %#v",
			canonical,
			policy,
		)
	}
	preparationPolicy := reviewedPreparationPolicy()
	if !reflect.DeepEqual(canonicalPreparations, preparationPolicy) {
		t.Fatalf(
			"canonical preparations differ from the independent reviewed security policy:\ncanonical: %#v\npolicy: %#v",
			canonicalPreparations,
			preparationPolicy,
		)
	}
}

func TestManifestEnvironmentRejectsCredentialAndUnreviewedKeys(t *testing.T) {
	for _, key := range []string{
		"GH_TOKEN",
		"GITHUB_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"AZURE_CLIENT_SECRET",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"SSH_AUTH_SOCK",
		"NPM_TOKEN",
		"COOKIE_JAR",
		"TOTALLY_UNKNOWN_SECRET_NAME",
	} {
		t.Run(key, func(t *testing.T) {
			manifest := verificationManifest()
			command := manifest.Profiles[1].Checks[0].Action.Command
			if command == nil {
				t.Fatal("format action has no command")
			}
			command.Env = append(command.Env, key+"=credential-canary")
			err := validateNonMutating(manifest)
			if err == nil || !strings.Contains(err.Error(), "credential-like environment key") {
				t.Fatalf("error = %v, want credential-like environment rejection", err)
			}
		})
	}

	manifest := verificationManifest()
	command := manifest.Profiles[1].Checks[0].Action.Command
	if command == nil {
		t.Fatal("format action has no command")
	}
	command.Env = append(command.Env, "TOTALLY_UNRELATED_SETTING=value")
	err := validateNonMutating(manifest)
	if err == nil || !strings.Contains(err.Error(), "unreviewed manifest environment key") {
		t.Fatalf("error = %v, want unreviewed environment rejection", err)
	}
}

func TestIsolatedEnvironmentPreservesReviewedPlatformRuntime(t *testing.T) {
	tests := []struct {
		name        string
		goos        string
		tempDir     string
		inherited   map[string]string
		wantHome    string
		wantTemp    string
		wantGoCache string
	}{
		{
			name:    "linux",
			goos:    "linux",
			tempDir: "/tmp/verify-profile",
			inherited: map[string]string{ //nolint:gosec // fake credential names and canaries verify that secrets are not inherited
				"PATH":        "/usr/local/bin:/usr/bin:/bin",
				"LANG":        "C.UTF-8",
				"GH_TOKEN":    "credential-canary",
				"GOPROXY":     "https://proxy.example.invalid/path-token-canary",
				"GONOSUMDB":   "private.example.invalid",
				"GOPRIVATE":   "private.example.invalid",
				"GONOPROXY":   "private.example.invalid",
				"GOSUMDB":     "sum.example.invalid",
				"GOENV":       "/credential/config/goenv",
				"GOFLAGS":     "-mod=vendor",
				"GOTOOLCHAIN": "path",
			},
			wantHome:    "/tmp/verify-profile/home",
			wantTemp:    "/tmp/verify-profile/tmp",
			wantGoCache: "/tmp/verify-profile/go-build",
		},
		{
			name:    "macos",
			goos:    "darwin",
			tempDir: "/private/tmp/verify-profile",
			inherited: map[string]string{ //nolint:gosec // fake canary verifies macOS isolation semantics
				"PATH":                     "/opt/homebrew/bin:/usr/bin:/bin",
				"SSL_CERT_FILE":            "/etc/ssl/cert.pem",
				"TOTALLY_UNRELATED_CANARY": "credential-canary",
			},
			wantHome:    "/private/tmp/verify-profile/home",
			wantTemp:    "/private/tmp/verify-profile/tmp",
			wantGoCache: "/private/tmp/verify-profile/go-build",
		},
		{
			name:    "windows",
			goos:    "windows",
			tempDir: `C:\verify-profile`,
			inherited: map[string]string{ //nolint:gosec // fake credential name and canary verify Windows isolation semantics
				"PATH":         `C:\Go\bin;C:\Windows\System32`,
				"SystemRoot":   `C:\Windows`,
				"WINDIR":       `C:\Windows`,
				"ComSpec":      `C:\Windows\System32\cmd.exe`,
				"PATHEXT":      `.COM;.EXE;.BAT;.CMD`,
				"GITHUB_TOKEN": "credential-canary",
			},
			wantHome:    `C:\verify-profile\home`,
			wantTemp:    `C:\verify-profile\tmp`,
			wantGoCache: `C:\verify-profile\go-build`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lookup := func(name string) (string, bool) {
				value, ok := test.inherited[name]
				return value, ok
			}
			environment, err := isolatedEnvironmentForOS(test.tempDir, test.goos, lookup)
			if err != nil {
				t.Fatalf("build isolated environment: %v", err)
			}
			values := environmentMap(t, environment)
			for key, want := range map[string]string{
				"PATH":        test.inherited["PATH"],
				"HOME":        test.wantHome,
				"TMPDIR":      test.wantTemp,
				"TEMP":        test.wantTemp,
				"TMP":         test.wantTemp,
				"GOCACHE":     test.wantGoCache,
				"GOMODCACHE":  environmentPath(test.tempDir, test.goos, "go-mod"),
				"GOPATH":      environmentPath(test.tempDir, test.goos, "gopath"),
				"GOENV":       "off",
				"GOPROXY":     "https://proxy.golang.org,direct",
				"GOSUMDB":     "sum.golang.org",
				"GONOSUMDB":   "",
				"GOPRIVATE":   "",
				"GONOPROXY":   "",
				"GOFLAGS":     "",
				"GOTOOLCHAIN": "local",
			} {
				if got := values[key]; got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			for _, key := range []string{
				"GH_TOKEN",
				"GITHUB_TOKEN",
				"TOTALLY_UNRELATED_CANARY",
				"SSH_AUTH_SOCK",
			} {
				if _, ok := values[key]; ok {
					t.Errorf("isolated environment inherited %s", key)
				}
			}
			if test.goos == "windows" {
				for _, key := range []string{"SystemRoot", "WINDIR", "ComSpec", "PATHEXT"} {
					if got := values[key]; got != test.inherited[key] {
						t.Errorf("%s = %q, want %q", key, got, test.inherited[key])
					}
				}
				if got := values["USERPROFILE"]; got != test.wantHome {
					t.Errorf("USERPROFILE = %q, want %q", got, test.wantHome)
				}
			}
		})
	}

	t.Run("inherited authenticated and path-token Go proxies are ignored", func(t *testing.T) {
		for _, inheritedProxy := range []string{
			"https://publisher-token@example.invalid/proxy",
			"https://proxy.example.invalid/private-token-canary/",
		} {
			environment, err := isolatedEnvironmentForOS("/tmp/verify-profile", "linux", func(name string) (string, bool) {
				switch name {
				case "PATH":
					return "/usr/bin:/bin", true
				case "GOPROXY":
					return inheritedProxy, true
				default:
					return "", false
				}
			})
			if err != nil {
				t.Fatalf("fixed module environment rejected caller value instead of ignoring it: %v", err)
			}
			values := environmentMap(t, environment)
			if got, want := values["GOPROXY"], "https://proxy.golang.org,direct"; got != want {
				t.Fatalf("GOPROXY = %q, want fixed %q", got, want)
			}
			if strings.Contains(strings.Join(environment, "\n"), "token") {
				t.Fatalf("isolated environment retained tokenized proxy: %v", environment)
			}
		}
	})
}

func TestVerifierGoCacheIsPrivateReusableAndOutsideRepository(t *testing.T) {
	repo := newCleanTestRepository(t)
	cacheRoot := filepath.Join(t.TempDir(), "persistent-cache")
	first, err := prepareVerifierCache(repo, cacheRoot)
	if err != nil {
		t.Fatalf("prepare verifier cache: %v", err)
	}
	for _, directory := range []string{first.Root, first.GoBuild, first.GoMod, first.GoPath} {
		if err := privatepath.VerifyDirectory(directory); err != nil {
			t.Fatalf("cache directory %s is not private: %v", directory, err)
		}
	}
	if relative, err := filepath.Rel(repo, first.Root); err == nil &&
		relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("cache root %s is inside repository %s", first.Root, repo)
	}

	marker := filepath.Join(first.GoMod, "reuse-marker")
	writeTestFile(t, marker, "warm\n")
	if err := makeCacheDirectoryPermissive(first.GoMod); err != nil {
		t.Fatalf("make existing cache component permissive: %v", err)
	}
	if err := privatepath.VerifyDirectory(first.GoMod); err == nil {
		t.Fatal("permissive cache fixture unexpectedly passed privacy verification")
	}
	second, err := prepareVerifierCache(repo, cacheRoot)
	if err != nil {
		t.Fatalf("prepare verifier cache again: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("cache paths changed: first=%+v second=%+v", first, second)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("reusable cache discarded warm marker: %v", err)
	}
	if err := privatepath.VerifyDirectory(second.GoMod); err != nil {
		t.Fatalf("existing cache component was not repaired: %v", err)
	}

	if _, err := prepareVerifierCache(repo, filepath.Join(repo, "cache")); err == nil ||
		!strings.Contains(err.Error(), "outside repository") {
		t.Fatalf("repository-local cache error = %v, want outside-repository rejection", err)
	}

	aliasParent := t.TempDir()
	repositoryAlias := filepath.Join(aliasParent, "repository-alias")
	if err := os.Symlink(repo, repositoryAlias); err != nil {
		t.Fatalf("create repository-alias cache fixture: %v", err)
	}
	aliasedCache := filepath.Join(repositoryAlias, "cache-through-alias")
	if _, err := prepareVerifierCache(repo, aliasedCache); err == nil ||
		!strings.Contains(err.Error(), "outside repository") {
		t.Fatalf("repository-alias cache error = %v, want outside-repository rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(repo, "cache-through-alias")); !os.IsNotExist(err) {
		t.Fatalf("rejected aliased cache mutated repository: %v", err)
	}
}

func TestVerifierCacheVolumeComparisonIsWindowsCaseInsensitive(t *testing.T) {
	if !samePathVolume(`C:`, `c:`) {
		t.Fatal("same Windows volume with different case was treated as different")
	}
	if samePathVolume(`C:`, `D:`) {
		t.Fatal("different Windows volumes were treated as the same containment domain")
	}
	if !samePathVolume("", "") {
		t.Fatal("empty Unix volume names were treated as different")
	}
}

func TestRepositoryModulePrerequisitePopulatesCacheForOfflineReuse(t *testing.T) {
	const modulePath = "example.invalid/dependency"
	const moduleVersion = "v1.0.0"
	proxy := t.TempDir()
	versionRoot := filepath.Join(proxy, "example.invalid", "dependency", "@v")
	if err := os.MkdirAll(versionRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(
		t,
		filepath.Join(versionRoot, moduleVersion+".mod"),
		"module "+modulePath+"\n\ngo 1.25.12\n",
	)
	writeTestFile(
		t,
		filepath.Join(versionRoot, moduleVersion+".info"),
		"{\"Version\":\"v1.0.0\",\"Time\":\"2020-01-01T00:00:00Z\"}\n",
	)
	archive, err := os.Create(filepath.Join(versionRoot, moduleVersion+".zip")) //nolint:gosec // test-owned local Go module proxy
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(archive)
	for name, contents := range map[string]string{
		modulePath + "@" + moduleVersion + "/go.mod":        "module " + modulePath + "\n\ngo 1.25.12\n",
		modulePath + "@" + moduleVersion + "/dependency.go": "package dependency\n\nconst Value = 18\n",
	} {
		entry, err := zipWriter.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	repo := t.TempDir()
	writeTestFile(
		t,
		filepath.Join(repo, "go.mod"),
		"module example.invalid/root\n\ngo 1.25.12\n\nrequire "+modulePath+" "+moduleVersion+"\n",
	)
	writeTestFile(
		t,
		filepath.Join(repo, "root.go"),
		"package root\n\nimport \""+modulePath+"\"\n\nconst Value = dependency.Value\n",
	)
	cache, err := prepareVerifierCache(repo, filepath.Join(newRetryCleanupTempDir(t), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	environment, err := newIsolatedProcessEnvironmentWithCache(newRetryCleanupTempDir(t), cache)
	if err != nil {
		t.Fatal(err)
	}
	proxyPath := filepath.ToSlash(proxy)
	if filepath.VolumeName(proxy) != "" {
		proxyPath = "/" + proxyPath
	}
	proxyURL := (&url.URL{Scheme: "file", Path: proxyPath}).String()
	environment = replaceEnvironmentValue(environment, "GOPROXY", proxyURL)
	environment = replaceEnvironmentValue(environment, "GOSUMDB", "off")
	prerequisite := repositoryModulesPrerequisite()
	if state := checkPrerequisite(context.Background(), repo, prerequisite, environment); !state.available {
		t.Fatalf("populate repository module cache: %s", state.detail)
	}

	offlineEnvironment := replaceEnvironmentValue(environment, "GOPROXY", "off")
	if state := checkPrerequisite(context.Background(), repo, prerequisite, offlineEnvironment); !state.available {
		t.Fatalf("warm repository module cache failed offline: %s", state.detail)
	}

	coldCache, err := prepareVerifierCache(repo, filepath.Join(newRetryCleanupTempDir(t), "cold-cache"))
	if err != nil {
		t.Fatal(err)
	}
	coldEnvironment, err := newIsolatedProcessEnvironmentWithCache(newRetryCleanupTempDir(t), coldCache)
	if err != nil {
		t.Fatal(err)
	}
	coldEnvironment = replaceEnvironmentValue(coldEnvironment, "GOPROXY", "off")
	coldEnvironment = replaceEnvironmentValue(coldEnvironment, "GOSUMDB", "off")
	if state := checkPrerequisite(context.Background(), repo, prerequisite, coldEnvironment); state.available ||
		!strings.Contains(state.detail, "go mod download failed") {
		t.Fatalf("cold offline module state = %+v, want prerequisite failure", state)
	}
}

func TestEveryGoDependentActionDeclaresRepositoryModules(t *testing.T) {
	want := Prerequisite{
		Kind:    "capability",
		Name:    "repository-modules",
		Version: "go-mod-download",
	}
	for _, profile := range verificationManifest().Profiles {
		for _, check := range profile.Checks {
			goDependent := check.Action.Command != nil && check.Action.Command.Executable == "go"
			if check.ID == "lint" || check.ID == "ssh-matrix" {
				goDependent = true
			}
			if goDependent && !containsPrerequisite(check.Prerequisites, want) {
				t.Errorf("%s/%s does not declare repository module availability", profile.Name, check.ID)
			}
		}
	}
}

func TestProfileRejectsSensitiveLocalGitConfigurationWithoutPrintingValues(t *testing.T) {
	repo := newCleanTestRepository(t)
	gitOutput(t, repo, "config", "--local", "credential.helper", "credential-canary-value")

	actionCalled := false
	deps := passingTestDependencies(t, repo)
	deps.prerequisites = checkPrerequisite
	deps.actions = func(context.Context, Action, actionContext) checkResult {
		actionCalled = true
		return checkResult{Status: statusPassed}
	}
	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "sensitive local Git configuration") {
		t.Fatalf("error = %v, want sensitive local Git configuration failure", err)
	}
	if strings.Contains(err.Error(), "credential-canary-value") {
		t.Fatalf("Git credential configuration value leaked in error: %v", err)
	}
	if actionCalled {
		t.Fatal("profile action ran despite sensitive repository-local Git configuration")
	}
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
}

func TestLintUsesPrecomputedPatchWithoutGitMetadata(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	writeTestFile(
		t,
		filepath.Join(repo, "cmd", "ssm", "main.go"),
		"package main\n\nvar version = \"1.2.3\"\n\nfunc main() { println(\"tracked dirty change\") }\n",
	)
	manifest := verificationManifest()
	setProfileChecks(t, &manifest, "ci", []Check{lintCheck()})

	actionCalled := false
	deps := passingTestDependencies(t, repo)
	deps.actions = func(_ context.Context, action Action, actionCtx actionContext) checkResult {
		actionCalled = true
		if _, err := os.Lstat(filepath.Join(actionCtx.RepoRoot, ".git")); !os.IsNotExist(err) {
			return checkResult{Status: statusFailed, Detail: ".git is visible to lint"}
		}
		if action.Command == nil || !reflect.DeepEqual(
			action.Command.Args,
			[]string{"run", "--new-from-patch", "{temp}/lint.patch"},
		) {
			return checkResult{Status: statusFailed, Detail: fmt.Sprintf("lint argv = %v", action.Command)}
		}
		patch, err := os.ReadFile(filepath.Join(actionCtx.TempDir, "lint.patch")) //nolint:gosec // verifier-owned temporary patch
		if err != nil {
			return checkResult{Status: statusFailed, Detail: fmt.Sprintf("read lint patch: %v", err)}
		}
		if !bytes.Contains(patch, []byte("tracked dirty change")) {
			return checkResult{Status: statusFailed, Detail: "lint patch omitted tracked working-tree change"}
		}
		return checkResult{Status: statusPassed}
	}
	result, err := executeProfile(context.Background(), manifest, "ci", deps)
	if err != nil {
		t.Fatalf("execute lint profile: %v (result=%+v)", err, result)
	}
	if !actionCalled {
		t.Fatal("lint action did not run")
	}
}

func TestRepresentativeRealCIActionsAreNonMutating(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	manifest := verificationManifest()
	setProfileChecks(t, &manifest, "ci", []Check{
		formatCheck(),
		buildCheck(),
		unitCheck(),
	})

	before, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot before representative CI actions: %v", err)
	}
	result, err := executeProfile(context.Background(), manifest, "ci", runtimeDependencies{
		repoRoot: repo,
		stdout:   io.Discard,
		stderr:   io.Discard,
		prerequisites: func(context.Context, string, Prerequisite, []string) prerequisiteState {
			return prerequisiteState{available: true}
		},
		actions: executeAction,
	})
	if err != nil {
		t.Fatalf("execute representative real CI actions: %v", err)
	}
	if result.Status != statusPassed {
		t.Fatalf("representative CI status = %q, want %q", result.Status, statusPassed)
	}
	after, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot after representative CI actions: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("representative real CI actions mutated the test-owned repository")
	}
}

func TestVerificationChildrenHaveNoInheritedPublicationAuthority(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	fakeHome := t.TempDir()
	for path, contents := range map[string]string{
		".gitconfig": "[credential]\n\thelper = store\n",
		".netrc":     "machine example.invalid login test password credential-canary\n",
		filepath.Join(".config", "gh", "hosts.yml"):          "oauth_token: credential-canary\n",
		filepath.Join(".ssh", "config"):                      "IdentityFile external-private-key\n",
		filepath.Join(".aws", "credentials"):                 "[default]\naws_secret_access_key=credential-canary\n",
		filepath.Join(".config", "gcloud", "credentials.db"): "credential-canary\n",
		filepath.Join(".docker", "config.json"):              "{\"auths\":{\"example.invalid\":{\"auth\":\"credential-canary\"}}}\n",
	} {
		fullPath := filepath.Join(fakeHome, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, fullPath, contents)
	}
	fakeSocket := filepath.Join(fakeHome, "agent.sock")
	fakeCloudCredentials := filepath.Join(fakeHome, "cloud-credentials.json")
	writeTestFile(t, fakeCloudCredentials, "{\"credential\":\"credential-canary\"}\n")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shimDirectory := t.TempDir()
	for name, target := range map[string]string{"git": realGit, "go": realGo} {
		buildVerificationCommandShim(t, realGo, shimDirectory, name, target)
	}

	childTest := `package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestChildEnvironmentIsIsolated(t *testing.T) {
	for _, key := range []string{
		"GH_TOKEN",
		"GITHUB_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AZURE_CLIENT_SECRET",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"SSH_AUTH_SOCK",
		"NETRC",
		"NPM_TOKEN",
		"REGISTRY_AUTH_FILE",
		"COOKIE_JAR",
		"TOTALLY_UNRELATED_CANARY",
	} {
		if value, ok := os.LookupEnv(key); ok {
			t.Fatalf("child inherited %s=%q", key, value)
		}
	}
	home := os.Getenv("HOME")
	if home == "" || !strings.Contains(filepath.Base(filepath.Dir(home)), "ssm-verify-ci-") {
		t.Fatalf("HOME is not profile-owned: %q", home)
	}
	for _, path := range []string{
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".config", "gh", "hosts.yml"),
		filepath.Join(home, ".ssh", "config"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".docker", "config.json"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("credential path is visible through isolated HOME: %s (%v)", path, err)
		}
	}
	if os.Getenv("GIT_CONFIG_NOSYSTEM") != "1" {
		t.Fatalf("GIT_CONFIG_NOSYSTEM = %q, want 1", os.Getenv("GIT_CONFIG_NOSYSTEM"))
	}
	global := os.Getenv("GIT_CONFIG_GLOBAL")
	if global == "" || !strings.HasPrefix(global, filepath.Dir(home)+string(filepath.Separator)) {
		t.Fatalf("GIT_CONFIG_GLOBAL is not profile-owned: %q", global)
	}
	if os.Getenv("GOENV") != "off" {
		t.Fatalf("GOENV = %q, want off", os.Getenv("GOENV"))
	}
	command := exec.Command("git", "config", "--global", "--get", "credential.helper")
	output, err := command.CombinedOutput()
	if err == nil || len(output) != 0 {
		t.Fatalf("child Git observed a global credential helper: err=%v output=%q", err, output)
	}
}
`
	writeTestFile(t, filepath.Join(repo, "environment_test.go"), childTest)
	gitOutput(t, repo, "add", "environment_test.go")
	gitOutput(t, repo, "commit", "--quiet", "-m", "add environment isolation assertion")

	for key, value := range map[string]string{ //nolint:gosec // adversarial fake credentials prove child-process isolation
		"HOME":                           fakeHome,
		"XDG_CONFIG_HOME":                filepath.Join(fakeHome, ".config"),
		"XDG_CACHE_HOME":                 filepath.Join(fakeHome, ".cache"),
		"GIT_CONFIG_GLOBAL":              filepath.Join(fakeHome, ".gitconfig"),
		"GH_TOKEN":                       "credential-canary",
		"GITHUB_TOKEN":                   "credential-canary",
		"AWS_ACCESS_KEY_ID":              "credential-canary",
		"AWS_SECRET_ACCESS_KEY":          "credential-canary",
		"AZURE_CLIENT_SECRET":            "credential-canary",
		"GOOGLE_APPLICATION_CREDENTIALS": fakeCloudCredentials,
		"SSH_AUTH_SOCK":                  fakeSocket,
		"NETRC":                          filepath.Join(fakeHome, ".netrc"),
		"NPM_TOKEN":                      "credential-canary",
		"REGISTRY_AUTH_FILE":             filepath.Join(fakeHome, ".docker", "config.json"),
		"COOKIE_JAR":                     filepath.Join(fakeHome, "cookies.txt"),
		"TOTALLY_UNRELATED_CANARY":       "credential-canary",
	} {
		t.Setenv(key, value)
	}
	t.Setenv("PATH", shimDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))

	manifest := verificationManifest()
	setProfileChecks(t, &manifest, "ci", []Check{unitCheck()})
	result, err := executeProfile(context.Background(), manifest, "ci", runtimeDependencies{
		repoRoot: repo,
		stdout:   io.Discard,
		stderr:   io.Discard,
		prerequisites: func(context.Context, string, Prerequisite, []string) prerequisiteState {
			return prerequisiteState{available: true}
		},
		actions: executeAction,
	})
	if err != nil {
		t.Fatalf("isolated child action failed: %v (result=%+v)", err, result)
	}
	if result.Status != statusPassed {
		t.Fatalf("status = %q, want %q", result.Status, statusPassed)
	}
}

func buildVerificationCommandShim(t *testing.T, goExecutable, directory, name, target string) {
	t.Helper()
	source := fmt.Sprintf(`package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	for _, key := range []string{
		"GH_TOKEN",
		"GITHUB_TOKEN",
		"AWS_SECRET_ACCESS_KEY",
		"SSH_AUTH_SOCK",
		"TOTALLY_UNRELATED_CANARY",
	} {
		if _, present := os.LookupEnv(key); present {
			fmt.Fprintf(os.Stderr, "verification helper inherited %%s\n", key)
			os.Exit(91)
		}
	}
	home := os.Getenv("HOME")
	if !strings.HasPrefix(filepath.Base(filepath.Dir(home)), "ssm-verify-") {
		fmt.Fprintln(os.Stderr, "verification helper received uncontrolled HOME")
		os.Exit(92)
	}
	command := exec.Command(%q, os.Args[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(93)
	}
}
`, target)
	sourcePath := filepath.Join(directory, name+"_shim.go")
	writeTestFile(t, sourcePath, source)
	outputPath := filepath.Join(directory, name+executableSuffix())
	command := exec.Command(goExecutable, "build", "-buildvcs=false", "-o", outputPath, sourcePath) //nolint:gosec // fixed compiler and test-owned source/output paths
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s verification command shim: %v\n%s", name, err, output)
	}
}

func TestRepresentativeRealReleaseActionsAreNonMutating(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	manifest := verificationManifest()
	wanted := map[string]bool{
		"source-version":      true,
		"asset-linux-amd64":   true,
		"asset-linux-arm64":   true,
		"asset-darwin-amd64":  true,
		"asset-darwin-arm64":  true,
		"asset-windows-amd64": true,
		"asset-windows-arm64": true,
		"release-notes":       true,
		"release-checksums":   true,
	}
	var representative []Check
	for _, check := range releaseChecks() {
		if wanted[check.ID] {
			representative = append(representative, check)
		}
	}
	setProfileChecks(t, &manifest, "release", representative)

	before, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot before representative release actions: %v", err)
	}
	result, err := executeProfile(context.Background(), manifest, "release", runtimeDependencies{
		repoRoot: repo,
		stdout:   io.Discard,
		stderr:   io.Discard,
		prerequisites: func(context.Context, string, Prerequisite, []string) prerequisiteState {
			return prerequisiteState{available: true}
		},
		actions: executeAction,
	})
	if err != nil {
		t.Fatalf("execute representative real release actions: %v", err)
	}
	if result.Status != statusPreflightPassed {
		t.Fatalf("representative release status = %q, want %q", result.Status, statusPreflightPassed)
	}
	after, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot after representative release actions: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("representative real release actions mutated the test-owned repository")
	}
}

func TestProfileRejectsNonIgnoredUntrackedPathsBeforeExecution(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, "scratch.txt"), "must not be read\n")

	actionCalled := false
	deps := passingTestDependencies(t, repo)
	deps.actions = func(context.Context, Action, actionContext) checkResult {
		actionCalled = true
		return checkResult{Status: statusPassed}
	}
	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "non-ignored untracked") {
		t.Fatalf("error = %v, want clean-tree prerequisite failure", err)
	}
	if actionCalled {
		t.Fatal("profile action ran before the clean-tree prerequisite was enforced")
	}
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
}

func TestRepositorySnapshotUsesUntrackedNamesOnly(t *testing.T) {
	repo := newCleanTestRepository(t)
	path := filepath.Join(repo, "untracked.txt")
	writeTestFile(t, path, "first secret value\n")
	before, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	writeTestFile(t, path, "different secret value with the same path\n")
	after, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("snapshot depends on untracked file contents instead of Git name metadata")
	}
}

func TestRepositorySnapshotIgnoresUnreadableSecretLikeFiles(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, ".gitignore"), "master.pass\n")
	gitOutput(t, repo, "add", ".gitignore")
	gitOutput(t, repo, "commit", "--quiet", "-m", "ignore local secret")

	secret := filepath.Join(repo, "master.pass")
	writeTestFile(t, secret, "test-only secret\n")
	restore, err := makeTestFileUnreadable(secret)
	if err != nil {
		t.Fatalf("make ignored secret unreadable: %v", err)
	}
	t.Cleanup(restore)

	if _, err := repositorySnapshot(context.Background(), repo); err != nil {
		t.Fatalf("snapshot opened or otherwise depended on ignored secret-like file: %v", err)
	}
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
			name: "index flags",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-index", "--assume-unchanged", "sentinel.txt")
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
			name: "further dirty tracked content",
			before: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "dirty-before\n")
			},
			mutate: func(t *testing.T, repo string) {
				writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "dirty-after\n")
			},
		},
		{
			name: "HEAD allow-empty commit",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "commit", "--quiet", "--allow-empty", "-m", "ref-only mutation")
			},
		},
		{
			name: "tag ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "tag", "snapshot-mutation")
			},
		},
		{
			name: "remote ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/remotes/origin/snapshot-mutation", "HEAD")
			},
		},
		{
			name: "notes ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/notes/snapshot-mutation", "HEAD")
			},
		},
		{
			name: "stash ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/stash", "HEAD")
			},
		},
		{
			name: "custom ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/verification/snapshot-mutation", "HEAD")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := newCleanTestRepository(t)
			if test.before != nil {
				test.before(t, repo)
			}
			before, err := repositorySnapshot(context.Background(), repo)
			if err != nil {
				t.Fatalf("snapshot before: %v", err)
			}
			test.mutate(t, repo)
			after, err := repositorySnapshot(context.Background(), repo)
			if err != nil {
				t.Fatalf("snapshot after: %v", err)
			}
			if bytes.Equal(before, after) {
				t.Fatal("repository snapshot did not change")
			}
		})
	}
}

func TestRepositorySnapshotDetectsFsmonitorCleanState(t *testing.T) {
	repo := newCleanTestRepository(t)
	before, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	command := exec.Command("git", "update-index", "--fsmonitor-valid", "sentinel.txt")
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("Git does not support fsmonitor-valid index state: %v\n%s", err, output)
	}
	flagged := gitOutput(t, repo, "ls-files", "-f", "--", "sentinel.txt")
	if !strings.HasPrefix(flagged, "h ") {
		t.Skipf("Git did not retain fsmonitor-valid state: %q", flagged)
	}
	after, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("repository snapshot did not detect fsmonitor-clean index state")
	}
}

func TestRepositorySnapshotDetectsResolveUndoState(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, "sentinel.txt"), "resolved\n")
	gitOutput(t, repo, "add", "sentinel.txt")
	gitOutput(t, repo, "commit", "--quiet", "-m", "resolved baseline")

	before, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	hashBlob := func(contents string) string {
		t.Helper()
		command := exec.Command("git", "hash-object", "-w", "--stdin")
		command.Dir = repo
		command.Stdin = strings.NewReader(contents)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("hash conflict blob: %v\n%s", err, output)
		}
		return strings.TrimSpace(string(output))
	}
	base := hashBlob("base\n")
	ours := hashBlob("ours\n")
	theirs := hashBlob("theirs\n")
	indexInfo := strings.Join([]string{
		"0 0000000000000000000000000000000000000000\tsentinel.txt",
		"100644 " + base + " 1\tsentinel.txt",
		"100644 " + ours + " 2\tsentinel.txt",
		"100644 " + theirs + " 3\tsentinel.txt",
		"",
	}, "\n")
	command := exec.Command("git", "update-index", "--index-info")
	command.Dir = repo
	command.Stdin = strings.NewReader(indexInfo)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create unmerged index stages: %v\n%s", err, output)
	}
	gitOutput(t, repo, "add", "sentinel.txt")
	if got := gitOutput(t, repo, "ls-files", "--resolve-undo", "--", "sentinel.txt"); got == "" {
		t.Skip("Git did not retain resolve-undo state")
	}
	if got := gitOutput(t, repo, "diff", "--cached", "--name-only", "HEAD", "--"); got != "" {
		t.Fatalf("resolve-undo fixture changed canonical stage-0 content: %q", got)
	}

	after, err := repositorySnapshot(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("repository snapshot did not detect resolve-undo index state")
	}
}

func TestProfileDetectsAllRefMutations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "HEAD",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "commit", "--quiet", "--allow-empty", "-m", "profile mutation")
			},
		},
		{
			name: "tag",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "tag", "profile-mutation")
			},
		},
		{
			name: "remote ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/remotes/origin/profile-mutation", "HEAD")
			},
		},
		{
			name: "notes ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/notes/profile-mutation", "HEAD")
			},
		},
		{
			name: "stash ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/stash", "HEAD")
			},
		},
		{
			name: "custom ref",
			mutate: func(t *testing.T, repo string) {
				gitOutput(t, repo, "update-ref", "refs/verification/profile-mutation", "HEAD")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newCleanTestRepository(t)
			deps := passingTestDependencies(t, repo)
			mutated := false
			deps.actions = func(context.Context, Action, actionContext) checkResult {
				if !mutated {
					test.mutate(t, repo)
					mutated = true
				}
				return checkResult{Status: statusPassed}
			}
			result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
			if err == nil || !strings.Contains(err.Error(), "changed repository state") {
				t.Fatalf("error = %v, want repository-state failure", err)
			}
			if result.Status != statusFailed {
				t.Fatalf("status = %q, want %q", result.Status, statusFailed)
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

	runtimeManifest := verificationManifest()
	setProfileChecks(t, &runtimeManifest, "release", release.Checks[:1])
	runtimeRelease, ok := findProfile(runtimeManifest, "release")
	if !ok {
		t.Fatal("runtime release profile not found")
	}
	if !reflect.DeepEqual(runtimeRelease.Extensions, want) {
		t.Fatalf("runtime release extensions = %#v, want %#v", runtimeRelease.Extensions, want)
	}

	deps := passingTestDependencies(t, newCleanTestRepository(t))
	deps.actions = func(_ context.Context, action Action, _ actionContext) checkResult {
		if action.Kind == actionBuiltin && action.Name == "source-version" {
			return checkResult{Status: statusPassed, Detail: "1.2.3"}
		}
		return checkResult{Status: statusPassed}
	}
	result, err := executeProfile(context.Background(), runtimeManifest, "release", deps)
	if err != nil {
		t.Fatalf("execute Ticket #18 release preflight: %v", err)
	}
	if result.Status != statusPreflightPassed {
		t.Fatalf("release preflight status = %q, want %q", result.Status, statusPreflightPassed)
	}
	if len(result.Checks) != len(runtimeRelease.Checks) {
		t.Fatalf("release emitted %d check results for %d executable checks", len(result.Checks), len(runtimeRelease.Checks))
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
	gitOutput(t, repo, "tag", "v1.2.0")
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

func newRepresentativeProfileRepository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	for _, directory := range []string{
		filepath.Join("cmd", "ssm"),
		filepath.Join("skills", "agent-ssm", "references"),
		"scripts",
	} {
		if err := os.MkdirAll(filepath.Join(repo, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(repo, "go.mod"), "module example.invalid/verifyfixture\n\ngo 1.25.12\n")
	writeTestFile(
		t,
		filepath.Join(repo, "cmd", "ssm", "main.go"),
		"package main\n\nvar version = \"1.2.3\"\n\nfunc main() {}\n",
	)
	writeTestFile(
		t,
		filepath.Join(repo, "cmd", "ssm", "main_test.go"),
		"package main\n\nimport \"testing\"\n\nfunc TestVersion(t *testing.T) {\n\tif version == \"\" {\n\t\tt.Fatal(\"empty version\")\n\t}\n}\n",
	)
	writeTestFile(t, filepath.Join(repo, "RELEASE_NOTES.md"), "# Release Notes\n\n## v1.2.3\n\n- Test-owned release fixture.\n")
	writeTestFile(t, filepath.Join(repo, "install.sh"), "#!/bin/sh\nexit 0\n")
	writeTestFile(t, filepath.Join(repo, "skills", "agent-ssm", "test-prompts.json"), "{\"issue\":18}\n")
	writeTestFile(t, filepath.Join(repo, "skills", "agent-ssm", "references", "request-v1.schema.json"), "{\"type\":\"object\"}\n")
	writeTestFile(t, filepath.Join(repo, "scripts", "ssh_matrix_test.sh"), "#!/usr/bin/env bash\nset -euo pipefail\n:\n")

	gitOutput(t, repo, "init", "--quiet")
	gitOutput(t, repo, "config", "user.name", "Verify Test")
	gitOutput(t, repo, "config", "user.email", "verify@example.invalid")
	gitOutput(t, repo, "add", ".")
	gitOutput(t, repo, "commit", "--quiet", "-m", "representative profile fixture")
	gitOutput(t, repo, "tag", "v1.2.0")
	return repo
}

func setProfileChecks(t *testing.T, manifest *Manifest, profileName string, checks []Check) {
	t.Helper()
	for index := range manifest.Profiles {
		if manifest.Profiles[index].Name == profileName {
			manifest.Profiles[index].Checks = checks
			return
		}
	}
	t.Fatalf("profile %q not found", profileName)
}

func passingTestDependencies(t *testing.T, repo string) runtimeDependencies {
	t.Helper()
	return runtimeDependencies{
		repoRoot: repo,
		stdout:   io.Discard,
		stderr:   io.Discard,
		prerequisites: func(context.Context, string, Prerequisite, []string) prerequisiteState {
			return prerequisiteState{available: true}
		},
		actions: func(context.Context, Action, actionContext) checkResult {
			return checkResult{Status: statusPassed}
		},
	}
}

func newTestProcessEnvironment(t *testing.T) []string {
	t.Helper()
	environment, err := newIsolatedProcessEnvironment(newRetryCleanupTempDir(t))
	if err != nil {
		t.Fatalf("create isolated test process environment: %v", err)
	}
	return environment
}

func environmentMap(t *testing.T, environment []string) map[string]string {
	t.Helper()
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("invalid environment entry %q", entry)
		}
		if _, duplicate := values[key]; duplicate {
			t.Fatalf("duplicate environment key %q", key)
		}
		values[key] = value
	}
	return values
}

func replaceEnvironmentValue(environment []string, name, value string) []string {
	replaced := append([]string(nil), environment...)
	prefix := name + "="
	for index, entry := range replaced {
		if strings.HasPrefix(entry, prefix) {
			replaced[index] = prefix + value
			return replaced
		}
	}
	return append(replaced, prefix+value)
}

func newRetryCleanupTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "ssm-verify-test-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cleanupErr := removeTestCacheDirectory(directory); cleanupErr != nil {
			t.Errorf("remove test cache directory: %v", cleanupErr)
		}
	})
	return directory
}

func removeTestCacheDirectory(directory string) error {
	var cleanupErr error
	for range 20 {
		repairErr := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error { //nolint:gosec // directory is an exclusive test-owned MkdirTemp tree; symlinks are not followed
			if os.IsNotExist(walkErr) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			mode := os.FileMode(0o600)
			if entry.IsDir() {
				mode = 0o700
			}
			return os.Chmod(path, mode) //nolint:gosec // path is supplied by WalkDir beneath the exclusive test-owned tree
		})
		removeErr := os.RemoveAll(directory) //nolint:gosec // directory is created by newRetryCleanupTempDir for this test cleanup
		if repairErr == nil && removeErr == nil {
			if _, statErr := os.Lstat(directory); os.IsNotExist(statErr) { //nolint:gosec // directory is the test-owned cleanup root
				return nil
			}
		}
		cleanupErr = errors.Join(repairErr, removeErr)
		time.Sleep(10 * time.Millisecond)
	}
	return cleanupErr
}

func TestRemoveTestCacheDirectoryRepairsReadOnlyModuleTree(t *testing.T) {
	directory, err := os.MkdirTemp("", "ssm-verify-readonly-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(directory, "cache", "go-mod", "example.invalid", "dependency@v1.0.0")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(nested, "dependency.go")
	writeTestFile(t, file, "package dependency\n")
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nested, 0o500); err != nil { //nolint:gosec // read-only directory mode is the adversarial test fixture
		t.Fatal(err)
	}
	if err := removeTestCacheDirectory(directory); err != nil {
		t.Fatalf("remove read-only module cache tree: %v", err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("cache directory still exists: %v", err)
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
		if reflect.DeepEqual(prerequisite, want) {
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
	const linuxInvocation = "go run ./cmd/verify ci"
	const windowsInvocation = "go run ./cmd/verify fast"
	if got := makeTargetRecipe(makefile, "check"); got != linuxInvocation {
		return fmt.Errorf("Makefile check recipe = %q, want %q", got, linuxInvocation)
	}
	if got := strings.Count(workflow, "run: "+linuxInvocation); got != 1 {
		return fmt.Errorf("workflow Linux manifest invocation count = %d, want 1", got)
	}
	if got := strings.Count(workflow, "run: "+windowsInvocation); got != 1 {
		return fmt.Errorf("workflow Windows manifest invocation count = %d, want 1", got)
	}

	for _, command := range manifestCommandLines(manifest) {
		if strings.Contains(makefile, command) || strings.Contains(workflow, command) {
			return fmt.Errorf("adapter duplicates manifest-owned command %q", command)
		}
	}
	return nil
}
