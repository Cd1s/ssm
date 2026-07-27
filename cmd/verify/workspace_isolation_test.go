package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileRejectsProcessTempRootInsideSourceRepositoryWithoutDiscoveryOrResidue(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, ".gitignore"), "ignored-temp/\n")
	gitOutput(t, repo, "add", ".gitignore")
	gitOutput(t, repo, "commit", "--quiet", "-m", "ignore adversarial process temp root")
	processTemp := filepath.Join(repo, "ignored-temp")
	if err := os.Mkdir(processTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, processTemp)
	}

	actionCalled := false
	discoveredSource := false
	deps := passingTestDependencies(t, repo)
	deps.stdout = io.Discard
	deps.stderr = io.Discard
	deps.actions = func(_ context.Context, _ Action, actionCtx actionContext) checkResult {
		actionCalled = true
		command := exec.Command("git", "rev-parse", "--show-toplevel")
		command.Dir = actionCtx.RepoRoot
		command.Env = actionCtx.Environment
		output, err := command.CombinedOutput()
		if err == nil && sameTestResolvedPath(t, strings.TrimSpace(string(output)), repo) {
			discoveredSource = true
		}
		return checkResult{Status: statusFailed, Detail: "adversarial discovery action was reached"}
	}

	_, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "temporary directory must be outside source repository") {
		t.Errorf("error = %v, want unsafe process temp-root rejection", err)
	}
	if actionCalled {
		t.Error("profile action ran before unsafe process temp root was rejected")
	}
	if discoveredSource {
		t.Error("action workspace discovered the source repository")
	}
	entries, readErr := os.ReadDir(processTemp)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected process temp root left residue: %v", entries)
	}
}

func TestActionGitDiscoveryCannotEscapeWorkspaceIntoUnrelatedParentRepository(t *testing.T) {
	sourceRepo := newCleanTestRepository(t)
	tempParentRepo := newCleanTestRepository(t)
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, tempParentRepo)
	}

	actionCalls := 0
	deps := passingTestDependencies(t, sourceRepo)
	deps.actions = func(_ context.Context, _ Action, actionCtx actionContext) checkResult {
		actionCalls++
		command := exec.Command("git", "rev-parse", "--show-toplevel")
		command.Dir = actionCtx.RepoRoot
		command.Env = actionCtx.Environment
		if output, err := command.CombinedOutput(); err == nil {
			return checkResult{
				Status: statusFailed,
				Detail: "action escaped Git discovery ceiling into " + strings.TrimSpace(string(output)),
			}
		}
		return checkResult{Status: statusPassed}
	}

	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err != nil {
		t.Fatalf("execute isolated profile: %v (result=%+v)", err, result)
	}
	fast, _ := findProfile(verificationManifest(), "fast")
	if actionCalls != len(fast.Checks) {
		t.Fatalf("action calls = %d, want %d", actionCalls, len(fast.Checks))
	}
}

func sameTestResolvedPath(t *testing.T, left, right string) bool {
	t.Helper()
	left, err := filepath.EvalSymlinks(left)
	if err != nil {
		t.Fatal(err)
	}
	right, err = filepath.EvalSymlinks(right)
	if err != nil {
		t.Fatal(err)
	}
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}
