//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileRejectsSymlinkAliasTempRootResolvingInsideSourceRepository(t *testing.T) {
	repo := newCleanTestRepository(t)
	writeTestFile(t, filepath.Join(repo, ".gitignore"), "ignored-temp/\n")
	gitOutput(t, repo, "add", ".gitignore")
	gitOutput(t, repo, "commit", "--quiet", "-m", "ignore aliased process temp root")
	inside := filepath.Join(repo, "ignored-temp")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "temp-alias")
	if err := os.Symlink(inside, alias); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, alias)
	}

	actionCalled := false
	deps := passingTestDependencies(t, repo)
	deps.actions = func(context.Context, Action, actionContext) checkResult {
		actionCalled = true
		return checkResult{Status: statusPassed}
	}
	if _, err := executeProfile(context.Background(), verificationManifest(), "fast", deps); err == nil ||
		!strings.Contains(err.Error(), "temporary directory must be outside source repository") {
		t.Fatalf("symlink-alias temp error = %v", err)
	}
	if actionCalled {
		t.Fatal("profile action ran through a temp-root symlink alias")
	}
	entries, err := os.ReadDir(inside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected symlink-alias temp root left residue: %v", entries)
	}
}
