//go:build unix

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBuiltinReadersRejectSymlinksToExternalFiles(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	external := t.TempDir()

	t.Run("source version", func(t *testing.T) {
		target := filepath.Join(external, "external-main.go")
		writeTestFile(t, target, "package main\n\nvar version = \"9.9.9\"\n// secret-marker-source\n")
		replaceWithSymlink(t, filepath.Join(repo, "cmd", "ssm", "main.go"), target)

		result := executeBuiltin("source-version", actionContext{RepoRoot: repo})
		if result.Status != statusFailed {
			t.Fatalf("status = %q (%s), want failed", result.Status, result.Detail)
		}
		if strings.Contains(result.Detail, "secret-marker-source") {
			t.Fatalf("failure exposed external source content: %s", result.Detail)
		}
	})

	t.Run("release notes", func(t *testing.T) {
		replaceWithRegularFile(
			t,
			filepath.Join(repo, "cmd", "ssm", "main.go"),
			"package main\n\nvar version = \"1.2.3\"\n",
		)
		target := filepath.Join(external, "external-release-notes.md")
		writeTestFile(t, target, "# Release Notes\n\n## v1.2.3\n\nsecret-marker-notes\n")
		replaceWithSymlink(t, filepath.Join(repo, "RELEASE_NOTES.md"), target)

		result := executeBuiltin("release-notes", actionContext{RepoRoot: repo})
		if result.Status != statusFailed {
			t.Fatalf("status = %q (%s), want failed", result.Status, result.Detail)
		}
		if strings.Contains(result.Detail, "secret-marker-notes") {
			t.Fatalf("failure exposed external release-note content: %s", result.Detail)
		}
	})

	t.Run("release checksum input", func(t *testing.T) {
		tempDir := t.TempDir()
		for _, name := range []string{
			"ssm-linux-amd64",
			"ssm-linux-arm64",
			"ssm-darwin-amd64",
			"ssm-darwin-arm64",
			"ssm-windows-amd64.exe",
			"ssm-windows-arm64.exe",
		} {
			writeTestFile(t, filepath.Join(tempDir, name), "artifact\n")
		}
		target := filepath.Join(external, "external-install-secret")
		writeTestFile(t, target, "secret-marker-install\n")
		replaceWithSymlink(t, filepath.Join(repo, "install.sh"), target)

		result := executeBuiltin("release-checksums", actionContext{
			RepoRoot: repo,
			TempDir:  tempDir,
		})
		if result.Status != statusFailed {
			t.Fatalf("status = %q (%s), want failed", result.Status, result.Detail)
		}
		if strings.Contains(result.Detail, "secret-marker-install") {
			t.Fatalf("failure exposed external install content: %s", result.Detail)
		}
	})
}

func TestTrackedFilePrerequisiteRejectsExternalSymlink(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	external := filepath.Join(t.TempDir(), "external-secret")
	writeTestFile(t, external, "credential-canary\n")
	replaceWithSymlink(t, filepath.Join(repo, "install.sh"), external)

	state := checkPrerequisite(
		repo,
		Prerequisite{Kind: "file", Name: "install.sh", Version: "tracked"},
		newTestProcessEnvironment(t),
	)
	if state.available || !strings.Contains(state.detail, "without following links") {
		t.Fatalf("state = %+v, want no-follow tracked-file rejection", state)
	}
}

func TestProfileRejectsTrackedSymlinkToExternalFIFOBeforeActions(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	fifo := filepath.Join(t.TempDir(), "external-secret.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create external FIFO: %v", err)
	}
	tracked := filepath.Join(repo, "install.sh")
	if err := os.Remove(tracked); err != nil {
		t.Fatalf("remove tracked regular file: %v", err)
	}
	if err := os.Symlink(fifo, tracked); err != nil {
		t.Fatalf("replace tracked file with external FIFO symlink: %v", err)
	}

	actionCalled := false
	deps := passingTestDependencies(t, repo)
	deps.stdout = io.Discard
	deps.stderr = io.Discard
	deps.actions = func(context.Context, Action, actionContext) checkResult {
		actionCalled = true
		return checkResult{Status: statusPassed}
	}

	type outcome struct {
		result profileResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
		done <- outcome{result: result, err: err}
	}()

	var got outcome
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		// Unblock an incorrect reader so the test process can clean up, but do
		// not write any FIFO content.
		if descriptor, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = unix.Close(descriptor)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("profile blocked opening the external FIFO target")
	}

	if got.err == nil || !strings.Contains(got.err.Error(), "unsafe tracked worktree path") {
		t.Fatalf("error = %v, want unsafe tracked-worktree rejection", got.err)
	}
	if actionCalled {
		t.Fatal("profile action ran before tracked path identities were validated")
	}
	if got.result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", got.result.Status, statusFailed)
	}
}

func TestProfileRejectsTrackedNonRegularLeafBeforeActions(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	tracked := filepath.Join(repo, "install.sh")
	if err := os.Remove(tracked); err != nil {
		t.Fatalf("remove tracked regular file: %v", err)
	}
	if err := unix.Mkfifo(tracked, 0o600); err != nil {
		t.Fatalf("replace tracked file with FIFO: %v", err)
	}

	actionCalled := false
	deps := passingTestDependencies(t, repo)
	deps.actions = func(context.Context, Action, actionContext) checkResult {
		actionCalled = true
		return checkResult{Status: statusPassed}
	}
	type outcome struct {
		result profileResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
		done <- outcome{result: result, err: err}
	}()

	var got outcome
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		if descriptor, err := unix.Open(tracked, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = unix.Close(descriptor)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("profile blocked opening a tracked FIFO leaf")
	}
	if got.err == nil || !strings.Contains(got.err.Error(), "not a regular file") {
		t.Fatalf("error = %v, want tracked non-regular-file rejection", got.err)
	}
	if actionCalled {
		t.Fatal("profile action ran before tracked leaf identity was validated")
	}
	if got.result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", got.result.Status, statusFailed)
	}
}

func TestProfileRejectsSymlinkedTrackedPathComponentBeforeActions(t *testing.T) {
	repo := newRepresentativeProfileRepository(t)
	external := filepath.Join(t.TempDir(), "external-secret-directory")
	if err := os.MkdirAll(filepath.Join(external, "references"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(external, "test-prompts.json"), "{\"secret\":\"marker\"}\n")
	writeTestFile(t, filepath.Join(external, "references", "request-v1.schema.json"), "{\"secret\":\"marker\"}\n")

	trackedComponent := filepath.Join(repo, "skills", "agent-ssm")
	if err := os.RemoveAll(trackedComponent); err != nil {
		t.Fatalf("remove tracked directory fixture: %v", err)
	}
	if err := os.Symlink(external, trackedComponent); err != nil {
		t.Fatalf("replace tracked path component with symlink: %v", err)
	}

	actionCalled := false
	deps := passingTestDependencies(t, repo)
	deps.actions = func(context.Context, Action, actionContext) checkResult {
		actionCalled = true
		return checkResult{Status: statusPassed}
	}
	result, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
	if err == nil || !strings.Contains(err.Error(), "unsafe tracked worktree path") {
		t.Fatalf("error = %v, want tracked component rejection", err)
	}
	if actionCalled {
		t.Fatal("profile action ran before tracked component identity was validated")
	}
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
}

func TestActionWorkspacePreservesDirtyUnixExecutableBits(t *testing.T) {
	for _, test := range []struct {
		name            string
		indexExecutable bool
		worktreeMode    os.FileMode
		wantExecutable  bool
	}{
		{
			name:           "add execute permission",
			worktreeMode:   0o700,
			wantExecutable: true,
		},
		{
			name:            "remove execute permission",
			indexExecutable: true,
			worktreeMode:    0o600,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newCleanTestRepository(t)
			source := filepath.Join(repo, "sentinel.txt")
			if test.indexExecutable {
				//nolint:gosec // test fixture needs owner execute permission to model an indexed executable
				if err := os.Chmod(source, 0o700); err != nil {
					t.Fatalf("make indexed fixture executable: %v", err)
				}
				gitOutput(t, repo, "add", "sentinel.txt")
				gitOutput(t, repo, "commit", "--quiet", "-m", "executable baseline")
			}
			if err := os.Chmod(source, test.worktreeMode); err != nil {
				t.Fatalf("set dirty working-tree mode: %v", err)
			}

			workspace := filepath.Join(t.TempDir(), "action-workspace")
			if _, err := materializeActionWorkspace(repo, workspace, newTestProcessEnvironment(t)); err != nil {
				t.Fatalf("materialize action workspace: %v", err)
			}
			info, err := os.Stat(filepath.Join(workspace, "sentinel.txt"))
			if err != nil {
				t.Fatalf("stat copied tracked file: %v", err)
			}
			if got := info.Mode().Perm()&0o111 != 0; got != test.wantExecutable {
				t.Fatalf(
					"workspace executable = %t (mode %o), want %t from dirty working tree",
					got,
					info.Mode().Perm(),
					test.wantExecutable,
				)
			}
		})
	}
}

func replaceWithSymlink(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove regular file %s: %v", path, err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("replace %s with symlink: %v", path, err)
	}
}

func replaceWithRegularFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove replaced path %s: %v", path, err)
	}
	writeTestFile(t, path, contents)
}
