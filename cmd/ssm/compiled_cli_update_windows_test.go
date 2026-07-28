//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func assertCompiledFileUnchanged(t *testing.T, path string, before compiledFileIdentity) {
	t.Helper()
	if got := loadCompiledFileIdentity(t, path); got != before {
		t.Fatal("compiled CLI executable changed after the characterized replacement failure")
	}
}

func assertCompiledExplicitUpdateOutcome(
	t *testing.T,
	result compiledCLIResult,
	executablePath string,
	before compiledFileIdentity,
	_ []byte,
	_ string,
) {
	t.Helper()
	stderrHasRenameFailure := strings.HasPrefix(result.Stderr, "Error: rename ") &&
		strings.Contains(result.Stderr, ".new ") &&
		strings.Contains(result.Stderr, filepath.Base(executablePath)+": ") &&
		strings.HasSuffix(result.Stderr, "\n") &&
		strings.Count(result.Stderr, "\n") == 1
	if result.ProcessExit != 1 ||
		result.Stdout != "Checking for updates...\n" ||
		!stderrHasRenameFailure {
		t.Fatalf("explicit update rename-failure contract failed; output=%s", compiledOutputIdentity(result))
	}
	assertCompiledFileUnchanged(t, executablePath, before)
}
