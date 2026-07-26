//go:build windows

package main

import (
	"strings"
	"testing"
)

func assertCompiledAutomaticUpdateOutcome(
	t *testing.T,
	result compiledCLIResult,
	executablePath string,
	before compiledFileIdentity,
	_ []byte,
) {
	t.Helper()
	assertCompiledJSONArraySuccess(t, result, 0)
	assertCompiledFileUnchanged(t, executablePath, before)
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
		strings.Contains(result.Stderr, ".new "+executablePath+": ") &&
		strings.HasSuffix(result.Stderr, "\n") &&
		strings.Count(result.Stderr, "\n") == 1
	if result.ProcessExit != 1 ||
		result.Stdout != "Checking for updates...\n" ||
		!stderrHasRenameFailure {
		t.Fatalf("explicit update rename-failure contract failed; output=%s", compiledOutputIdentity(result))
	}
	assertCompiledFileUnchanged(t, executablePath, before)
}
