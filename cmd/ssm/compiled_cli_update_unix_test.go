//go:build !windows

package main

import "testing"

func assertCompiledFileUnchanged(t *testing.T, path string, before compiledFileIdentity) {
	t.Helper()
	if got := loadCompiledFileIdentity(t, path); got != before {
		t.Fatal("compiled CLI executable changed unexpectedly")
	}
}

func assertCompiledAutomaticUpdateOutcome(
	t *testing.T,
	result compiledCLIResult,
	executablePath string,
	_ compiledFileIdentity,
	replacement []byte,
) {
	t.Helper()
	assertCompiledJSONArraySuccess(t, result, 0)
	assertCompiledFileMatches(t, executablePath, replacement)
}

func assertCompiledExplicitUpdateOutcome(
	t *testing.T,
	result compiledCLIResult,
	executablePath string,
	_ compiledFileIdentity,
	replacement []byte,
	version string,
) {
	t.Helper()
	if result.ProcessExit != 0 ||
		result.Stdout != "Checking for updates...\nUpdated to "+version+"\n" ||
		result.Stderr != "" {
		t.Fatalf("explicit update success contract failed; output=%s", compiledOutputIdentity(result))
	}
	assertCompiledFileMatches(t, executablePath, replacement)
}
