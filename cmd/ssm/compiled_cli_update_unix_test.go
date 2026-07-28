//go:build !windows

package main

import "testing"

func assertCompiledAutomaticUpdateOutcome(
	t *testing.T,
	result compiledCLIResult,
	executablePath string,
	_ compiledFileIdentity,
	replacement []byte,
) {
	t.Helper()
	assertCompiledEmptyJSONArraySuccess(t, result)
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
