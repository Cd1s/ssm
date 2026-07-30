//go:build windows

package main

import "testing"

func assertCompiledFileUnchanged(t *testing.T, path string, before compiledFileIdentity) {
	t.Helper()
	if got := loadCompiledFileIdentity(t, path); got != before {
		t.Fatal("compiled CLI executable changed after the characterized replacement failure")
	}
}
