package privatepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivacyBoundaryRestrictsAndVerifiesExistingPaths(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cache")
	//nolint:gosec // adversarial fixture proves the boundary repairs an existing permissive directory
	if err := os.Mkdir(directory, 0o777); err != nil {
		t.Fatalf("create permissive directory fixture: %v", err)
	}
	file := filepath.Join(directory, "entry")
	//nolint:gosec // adversarial fixture proves the boundary repairs an existing permissive file
	if err := os.WriteFile(file, []byte("cache\n"), 0o666); err != nil {
		t.Fatalf("create permissive file fixture: %v", err)
	}

	if err := RestrictDirectory(directory); err != nil {
		t.Fatalf("restrict directory: %v", err)
	}
	if err := VerifyDirectory(directory); err != nil {
		t.Fatalf("verify directory: %v", err)
	}
	if err := RestrictFile(file); err != nil {
		t.Fatalf("restrict file: %v", err)
	}
	if err := VerifyFile(file); err != nil {
		t.Fatalf("verify file: %v", err)
	}
	assertPlatformPrivacy(t, directory, file)
}
