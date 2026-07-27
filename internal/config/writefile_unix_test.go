//go:build unix

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePrivateDirPreservesExistingDirectorySymlinkCompatibility(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil { //nolint:gosec // characterization starts with the legacy permissive target mode
		t.Fatal(err)
	}
	link := filepath.Join(root, "config-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := EnsurePrivateDir(link); err != nil {
		t.Fatalf("EnsurePrivateDir on existing directory symlink: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("symlink target mode = %o, want 700", info.Mode().Perm())
	}
}

func TestWritePrivateFilePreservesExistingParentDirectorySymlinkCompatibility(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil { //nolint:gosec // characterization starts with the legacy permissive target mode
		t.Fatal(err)
	}
	link := filepath.Join(root, "config-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := WritePrivateFile(filepath.Join(link, "settings.json"), []byte("compatible\n")); err != nil {
		t.Fatalf("WritePrivateFile through existing directory symlink: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(target, "settings.json")) //nolint:gosec // path is beneath the test-owned temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "compatible\n" {
		t.Fatalf("written data = %q", data)
	}
}
