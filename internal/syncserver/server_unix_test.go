//go:build unix

package syncserver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewPreservesExistingDataDirectorySymlinkCompatibility(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil { //nolint:gosec // characterization starts with the legacy permissive target mode
		t.Fatal(err)
	}
	link := filepath.Join(root, "server-data-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := New(link); err != nil {
		t.Fatalf("New with existing data-directory symlink: %v", err)
	}
	for _, path := range []string{
		filepath.Join(target, "vaults"),
		filepath.Join(target, "users.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected storage path %s: %v", path, err)
		}
	}
}
