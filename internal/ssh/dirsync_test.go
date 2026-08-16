package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateUploadDirWalkRejectsEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateUploadDirWalk(dir); err == nil || !strings.Contains(err.Error(), "empty directory") {
		t.Fatalf("expected empty-directory validation error, got %v", err)
	}
}

func TestValidateUploadDirWalkRejectsNonRegularEntry(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("missing-target", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := validateUploadDirWalk(dir); err == nil || !strings.Contains(err.Error(), "non-regular entry") {
		t.Fatalf("expected non-regular validation error, got %v", err)
	}
}

func TestLocalTreeFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0700)
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("b"), 0600)
	files, err := LocalTreeFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files=%v", files)
	}
}

func TestRemoteParentDirStillWorks(t *testing.T) {
	if RemoteParentDir("/a/b/c") != "/a/b" {
		t.Fatal(RemoteParentDir("/a/b/c"))
	}
}
