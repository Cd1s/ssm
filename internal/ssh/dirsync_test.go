package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

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
