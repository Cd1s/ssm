package ssh

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestR3DirectoryDownloadStagingWidensPermissionsOfExistingDestination(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(filepath.Join(dest, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dest, ".ssh", "id_x")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	staging, err := newDirectoryDownloadStaging(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer staging.cleanup()
	if err := staging.publish(dest, systemDirectoryDownloadPublishOperations()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		path string
		want os.FileMode
	}{{dest, 0o700}, {filepath.Join(dest, ".ssh"), 0o700}, {secret, 0o600}} {
		info, err := os.Stat(p.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != p.want {
			t.Errorf("%s mode %o, want %o", p.path, info.Mode().Perm(), p.want)
		}
	}

	real := filepath.Join(root, "real")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	staging2, err := newDirectoryDownloadStaging(link)
	if err != nil {
		t.Fatal(err)
	}
	defer staging2.cleanup()
	if err := staging2.publish(link, systemDirectoryDownloadPublishOperations()); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlinked destination was replaced by %v (err=%v)", info.Mode(), err)
	}
}
