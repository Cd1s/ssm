package ssh

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func tarBytes(t *testing.T, header *tar.Header, data []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	if err := w.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func extractTestTar(t *testing.T, root string, archive []byte) error {
	t.Helper()
	args := []string{"-C", root}
	if runtime.GOOS == "linux" {
		args = append(args, "--no-same-owner", "--no-same-permissions")
	}
	args = append(args, "-xf", "-")
	cmd := exec.Command("tar", args...) //nolint:gosec // test-only tar fixture under t.TempDir
	cmd.Stdin = bytes.NewReader(archive)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func TestRejectSpecialEntriesClearsSpecialPermissionBits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setid")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755|os.ModeSetuid); err != nil { //nolint:gosec // test-only fixture under t.TempDir uses intentional setuid mode
		t.Fatal(err)
	}
	if err := rejectSpecialEntries(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("special permission bits remain: %v", info.Mode())
	}
}

func TestDirectoryTarRejectsCharacterDevice(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("device node tar extraction is Linux-specific")
	}
	root := t.TempDir()
	archive := tarBytes(t, &tar.Header{Name: "console", Mode: 0o600, Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}, nil)
	if err := extractTestTar(t, root, archive); err != nil {
		t.Skipf("cannot create device node in test temp directory: %v", err)
	}
	if err := rejectSpecialEntries(root); err == nil {
		t.Fatal("device node was accepted")
	}
}

func TestDirectoryTarDropsSetuidFromRegularFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("tar permission behavior is tested on Linux GNU tar")
	}
	root := t.TempDir()
	archive := tarBytes(t, &tar.Header{Name: "setid", Mode: 0o4755, Size: 1}, []byte("x"))
	if err := extractTestTar(t, root, archive); err != nil {
		t.Fatal(err)
	}
	if err := rejectSpecialEntries(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "setid"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("setuid bit survived extraction: %v", info.Mode())
	}
}
