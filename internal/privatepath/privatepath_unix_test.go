//go:build unix

package privatepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWarnIfBroad(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want bool
	}{
		{"private", 0o600, false}, {"readonly", 0o400, false}, {"group", 0o640, true}, {"other", 0o604, true}, {"world", 0o644, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			} //nolint:gosec // deliberately broad fixture modes verify advisory permission detection
			if got := WarnIfBroad(path); got != tc.want {
				t.Fatalf("WarnIfBroad(%o) = %v, want %v", tc.mode, got, tc.want)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != tc.mode {
				t.Fatal("permission detection changed the file mode")
			}
		})
	}
	if WarnIfBroad(filepath.Join(dir, "missing")) {
		t.Fatal("missing path warned")
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // a broad directory must not produce a credential-file warning
		t.Fatal(err)
	}
	if WarnIfBroad(dir) {
		t.Fatal("directory warned")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil { //nolint:gosec // the symlink target intentionally permits other users to read it
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if !WarnIfBroad(link) {
		t.Fatal("symlink target did not warn")
	}
}

func assertPlatformPrivacy(t *testing.T, directory, file string) {
	t.Helper()
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := directoryInfo.Mode().Perm(), os.FileMode(0o700); got != want {
		t.Fatalf("directory mode = %o, want %o", got, want)
	}
	fileInfo, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fileInfo.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("file mode = %o, want %o", got, want)
	}
}
