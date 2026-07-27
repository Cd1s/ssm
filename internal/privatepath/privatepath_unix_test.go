//go:build unix

package privatepath

import (
	"os"
	"testing"
)

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
