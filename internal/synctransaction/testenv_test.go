package synctransaction

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/config"
)

func isolateTestUserConfig(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
	t.Setenv("LOCALAPPDATA", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

func replacePathWithDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove existing fault target %s: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create fault target parent %s: %v", filepath.Dir(path), err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create directory fault target %s: %v", path, err)
	}
}

func TestIsolateTestUserConfig(t *testing.T) {
	home := isolateTestUserConfig(t)

	for _, name := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		if got := os.Getenv(name); got != home {
			t.Fatalf("%s = %q, want %q", name, got, home)
		}
	}
	if got, want := os.Getenv("XDG_CONFIG_HOME"), filepath.Join(home, ".config"); got != want {
		t.Fatalf("XDG_CONFIG_HOME = %q, want %q", got, want)
	}
	if got, want := config.Dir(), filepath.Join(home, ".config", "ssm"); got != want {
		t.Fatalf("config.Dir() = %q, want %q", got, want)
	}
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir(): %v", err)
	}
	relative, err := filepath.Rel(home, userConfigDir)
	if err != nil {
		t.Fatalf("relate user config dir %q to test home %q: %v", userConfigDir, home, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("os.UserConfigDir() = %q, want path within %q", userConfigDir, home)
	}
}
