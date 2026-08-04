//go:build unix

package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ssm/internal/config"
	cryptovault "ssm/internal/vault"
)

func TestMajorPreflightDoesNotChangeConfigDirectoryMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const password = "read-only migration preflight" //nolint:gosec // test-only vault passphrase
	if err := config.Save(&config.Vault{}, password); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config.Dir(), 0755); err != nil { //nolint:gosec // deliberately non-private fixture proves review does not repair persistent state
		t.Fatal(err)
	}
	passwordPath := filepath.Join(t.TempDir(), "master.pass")
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	check := checkPendingRecovery(passwordPath)
	if check.Status != "passed" {
		t.Fatalf("pending/recovery check = %#v", check)
	}
	info, err := os.Stat(config.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("read-only major preflight changed config directory mode to %o, want 755", got)
	}
}

func TestMajorPreflightReadsLegacyVaultWithoutChangingState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const password = "legacy read-only migration preflight"                               //nolint:gosec // test-only vault passphrase
	legacy, err := json.Marshal([]config.Connection{{Name: "legacy", Host: "127.0.0.1"}}) //nolint:gosec // fixture intentionally exercises the legacy struct with an empty password field
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cryptovault.Encrypt(legacy, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config.Dir(), 0755); err != nil { //nolint:gosec // deliberately non-private fixture proves review does not repair persistent state
		t.Fatal(err)
	}
	if err := os.Chmod(config.Dir(), 0755); err != nil { //nolint:gosec // deliberately non-private fixture proves review does not repair persistent state
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Path(), encrypted, 0600); err != nil { //nolint:gosec // test-owned encrypted legacy fixture
		t.Fatal(err)
	}
	before, err := os.ReadFile(config.Path()) //nolint:gosec // test-owned encrypted legacy fixture
	if err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(t.TempDir(), "master.pass")
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	check := checkPendingRecovery(passwordPath)
	if check.Status != "passed" {
		t.Fatalf("legacy pending/recovery check = %#v", check)
	}
	after, err := os.ReadFile(config.Path()) //nolint:gosec // test-owned encrypted legacy fixture
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(config.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || info.Mode().Perm() != 0755 {
		t.Fatalf("legacy preflight mutated encrypted state: bytes_equal=%t dir_mode=%o", string(after) == string(before), info.Mode().Perm())
	}
}
