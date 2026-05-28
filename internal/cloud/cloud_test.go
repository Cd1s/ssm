package cloud

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveCloudCreatesConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &CloudConfig{Server: "https://sync.example.test", Token: "token", Email: "agent@example.test"}
	if err := SaveCloud(cfg); err != nil {
		t.Fatalf("SaveCloud: %v", err)
	}

	path := filepath.Join(home, ".config", "ssm", "cloud.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cloud config: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("cloud config mode = %o, want 600", info.Mode().Perm())
	}
}
