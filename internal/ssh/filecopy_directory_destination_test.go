//go:build unix

package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadScriptRejectsDirectoryDestination(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "existing")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := runUploadScript(t, os.Getenv("PATH"), uploadCommandWithIntegrity(dest, 0o644, 3, "", DefaultUploadDirMode), []byte("abc"))
	entries, _ := os.ReadDir(dest)
	if err == nil {
		t.Fatalf("upload script succeeded for directory destination; output=%q", strings.TrimSpace(out))
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("upload script left files inside directory destination: %v", names)
	}
	if strings.Contains(out, "SSM_TRANSFER") {
		t.Fatalf("upload script reported a receipt for directory destination: %q", strings.TrimSpace(out))
	}
}

func TestUploadScriptOverwritesRegularFileDestination(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "existing")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runUploadScript(t, os.Getenv("PATH"), uploadCommandWithIntegrity(dest, 0o644, 3, "", DefaultUploadDirMode), []byte("abc"))
	if err != nil {
		t.Fatalf("upload script failed for regular file destination: %v; output=%q", err, strings.TrimSpace(out))
	}
	content, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "abc" {
		t.Fatalf("destination content = %q, want %q", content, "abc")
	}
}
