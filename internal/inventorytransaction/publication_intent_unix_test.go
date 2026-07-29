//go:build unix

package inventorytransaction

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPublishingIntentDocumentUsesOpenedFileAcrossReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publishing-intent.json")
	original := []byte(`{"version":2}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("write original publishing intent: %v", err)
	}
	file, err := os.Open(path) //nolint:gosec // path is beneath the test-owned temporary directory
	if err != nil {
		t.Fatalf("open original publishing intent: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatalf("stat original publishing intent: %v", err)
	}
	replacement := filepath.Join(filepath.Dir(path), "replacement.json")
	if err := os.WriteFile(replacement, bytes.Repeat([]byte("x"), 512*1024+1), 0o600); err != nil {
		_ = file.Close()
		t.Fatalf("write replacement publishing intent: %v", err)
	}
	if err := os.Rename(replacement, path); err != nil {
		_ = file.Close()
		t.Fatalf("replace publishing intent path: %v", err)
	}

	data, err := readPublishingIntentDocument(file, info.Size())
	if err != nil {
		t.Fatalf("read opened publishing intent after path replacement: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("publishing intent read switched to a replacement path")
	}
}
