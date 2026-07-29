//go:build windows

package inventorytransaction

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"ssm/internal/config"
)

func assertPublishingIntentFileClosed(t *testing.T, file *os.File, failure string) {
	t.Helper()
	if _, err := file.Stat(); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		_ = file.Close()
		t.Fatalf("%s: %v", failure, err)
	}
}

func TestReadPublishingIntentDocumentClosesBeforePrivateAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publishing-intent.json")
	original := []byte(`{"version":2}`)
	if err := config.WritePrivateFile(path, original); err != nil {
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

	data, err := readPublishingIntentDocument(file, info.Size())
	if err != nil {
		t.Fatalf("read original publishing intent: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("publishing intent read changed original document bytes")
	}

	replacement := []byte(`{"version":2,"state":"ready"}`)
	if err := config.WritePrivateFile(path, replacement); err != nil {
		t.Fatalf("atomically replace publishing intent after read: %v", err)
	}
	after, err := os.ReadFile(path) //nolint:gosec // path is beneath the test-owned temporary directory
	if err != nil {
		t.Fatalf("read replacement publishing intent: %v", err)
	}
	if !bytes.Equal(after, replacement) {
		t.Fatal("private atomic replacement did not publish replacement bytes")
	}
}
