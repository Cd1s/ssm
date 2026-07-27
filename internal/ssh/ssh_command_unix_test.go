//go:build unix

package ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadCommandCleansPartialAndPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "target")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", uploadCommandWithIntegrity(destination, 0o600, 100, "")) //nolint:gosec // test executes a command generated from a test-owned path
	cmd.Stdin = strings.NewReader("partial")
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("partial upload succeeded: %s", output)
	}
	data, err := os.ReadFile(destination) //nolint:gosec // destination is inside t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("destination changed to %q", data)
	}
	matches, err := filepath.Glob(destination + ".ssm-upload.*")
	if err != nil || len(matches) != 0 {
		t.Fatalf("partial temporary files = %v, err=%v", matches, err)
	}
}

func TestUploadCommandRejectsChecksumMismatchAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "target")
	payload := []byte("complete payload")
	wrong := sha256.Sum256([]byte("different payload"))
	cmd := exec.Command("sh", "-c", uploadCommandWithIntegrity(destination, 0o600, int64(len(payload)), hex.EncodeToString(wrong[:]))) //nolint:gosec // test executes a command generated from a test-owned path
	cmd.Stdin = bytes.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "SSM_INTEGRITY_MISMATCH") {
		t.Fatalf("checksum mismatch: err=%v output=%s", err, output)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("mismatch published destination: %v", err)
	}
	matches, globErr := filepath.Glob(destination + ".ssm-upload.*")
	if globErr != nil || len(matches) != 0 {
		t.Fatalf("mismatch temporary files = %v, err=%v", matches, globErr)
	}
}

func TestResumeCommandReportsMissingVerificationUtility(t *testing.T) {
	cmd := exec.Command("sh", "-c", resumeAppendCommand("/tmp/final", "/tmp/partial", "/tmp/meta", 0o600, 10, strings.Repeat("a", 64), 0, strings.Repeat("b", 64))) //nolint:gosec // test executes only fixed test paths
	cmd.Env = []string{"PATH=/definitely-missing"}
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "SSM_RESUME_ERROR tool_missing") {
		t.Fatalf("missing verification utility: err=%v output=%s", err, output)
	}
}

func TestResumeChecksumMismatchNeverPublishesDestination(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "final ' target")
	partial := filepath.Join(dir, ".partial")
	metadata := partial + ".meta"
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partial, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongDigest := strings.Repeat("0", 64)
	if err := os.WriteFile(metadata, []byte("v1 6 "+wrongDigest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prefix := sha256.Sum256([]byte("abc"))
	cmd := exec.Command("sh", "-c", resumeAppendCommand(destination, partial, metadata, 0o600, 6, wrongDigest, 3, hex.EncodeToString(prefix[:]))) //nolint:gosec // test executes a command generated from test-owned paths
	cmd.Stdin = strings.NewReader("def")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "SSM_RESUME_ERROR digest_mismatch") {
		t.Fatalf("resume checksum mismatch: err=%v output=%s", err, output)
	}
	data, err := os.ReadFile(destination) //nolint:gosec // destination is inside t.TempDir
	if err != nil || string(data) != "original" {
		t.Fatalf("destination changed: data=%q err=%v", data, err)
	}
}
