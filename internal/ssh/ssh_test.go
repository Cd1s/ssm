package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

func TestBuildAuthRequiresConfiguredMethod(t *testing.T) {
	_, err := buildAuth(config.Connection{Name: "agent"}, &config.Vault{})
	if err == nil {
		t.Fatal("expected missing auth error")
	}
	if !strings.Contains(err.Error(), "no authentication configured") {
		t.Fatalf("error = %q, want missing auth context", err)
	}
}

func TestUploadCommandRequiresSuccessfulWriteBeforeChmod(t *testing.T) {
	got := uploadCommand("/tmp/remote file's name", 0644)
	if !strings.Contains(got, " && chmod 0644 \"$tmp\"") {
		t.Fatalf("upload command = %q, want chmod guarded by &&", got)
	}
	if strings.Contains(got, "; chmod") {
		t.Fatalf("upload command = %q, chmod must not run after failed cat", got)
	}
	if !strings.Contains(got, "'/tmp/remote file'\"'\"'s name'") {
		t.Fatalf("upload command = %q, remote path was not shell-quoted", got)
	}
	if !strings.Contains(got, "mkdir -p '/tmp'") {
		t.Fatalf("upload command = %q, want mkdir -p parent", got)
	}
	if !strings.Contains(got, ".ssm-upload.$$") || !strings.Contains(got, "mv -f -- \"$tmp\"") {
		t.Fatalf("upload command = %q, want atomic sibling temp and rename", got)
	}
	if !strings.Contains(got, "trap 'rm -f -- \"$tmp\"'") {
		t.Fatalf("upload command = %q, want partial upload cleanup", got)
	}
}

func TestUploadCommandNestedParent(t *testing.T) {
	got := uploadCommand("/var/tmp/a/b/c.txt", 0600)
	if !strings.Contains(got, "mkdir -p '/var/tmp/a/b'") {
		t.Fatalf("upload command = %q", got)
	}
}

func TestUploadCommandCleansPartialAndPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "target")
	if err := os.WriteFile(destination, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", uploadCommandWithIntegrity(destination, 0600, 100, ""))
	cmd.Stdin = strings.NewReader("partial")
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("partial upload succeeded: %s", output)
	}
	data, err := os.ReadFile(destination)
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
	cmd := exec.Command("sh", "-c", uploadCommandWithIntegrity(destination, 0600, int64(len(payload)), hex.EncodeToString(wrong[:])))
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
	cmd := exec.Command("sh", "-c", resumeAppendCommand("/tmp/final", "/tmp/partial", "/tmp/meta", 0600, 10, strings.Repeat("a", 64), 0, strings.Repeat("b", 64)))
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
	if err := os.WriteFile(destination, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partial, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	wrongDigest := strings.Repeat("0", 64)
	if err := os.WriteFile(metadata, []byte("v1 6 "+wrongDigest+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prefix := sha256.Sum256([]byte("abc"))
	cmd := exec.Command("sh", "-c", resumeAppendCommand(destination, partial, metadata, 0600, 6, wrongDigest, 3, hex.EncodeToString(prefix[:])))
	cmd.Stdin = strings.NewReader("def")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "SSM_RESUME_ERROR digest_mismatch") {
		t.Fatalf("resume checksum mismatch: err=%v output=%s", err, output)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "original" {
		t.Fatalf("destination changed: data=%q err=%v", data, err)
	}
}

func TestResumePathsAreDeterministicAndShellSafe(t *testing.T) {
	digest := strings.Repeat("a", 64)
	partial, metadata, pattern := resumePaths("/tmp/weird ' target;$(touch nope)", digest)
	if !strings.HasPrefix(filepath.Base(partial), ".ssm-resume-v1-") || !strings.HasSuffix(partial, digest) || metadata != partial+".meta" || !strings.HasSuffix(pattern, "-*") {
		t.Fatalf("resume paths: partial=%q metadata=%q pattern=%q", partial, metadata, pattern)
	}
	command := resumeAppendCommand("/tmp/weird ' target;$(touch nope)", partial, metadata, 0600, 1, digest, 0, strings.Repeat("b", 64))
	if !strings.Contains(command, "chmod 0600") || !strings.Contains(command, "mv -f --") {
		t.Fatalf("resume command lacks restrictive mode or atomic publish: %s", command)
	}
}

func TestDownloadCommandQuotesPath(t *testing.T) {
	got := downloadCommand("/tmp/file's name")
	if !strings.Contains(got, "cat -- ") {
		t.Fatalf("download command = %q", got)
	}
	if !strings.Contains(got, "'/tmp/file'\"'\"'s name'") {
		t.Fatalf("download command = %q, path not quoted", got)
	}
}

func TestRemoteParentDir(t *testing.T) {
	tests := map[string]string{
		"/a/b/c": "/a/b",
		"/a":     "/",
		"rel/x":  "rel",
		"plain":  "",
		"/":      "",
	}
	for in, want := range tests {
		if got := RemoteParentDir(in); got != want {
			t.Fatalf("RemoteParentDir(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSuggestNames(t *testing.T) {
	names := []string{"limee-hk", "limee-sg", "hk-200m", "aws-sg"}
	got := SuggestNames("limee-hkx", names, 3)
	if len(got) == 0 || got[0] != "limee-hk" {
		t.Fatalf("SuggestNames = %#v, want limee-hk first", got)
	}
}

func TestHostKeyCallbackRejectsMalformedKnownHosts(t *testing.T) {
	dir := t.TempDir()
	knownHostsPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte("this is not a known_hosts line\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cb := buildHostKeyCallbackForPath(knownHostsPath)
	err := cb("127.0.0.1:22", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, testPublicKey(t))
	if err == nil {
		t.Fatal("expected malformed known_hosts to reject host key")
	}
	if !strings.Contains(err.Error(), "known_hosts parse failed") {
		t.Fatalf("error = %q, want parse failure context", err)
	}
}

func TestHostKeyCallbackRejectsUnknownHostWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	knownHostsPath := filepath.Join(dir, "known_hosts")
	cb := buildHostKeyCallbackForPath(knownHostsPath)

	key := testPublicKey(t)
	if err := cb("127.0.0.1:2222", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}, key); err == nil {
		t.Fatal("unknown host key was accepted")
	}
	if _, err := os.Stat(knownHostsPath); !os.IsNotExist(err) {
		t.Fatalf("known_hosts was created or stat failed: %v", err)
	}
}

func TestSaveHostKeyReportsDirectoryErrors(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "not-dir")
	if err := os.WriteFile(notDir, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}

	err := saveHostKey(filepath.Join(notDir, "known_hosts"), "127.0.0.1:22", testPublicKey(t))
	if err == nil {
		t.Fatal("expected directory creation error")
	}
}

func testPublicKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromSigner(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}
