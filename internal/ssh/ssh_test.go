package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
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
