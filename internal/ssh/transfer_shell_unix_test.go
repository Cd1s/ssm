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

// shellToolboxDir returns a PATH directory that exposes only the listed real
// utilities plus fake digest wrappers, so the remote probe order can be tested
// with a real POSIX shell.
func shellToolboxDir(t *testing.T, fakes map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"cat", "chmod", "mv", "rm", "mkdir", "wc", "tr", "awk"} {
		real, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("required utility %s unavailable: %v", name, err)
		}
		if err := os.Symlink(real, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // executable test double in a test-owned temporary directory
			t.Fatal(err)
		}
	}
	return dir
}

func digestWrapper(t *testing.T, format string) string {
	t.Helper()
	sum, err := exec.LookPath("sha256sum")
	if err != nil {
		t.Skipf("sha256sum unavailable for the test double: %v", err)
	}
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk unavailable")
	}
	return "printf '" + format + "\\n' \"$(" + sum + " | " + awk + " '{print $1}')\""
}

func runUploadScript(t *testing.T, path string, script string, payload []byte) (string, error) {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	cmd := exec.Command(shell, "-c", script) //nolint:gosec // test executes a command generated from test-owned paths
	cmd.Env = []string{"PATH=" + path}
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	return stdout.String() + stderr.String(), err
}

func TestUploadSHA256FallsBackToShasum(t *testing.T) {
	payload := []byte("shasum fallback payload")
	want := sha256.Sum256(payload)
	toolbox := shellToolboxDir(t, map[string]string{"shasum": digestWrapper(t, "%s  -")})
	destination := filepath.Join(t.TempDir(), "out")
	output, err := runUploadScript(t, toolbox, uploadCommandWithIntegrity(destination, 0o600, int64(len(payload)), hex.EncodeToString(want[:]), DefaultUploadDirMode), payload)
	if err != nil || !strings.Contains(output, "SSM_TRANSFER") {
		t.Fatalf("shasum-only upload: err=%v output=%s", err, output)
	}
	if data, err := os.ReadFile(destination); err != nil || !bytes.Equal(data, payload) { //nolint:gosec // destination is inside t.TempDir
		t.Fatalf("destination data=%q err=%v", data, err)
	}
}

func TestUploadSHA256FallsBackToOpenSSL(t *testing.T) {
	payload := []byte("openssl fallback payload")
	want := sha256.Sum256(payload)
	toolbox := shellToolboxDir(t, map[string]string{"openssl": digestWrapper(t, "SHA2-256(stdin)= %s")})
	destination := filepath.Join(t.TempDir(), "out")
	output, err := runUploadScript(t, toolbox, uploadCommandWithIntegrity(destination, 0o600, int64(len(payload)), hex.EncodeToString(want[:]), DefaultUploadDirMode), payload)
	if err != nil || !strings.Contains(output, "SSM_TRANSFER") {
		t.Fatalf("openssl-only upload: err=%v output=%s", err, output)
	}
}

func TestUploadSHA256WithoutAnyToolReportsMarkerBeforeWriting(t *testing.T) {
	toolbox := shellToolboxDir(t, nil)
	root := t.TempDir()
	destination := filepath.Join(root, "newdir", "out")
	output, err := runUploadScript(t, toolbox, uploadCommandWithIntegrity(destination, 0o600, 3, strings.Repeat("a", 64), DefaultUploadDirMode), []byte("abc"))
	if err == nil || !strings.Contains(output, integrityToolMissingMarker) {
		t.Fatalf("no digest tool: err=%v output=%s", err, output)
	}
	if _, statErr := os.Stat(filepath.Join(root, "newdir")); !os.IsNotExist(statErr) {
		t.Fatalf("parent directory was created before the tool probe: %v", statErr)
	}
}

func TestUploadCreatesParentDirectoriesWithRequestedMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want os.FileMode
	}{
		{name: "default", mode: DefaultUploadDirMode, want: 0o755},
		{name: "override", mode: 0o750, want: 0o750},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			destination := filepath.Join(root, "a", "b", "file.txt")
			output, err := runUploadScript(t, os.Getenv("PATH"), uploadCommandWithIntegrity(destination, 0o640, -1, "", tc.mode), []byte("x"))
			if err != nil {
				t.Fatalf("upload: %v: %s", err, output)
			}
			for _, dir := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
				info, err := os.Stat(dir)
				if err != nil || info.Mode().Perm() != tc.want {
					t.Fatalf("%s mode = %v err=%v, want %v", dir, info, err, tc.want)
				}
			}
			info, err := os.Stat(destination)
			if err != nil || info.Mode().Perm() != 0o640 {
				t.Fatalf("file mode = %v err=%v, want 0640 (file semantics unchanged)", info, err)
			}
		})
	}
}

func TestUploadKeepsExistingParentDirectoryMode(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "existing")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := runUploadScript(t, os.Getenv("PATH"), uploadCommandWithIntegrity(filepath.Join(parent, "f"), 0o600, -1, "", DefaultUploadDirMode), []byte("x")); err != nil {
		t.Fatalf("upload: %v: %s", err, output)
	}
	if info, err := os.Stat(parent); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("existing parent mode = %v err=%v, want unchanged 0700", info, err)
	}
}

func TestResumeProbeSharesDigestToolDetection(t *testing.T) {
	// With only shasum available the resume append script must pass the tool
	// check, using the same probe as put --sha256.
	toolbox := shellToolboxDir(t, map[string]string{"shasum": digestWrapper(t, "%s  -")})
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	cmd := exec.Command(shell, "-c", resumeAppendCommand("/nonexistent/final", "/nonexistent/partial", "/nonexistent/meta", 0o600, 10, strings.Repeat("a", 64), 0, strings.Repeat("b", 64))) //nolint:gosec // fixed non-existent test paths
	cmd.Env = []string{"PATH=" + toolbox}
	output, err := cmd.CombinedOutput()
	if err == nil || strings.Contains(string(output), "tool_missing") || !strings.Contains(string(output), "state_changed") {
		t.Fatalf("resume with shasum only should reach state validation: err=%v output=%s", err, output)
	}
}
