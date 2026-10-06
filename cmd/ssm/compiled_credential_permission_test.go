//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompiledCredentialPermissionWarnings(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		mode     os.FileMode
		suppress string
		warning  bool
	}{
		{"broad", 0o644, "", true},
		{"group", 0o640, "", true},
		{"other", 0o604, "", true},
		{"private", 0o600, "", false},
		{"readonly", 0o400, "", false},
		{"suppressed", 0o644, "1", false},
		{"zero_does_not_suppress", 0o644, "0", true},
		{"true_does_not_suppress", 0o644, "true", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newCompiledCLIHarness(t)
			path := writeCredentialPermissionFixture(t, harness.temp, testCase.mode)
			want := ""
			if testCase.warning {
				want = "warning: --password-file is readable by other users; run chmod 600 on it\n"
			}
			for _, action := range []string{"add", "upsert"} {
				result := harness.RunWithEnv(t, "ssm", nil, map[string]string{"SSM_NO_PERMISSION_WARNING": testCase.suppress},
					"--json", "host", action, "permission-host", "--host", "192.0.2.80", "--user", "runner", "--password-file", path, "--offline")
				assertCredentialPermissionResult(t, result, want, path)
			}
		})
	}
}

func TestCompiledHostKeyCredentialPermissionWarnings(t *testing.T) {
	for _, source := range []string{"broad", "private", "suppressed"} {
		t.Run(source, func(t *testing.T) {
			harness := newCompiledCLIHarness(t)
			path := filepath.Join(harness.temp, "PERMISSION_KEY_PATH_CANARY")
			if err := os.WriteFile(path, testPrivateKey(t), 0o600); err != nil {
				t.Fatal(err)
			}
			want := ""
			env := map[string]string{"SSM_NO_PERMISSION_WARNING": ""}
			if source != "private" {
				if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // deliberately broad private-key fixture exercises advisory warnings
					t.Fatal(err)
				}
				want = "warning: --key-file is readable by other users; run chmod 600 on it\n"
			}
			if source == "suppressed" {
				env["SSM_NO_PERMISSION_WARNING"] = "1"
				want = ""
			}
			for _, action := range []string{"add", "upsert"} {
				result := harness.RunWithEnv(t, "ssm", nil, env, "--json", "host", action, "permission-key-host", "--host", "192.0.2.81", "--user", "runner", "--key-file", path, "--offline")
				assertCredentialPermissionResult(t, result, want, path)
				if strings.Contains(result.Stderr, "PRIVATE KEY") {
					t.Fatal("permission warning leaked private-key material")
				}
			}
		})
	}
}

func TestCompiledMasterCredentialPermissionWarnings(t *testing.T) {
	for _, source := range []string{"flag", "environment", "default", "suppressed", "same_file_twice", "symlink_same_file", "hardlink_same_file"} {
		t.Run(source, func(t *testing.T) {
			harness := newCompiledCLIHarness(t)
			if err := os.Chmod(harness.passPath, 0o644); err != nil { //nolint:gosec // intentionally broad master-password fixture exercises advisory warnings
				t.Fatal(err)
			}
			env := map[string]string{"SSM_NO_PERMISSION_WARNING": ""}
			credentialPath := writeCredentialPermissionFixture(t, harness.temp, 0o600)
			want := "warning: --master-pass-file is readable by other users; run chmod 600 on it\n"
			switch source {
			case "flag":
				env["SSM_MASTER_PASS_FILE"] = ""
			case "default":
				env["SSM_MASTER_PASS_FILE"] = ""
			case "suppressed":
				env["SSM_NO_PERMISSION_WARNING"] = "1"
				want = ""
			case "same_file_twice", "symlink_same_file", "hardlink_same_file":
				credentialPath = harness.passPath
				if source == "symlink_same_file" {
					credentialPath = filepath.Join(harness.temp, "master-link")
					if err := os.Symlink(harness.passPath, credentialPath); err != nil {
						t.Fatal(err)
					}
				}
				if source == "hardlink_same_file" {
					credentialPath = filepath.Join(harness.temp, "master-hardlink")
					if err := os.Link(harness.passPath, credentialPath); err != nil {
						t.Fatal(err)
					}
				}
			}
			args := []string{"--json", "host", "add", "permission-host", "--host", "192.0.2.80", "--user", "runner", "--password-file", credentialPath, "--offline"}
			if source == "flag" {
				args = append([]string{"--master-pass-file", harness.passPath}, args...)
			}
			result := harness.RunWithEnv(t, "ssm", nil, env, args...)
			assertCredentialPermissionResult(t, result, want, harness.passPath)
		})
	}
}

func TestCredentialPermissionInputReaders(t *testing.T) {
	for _, source := range []string{"cloud_password", "secret", "request_secrets", "script"} {
		t.Run(source, func(t *testing.T) {
			t.Setenv("SSM_NO_PERMISSION_WARNING", "")
			path := writeCredentialPermissionFixture(t, t.TempDir(), 0o644)
			warning := captureCredentialPermissionStderr(t, func() {
				switch source {
				case "cloud_password":
					if got := readSecretFile(path, "password"); got != "PERMISSION_CONTENT_CANARY" {
						t.Fatalf("password content changed: %q", got)
					}
				case "secret":
					secrets := make(map[string]string)
					for _, name := range []string{"FIRST", "SECOND"} {
						if err := parseSecretKV(name+"=@"+path, secrets); err != nil {
							t.Fatal(err)
						}
						if secrets[name] != "PERMISSION_CONTENT_CANARY" {
							t.Fatal("secret content changed")
						}
					}
				case "request_secrets":
					spec, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "permission-host", Argv: []string{"true"}, SecretFiles: map[string]string{"FIRST": path, "SECOND": path}})
					if err != nil {
						t.Fatal(err)
					}
					if spec.Secrets["FIRST"] != "PERMISSION_CONTENT_CANARY" || spec.Secrets["SECOND"] != "PERMISSION_CONTENT_CANARY" {
						t.Fatal("request secret content changed")
					}
				case "script":
					if _, err := readScriptFile(path); err != nil {
						t.Fatal(err)
					}
				}
			})
			want := "warning: --secret is readable by other users; run chmod 600 on it\n"
			switch source {
			case "cloud_password":
				want = "warning: --password-file is readable by other users; run chmod 600 on it\n"
			case "script":
				want = ""
			}
			if warning != want {
				t.Fatalf("stderr = %q, want %q", warning, want)
			}
		})
	}
}

func writeCredentialPermissionFixture(t *testing.T, directory string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, "PERMISSION_PATH_CANARY")
	if err := os.WriteFile(path, []byte("PERMISSION_CONTENT_CANARY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { //nolint:gosec // explicit broad modes are necessary to test permission warnings
		t.Fatal(err)
	}
	return path
}

func assertCredentialPermissionResult(t *testing.T, result compiledCLIResult, warning, path string) {
	t.Helper()
	if result.ProcessExit != 0 {
		t.Fatalf("credential-file command exit = %d, stdout = %q, stderr = %q", result.ProcessExit, result.Stdout, result.Stderr)
	}
	decodeExactlyOneJSONObject(t, result.Stdout)
	if result.Stderr != warning {
		t.Fatalf("stderr = %q, want %q", result.Stderr, warning)
	}
	for _, forbidden := range []string{path, "PERMISSION_PATH_CANARY", "PERMISSION_CONTENT_CANARY", "ISSUE17_MASTER_PASSPHRASE_CANARY"} {
		if strings.Contains(result.Stderr, forbidden) {
			t.Fatal("credential permission warning leaked a path or credential")
		}
	}
}

func captureCredentialPermissionStderr(t *testing.T, read func()) string {
	t.Helper()
	// Inode numbers are reused after a temporary file is removed, so a stale
	// entry from an earlier subtest could suppress this subtest's warning.
	warnedCredentialFiles.Lock()
	warnedCredentialFiles.files = nil
	warnedCredentialFiles.Unlock()
	path := filepath.Join(t.TempDir(), "stderr")
	file, err := os.Create(path) //nolint:gosec // this output capture is confined to the test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = file
	defer func() {
		os.Stderr = original
		_ = file.Close()
	}()
	read()
	data, err := os.ReadFile(path) //nolint:gosec // reads only this test-owned stderr capture
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
