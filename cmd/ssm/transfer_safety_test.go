package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ssm/internal/config"
)

const compiledDownloadSafetyPassword = "ISSUE26_DOWNLOAD_SAFETY_PASSWORD_CANARY"

type compiledDownloadSafetyFixture struct {
	cli        *compiledCLIHarness
	alias      string
	remoteFile string
	remoteDir  string
}

func newCompiledDownloadSafetyFixture(t *testing.T, options compiledSSHFixtureOptions) compiledDownloadSafetyFixture {
	t.Helper()
	options.Password = compiledDownloadSafetyPassword
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, options)
	cli.TrustSSHHost(t, server)
	const alias = "download-safety"
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{server.Connection(alias, compiledDownloadSafetyPassword)},
	})

	remoteRoot := t.TempDir()
	remoteFile := filepath.Join(remoteRoot, "artifact")
	if err := os.WriteFile(remoteFile, []byte("REMOTE_FILE_CONTENT_CANARY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteDir := filepath.Join(remoteRoot, "tree")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteDir, "remote.txt"), []byte("REMOTE_DIRECTORY_CONTENT_CANARY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return compiledDownloadSafetyFixture{
		cli: cli, alias: alias, remoteFile: remoteFile, remoteDir: remoteDir,
	}
}

func TestCompiledRegularDownloadRemoteReadFailurePreservesDestinationAndRemovesTemps(t *testing.T) {
	fixture := newCompiledDownloadSafetyFixture(t, compiledSSHFixtureOptions{
		RunCommandContains: "cat -- ",
		RunStdoutFragments: []string{"PARTIAL_REMOTE_FILE_CONTENT_CANARY\n"},
		RunExitStatus:      23,
	})
	for _, route := range []string{"direct", "request-v1"} {
		route := route
		t.Run(route, func(t *testing.T) {
			destination := filepath.Join(fixture.cli.temp, "file-"+route)
			const original = "EXISTING_FILE_CONTENT_CANARY\n"
			if err := os.WriteFile(destination, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}

			result := runCompiledDownloadSafetyRoute(t, fixture, route, fixture.remoteFile, destination)
			assertCompiledDownloadSafetyFailure(t, result, fixture.alias, "file", "remote_read_failed", "remote_read")
			assertCompiledSafetyFileContents(t, destination, original)
			assertNoCompiledDownloadTemporaryOutputs(t, fixture.cli.temp)
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"password":       compiledDownloadSafetyPassword,
				"existing_file":  original,
				"remote_content": "REMOTE_FILE_CONTENT_CANARY",
				"partial_file":   "PARTIAL_REMOTE_FILE_CONTENT_CANARY",
			})
		})
	}
}

func TestCompiledDirectoryDownloadStreamFailuresPreserveDestinationAndRemoveTemps(t *testing.T) {
	tests := []struct {
		name      string
		options   compiledSSHFixtureOptions
		wantError string
		wantStage string
	}{
		{
			name: "remote read",
			options: compiledSSHFixtureOptions{
				RunCommandContains: "-cf - .",
				RunStdoutFragments: []string{"partial remote tar stream\n"},
				RunExitStatus:      23,
			},
			wantError: "remote_read_failed",
			wantStage: "remote_read",
		},
		{
			name: "local extraction write",
			options: compiledSSHFixtureOptions{
				RunCommandContains: "-cf - .",
				RunStdoutFragments: []string{"invalid tar stream\n"},
			},
			wantError: "local_write_failed",
			wantStage: "local_write",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newCompiledDownloadSafetyFixture(t, test.options)
			for _, route := range []string{"direct", "request-v1"} {
				route := route
				t.Run(route, func(t *testing.T) {
					destination := filepath.Join(fixture.cli.temp, "directory-"+route)
					writeCompiledPreservedDirectoryFixture(t, destination)

					result := runCompiledDownloadSafetyRoute(t, fixture, route, fixture.remoteDir, destination)
					assertCompiledDownloadSafetyFailure(t, result, fixture.alias, "directory", test.wantError, test.wantStage)
					assertCompiledPreservedDirectoryFixture(t, destination)
					assertNoCompiledDownloadTemporaryOutputs(t, fixture.cli.temp)
					assertNoCompiledCanaryLeak(t, result, map[string]string{
						"password":         compiledDownloadSafetyPassword,
						"existing_file":    "EXISTING_DIRECTORY_CONTENT_CANARY",
						"remote_directory": "REMOTE_DIRECTORY_CONTENT_CANARY",
					})
				})
			}
		})
	}
}

func runCompiledDownloadSafetyRoute(
	t *testing.T,
	fixture compiledDownloadSafetyFixture,
	route, remotePath, localPath string,
) compiledCLIResult {
	t.Helper()
	if route == "direct" {
		return fixture.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", fixture.alias, remotePath, localPath)
	}
	body, err := json.Marshal(map[string]any{
		"version": 1, "op": "get", "alias": fixture.alias,
		"remote_path": remotePath, "local_path": localPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture.cli.Run(t, "sshctl", body, "request", "-")
}

func assertCompiledDownloadSafetyFailure(
	t *testing.T,
	result compiledCLIResult,
	alias, kind, wantError, wantStage string,
) {
	t.Helper()
	if result.ProcessExit == 0 {
		t.Fatalf("download failure process exit = 0, want non-zero; output=%s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	if got, ok := value["ok"].(bool); !ok || got {
		t.Fatalf("download failure ok = %v, want false; output=%s", value["ok"], compiledOutputIdentity(result))
	}
	for field, want := range map[string]string{
		"error":     wantError,
		"stage":     wantStage,
		"alias":     alias,
		"direction": "get",
		"kind":      kind,
	} {
		assertCompiledStringField(t, value, field, want, result)
	}
	if !compiledJSONExitEquals(value["exit"], result.ProcessExit) {
		t.Fatalf("download failure JSON exit = %v, want process exit %d; output=%s", value["exit"], result.ProcessExit, compiledOutputIdentity(result))
	}
}

func writeCompiledPreservedDirectoryFixture(t *testing.T, destination string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(destination, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "existing.txt"), []byte("EXISTING_DIRECTORY_CONTENT_CANARY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "nested", "keep.txt"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertCompiledPreservedDirectoryFixture(t *testing.T, destination string) {
	t.Helper()
	assertCompiledSafetyFileContents(t, filepath.Join(destination, "existing.txt"), "EXISTING_DIRECTORY_CONTENT_CANARY\n")
	assertCompiledSafetyFileContents(t, filepath.Join(destination, "nested", "keep.txt"), "keep\n")
	if _, err := os.Stat(filepath.Join(destination, "remote.txt")); !os.IsNotExist(err) {
		t.Fatalf("failed directory download left remote-only output: %v", err)
	}
}

func assertCompiledSafetyFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is always beneath a test-owned temporary directory
	if err != nil || string(data) != want {
		t.Fatalf("file %q contents = %q, error = %v, want %q", path, data, err, want)
	}
}

func assertNoCompiledDownloadTemporaryOutputs(t *testing.T, parent string) {
	t.Helper()
	outputs, err := filepath.Glob(filepath.Join(parent, ".ssm-get-*"))
	if err != nil || len(outputs) != 0 {
		t.Fatalf("download temporary outputs = %v, error = %v", outputs, err)
	}
}
