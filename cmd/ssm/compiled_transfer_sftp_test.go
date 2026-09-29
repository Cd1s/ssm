package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"ssm/internal/config"
)

// Issue #87: transfers over the sftp subsystem for targets without a POSIX
// shell. The fixture serves only the sftp subsystem and rejects every exec
// request, so any shell command in the transfer path fails the test.

type sftpEnv struct {
	cli    *compiledCLIHarness
	server *compiledSSHFixture
	alias  string
}

func newSFTPEnv(t *testing.T, transfer string) sftpEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the in-process sftp server addresses the local file system with POSIX paths")
	}
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: issue80Password, SFTP: true, RejectExec: true})
	cli.TrustSSHHost(t, server)
	const alias = "sftp87"
	connection := server.Connection(alias, issue80Password)
	connection.Transfer = transfer
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{connection}})
	return sftpEnv{cli: cli, server: server, alias: alias}
}

func sftpPayload(size int) ([]byte, string) {
	data := bytes.Repeat([]byte("sftp-transfer-payload-0123456789\n"), size/33+1)[:size]
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:])
}

func sftpRequireNoExec(t *testing.T, env sftpEnv) {
	t.Helper()
	if commands := env.server.Commands(); len(commands) != 0 {
		t.Fatalf("SFTP transfer executed shell commands: %v", commands)
	}
}

func sftpNoStagingLeft(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".ssm-") {
			t.Fatalf("temporary file left behind in %s: %s", dir, entry.Name())
		}
	}
}

func TestCompiledSFTPGetFile(t *testing.T) {
	data, digest := sftpPayload(3<<20 + 17)
	for _, tc := range []struct {
		name     string
		transfer string
		flag     bool
	}{
		{name: "flag", flag: true},
		{name: "vault setting", transfer: "sftp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newSFTPEnv(t, tc.transfer)
			remote := filepath.Join(t.TempDir(), "payload.bin")
			issue80WriteFile(t, remote, data)
			local := filepath.Join(env.cli.temp, "out", "payload.bin")
			args := []string{"--offline", "--json", "get", env.alias, remote, local, "--sha256", "--timeout", "1m"}
			if tc.flag {
				args = append(args, "--sftp")
			}
			result := env.cli.Run(t, "sshctl", nil, args...)
			got := issue80JSON(t, result)
			if result.ProcessExit != 0 || got["ok"] != true || got["direction"] != "get" || got["kind"] != "file" ||
				got["integrity"] != "sha256_verified" || got["local_sha256"] != digest || got["remote_sha256"] != digest ||
				got["atomic"] != true || got["resume"] != "unsupported" || got["bytes_received"] != float64(len(data)) {
				t.Fatalf("sftp get = %s", compiledOutputIdentity(result))
			}
			written, err := os.ReadFile(local) //nolint:gosec // test-owned fixture path
			if err != nil || !bytes.Equal(written, data) {
				t.Fatalf("downloaded bytes differ: err=%v len=%d", err, len(written))
			}
			sftpNoStagingLeft(t, filepath.Dir(local))
			sftpRequireNoExec(t, env)
		})
	}
	t.Run("without --sha256 no integrity is claimed", func(t *testing.T) {
		env := newSFTPEnv(t, "sftp")
		remote := filepath.Join(t.TempDir(), "payload.bin")
		issue80WriteFile(t, remote, []byte("small"))
		local := filepath.Join(env.cli.temp, "small.bin")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, remote, local)
		got := issue80JSON(t, result)
		if result.ProcessExit != 0 || got["ok"] != true || got["integrity"] != "not_checked" || got["atomic"] != true {
			t.Fatalf("sftp get = %s", compiledOutputIdentity(result))
		}
	})
	t.Run("missing remote file publishes nothing", func(t *testing.T) {
		env := newSFTPEnv(t, "sftp")
		local := filepath.Join(env.cli.temp, "missing.bin")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, filepath.Join(t.TempDir(), "nope"), local)
		issue80RequireFailure(t, result, 1, "remote_read_failed", "remote_read")
		if _, err := os.Stat(local); err == nil {
			t.Fatal("a failed get published a file")
		}
		sftpNoStagingLeft(t, env.cli.temp)
	})
	t.Run("replaces an existing local file only on success", func(t *testing.T) {
		env := newSFTPEnv(t, "sftp")
		local := filepath.Join(env.cli.temp, "keep.bin")
		issue80WriteFile(t, local, []byte("previous"))
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, filepath.Join(t.TempDir(), "nope"), local)
		issue80RequireFailure(t, result, 1, "remote_read_failed", "remote_read")
		if kept, _ := os.ReadFile(local); string(kept) != "previous" { //nolint:gosec // test-owned fixture path
			t.Fatalf("failed get replaced the local file: %q", kept)
		}
	})
}

func TestCompiledSFTPDirectoriesAndResumeAreUnsupported(t *testing.T) {
	env := newSFTPEnv(t, "sftp")
	remoteDir := t.TempDir()
	issue80WriteFile(t, filepath.Join(remoteDir, "a.txt"), []byte("a"))
	local := filepath.Join(env.cli.temp, "tree")
	result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, remoteDir, local)
	got := issue80RequireFailure(t, result, 1, "unsupported_transfer_option", "validate")
	if got["kind"] != "directory" || got["direction"] != "get" {
		t.Fatalf("outcome identity = %v", got)
	}
	if _, err := os.Stat(local); err == nil {
		t.Fatal("directory get created the local destination")
	}

	localDir := filepath.Join(env.cli.temp, "src")
	issue80WriteFile(t, filepath.Join(localDir, "a.txt"), []byte("a"))
	target := filepath.Join(t.TempDir(), "dest")
	result = env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, localDir, target)
	got = issue80RequireFailure(t, result, 1, "unsupported_transfer_option", "validate")
	if got["kind"] != "directory" || got["direction"] != "put" {
		t.Fatalf("outcome identity = %v", got)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("directory put created the remote destination")
	}

	file := filepath.Join(env.cli.temp, "f.bin")
	issue80WriteFile(t, file, []byte("x"))
	result = env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, file, filepath.Join(t.TempDir(), "f"), "--resume=v1")
	issue80RequireFailure(t, result, 1, "unsupported_transfer_option", "validate")
	sftpRequireNoExec(t, env)
}

func TestCompiledSFTPPutFile(t *testing.T) {
	modeOf := func(t *testing.T, path string) os.FileMode {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}
	data, digest := sftpPayload(2<<20 + 5)
	t.Run("new file with parents, digest and modes", func(t *testing.T) {
		env := newSFTPEnv(t, "")
		local := filepath.Join(env.cli.temp, "artifact.bin")
		issue80WriteFile(t, local, data)
		if err := os.Chmod(local, 0o640); err != nil { //nolint:gosec // the test needs a group-readable source file to verify mode preservation
			t.Fatal(err)
		}
		root := t.TempDir()
		remote := filepath.Join(root, "new", "deep", "artifact.bin")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, remote, "--sftp", "--sha256", "--dir-mode", "0750", "--timeout", "1m")
		got := issue80JSON(t, result)
		if result.ProcessExit != 0 || got["ok"] != true || got["direction"] != "put" || got["kind"] != "file" ||
			got["integrity"] != "sha256_verified" || got["local_sha256"] != digest || got["remote_sha256"] != digest ||
			got["atomic"] != true || got["bytes_sent"] != float64(len(data)) {
			t.Fatalf("sftp put = %s", compiledOutputIdentity(result))
		}
		written, err := os.ReadFile(remote) //nolint:gosec // test-owned fixture path
		if err != nil || !bytes.Equal(written, data) {
			t.Fatalf("uploaded bytes differ: err=%v len=%d", err, len(written))
		}
		if mode := modeOf(t, remote); mode != 0o640 {
			t.Fatalf("file mode = %o, want 640", mode)
		}
		for _, dir := range []string{"new", filepath.Join("new", "deep")} {
			if mode := modeOf(t, filepath.Join(root, dir)); mode != 0o750 {
				t.Fatalf("%s mode = %o, want 750", dir, mode)
			}
		}
		sftpNoStagingLeft(t, filepath.Dir(remote))
		sftpRequireNoExec(t, env)
	})
	t.Run("vault setting replaces an existing file atomically", func(t *testing.T) {
		env := newSFTPEnv(t, "sftp")
		local := filepath.Join(env.cli.temp, "artifact.bin")
		issue80WriteFile(t, local, []byte("new contents"))
		remote := filepath.Join(t.TempDir(), "artifact.bin")
		issue80WriteFile(t, remote, []byte("old"))
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, remote)
		got := issue80JSON(t, result)
		if result.ProcessExit != 0 || got["ok"] != true || got["atomic"] != true || got["integrity"] != "size_verified" {
			t.Fatalf("sftp put = %s", compiledOutputIdentity(result))
		}
		if written, _ := os.ReadFile(remote); string(written) != "new contents" { //nolint:gosec // test-owned fixture path
			t.Fatalf("remote = %q", written)
		}
		sftpNoStagingLeft(t, filepath.Dir(remote))
		sftpRequireNoExec(t, env)
	})
	t.Run("server without posix-rename reports atomic false", func(t *testing.T) {
		if err := sftp.SetSFTPExtensions(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := sftp.SetSFTPExtensions("hardlink@openssh.com", "posix-rename@openssh.com", "statvfs@openssh.com"); err != nil {
				t.Error(err)
			}
		})
		env := newSFTPEnv(t, "sftp")
		local := filepath.Join(env.cli.temp, "artifact.bin")
		issue80WriteFile(t, local, []byte("replacement"))
		remote := filepath.Join(t.TempDir(), "artifact.bin")
		issue80WriteFile(t, remote, []byte("old"))
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, remote, "--sha256")
		got := issue80JSON(t, result)
		if result.ProcessExit != 0 || got["ok"] != true || got["atomic"] != false || got["integrity"] != "sha256_verified" {
			t.Fatalf("sftp put without posix-rename = %s", compiledOutputIdentity(result))
		}
		if written, _ := os.ReadFile(remote); string(written) != "replacement" { //nolint:gosec // test-owned fixture path
			t.Fatalf("remote = %q", written)
		}
		sftpNoStagingLeft(t, filepath.Dir(remote))
	})
	t.Run("missing local file fails before connecting", func(t *testing.T) {
		env := newSFTPEnv(t, "sftp")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, filepath.Join(env.cli.temp, "nope"), "/remote/x")
		issue80RequireFailure(t, result, 255, "local_read_failed", "local_read")
		if env.server.ConnectionCount() != 0 {
			t.Fatal("a missing local file reached the network")
		}
	})
	t.Run("unwritable remote directory leaves the destination untouched", func(t *testing.T) {
		env := newSFTPEnv(t, "sftp")
		local := filepath.Join(env.cli.temp, "artifact.bin")
		issue80WriteFile(t, local, []byte("data"))
		blocker := filepath.Join(t.TempDir(), "file")
		issue80WriteFile(t, blocker, []byte("not a directory"))
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, filepath.Join(blocker, "sub", "artifact.bin"))
		issue80RequireFailure(t, result, 1, "remote_write_failed", "remote_write")
		if kept, _ := os.ReadFile(blocker); string(kept) != "not a directory" { //nolint:gosec // test-owned fixture path
			t.Fatalf("blocker changed: %q", kept)
		}
	})
}

func TestCompiledSFTPUnavailableIsReportedExplicitly(t *testing.T) {
	env := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: issue80Password})
	env.TrustSSHHost(t, server)
	env.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("nosftp", issue80Password)}})
	local := filepath.Join(env.temp, "f.bin")
	issue80WriteFile(t, local, []byte("x"))
	result := env.Run(t, "sshctl", nil, "--offline", "--json", "put", "nosftp", local, "/remote/f.bin", "--sftp")
	issue80RequireFailure(t, result, 1, "sftp_unavailable", "capability")
	result = env.Run(t, "sshctl", nil, "--offline", "--json", "get", "nosftp", "/remote/f.bin", filepath.Join(env.temp, "out"), "--sftp")
	issue80RequireFailure(t, result, 1, "sftp_unavailable", "capability")
	if commands := server.Commands(); len(commands) != 0 {
		t.Fatalf("--sftp must not fall back to shell commands: %v", commands)
	}
}

func TestCompiledAutoTransferReportsUnsupportedRemoteShell(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe compiledPathProbe
	}{
		{name: "unparseable output", probe: compiledPathProbe{Stdout: "Microsoft Windows [Version 10.0]\r\n'if' is not recognized\r\n"}},
		{name: "shell error", probe: compiledPathProbe{Stderr: "sh: syntax error: unexpected token\n", Exit: 2}},
		{name: "command not found", probe: compiledPathProbe{Stderr: "if: command not found\n", Exit: 127}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := tc.probe
			env := newIssue80Env(t, compiledSSHFixtureOptions{PathProbe: &probe})
			local := filepath.Join(env.cli.temp, "out")
			result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, "/remote/f.bin", local)
			got := issue80RequireFailure(t, result, 1, "remote_shell_unsupported", "discovery")
			hint, _ := got["hint"].(string)
			if !strings.Contains(hint, "--sftp") || !strings.Contains(hint, "transfer: sftp") {
				t.Fatalf("hint does not point to SFTP: %v", got)
			}
			if _, err := os.Stat(local); err == nil {
				t.Fatal("a failed get published a file")
			}
		})
	}
	t.Run("a genuinely missing path is still a path error", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{})
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, filepath.Join(t.TempDir(), "absent"), filepath.Join(env.cli.temp, "out"))
		got := issue80JSON(t, result)
		message, _ := got["message"].(string)
		if result.ProcessExit == 0 || got["ok"] != false || got["error"] != "internal" || got["stage"] != "discovery" ||
			!strings.Contains(message, "remote path") || !strings.Contains(message, "not found") {
			t.Fatalf("missing path = %s", compiledOutputIdentity(result))
		}
	})
}

func TestCompiledRequestV1AcceptsTransferField(t *testing.T) {
	env := newSFTPEnv(t, "")
	data, digest := sftpPayload(4096)
	local := filepath.Join(env.cli.temp, "artifact.bin")
	issue80WriteFile(t, local, data)
	remote := filepath.Join(t.TempDir(), "artifact.bin")
	put, err := json.Marshal(map[string]any{
		"version": 1, "op": "put", "alias": env.alias, "local_path": local, "remote_path": remote,
		"transfer": "sftp", "sha256": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := env.cli.Run(t, "sshctl", put, "request", "-")
	if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true || got["remote_sha256"] != digest || got["atomic"] != true {
		t.Fatalf("request put = %s", compiledOutputIdentity(result))
	}
	fetched := filepath.Join(env.cli.temp, "fetched.bin")
	get, err := json.Marshal(map[string]any{
		"version": 1, "op": "get", "alias": env.alias, "remote_path": remote, "local_path": fetched,
		"transfer": "sftp", "sha256": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result = env.cli.Run(t, "sshctl", get, "request", "-")
	if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true || got["local_sha256"] != digest {
		t.Fatalf("request get = %s", compiledOutputIdentity(result))
	}
	if written, _ := os.ReadFile(fetched); !bytes.Equal(written, data) { //nolint:gosec // test-owned fixture path
		t.Fatal("request get bytes differ")
	}
	for _, op := range []string{"put", "get"} {
		body, err := json.Marshal(map[string]any{
			"version": 1, "op": op, "alias": env.alias, "local_path": local, "remote_path": remote, "transfer": "carrier-pigeon",
		})
		if err != nil {
			t.Fatal(err)
		}
		result := env.cli.Run(t, "sshctl", body, "request", "-")
		if got := issue80JSON(t, result); result.ProcessExit == 0 || got["ok"] != false || got["error"] != "invalid_request" {
			t.Fatalf("request %s with a bad transfer = %s", op, compiledOutputIdentity(result))
		}
	}
	sftpRequireNoExec(t, env)
}

func TestCompiledHostTransferField(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	passwordPath := filepath.Join(cli.temp, "host.pass")
	issue80WriteFile(t, passwordPath, []byte("transfer-host-credential\n"))
	show := func(t *testing.T) map[string]any {
		t.Helper()
		result := cli.Run(t, "sshctl", nil, "--json", "host", "show", "win", "--offline")
		return issue80JSON(t, result)
	}
	add := cli.Run(t, "sshctl", nil, "--json", "host", "add", "win", "--host", "192.0.2.80", "--user", "runner",
		"--password-file", passwordPath, "--transfer", "sftp", "--offline")
	if got := issue80JSON(t, add); add.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("host add --transfer = %s", compiledOutputIdentity(add))
	}
	if got := show(t); got["transfer"] != "sftp" {
		t.Fatalf("host show after add = %v", got)
	}
	unrelated := cli.Run(t, "sshctl", nil, "--json", "host", "update", "win", "--group", "lab", "--offline")
	if got := issue80JSON(t, unrelated); unrelated.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("host update = %s", compiledOutputIdentity(unrelated))
	}
	if got := show(t); got["transfer"] != "sftp" || got["group"] != "lab" {
		t.Fatalf("an unrelated update must keep transfer: %v", got)
	}
	reset := cli.Run(t, "sshctl", nil, "--json", "host", "update", "win", "--transfer", "auto", "--offline")
	if got := issue80JSON(t, reset); reset.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("host update --transfer auto = %s", compiledOutputIdentity(reset))
	}
	if got := show(t); got["transfer"] != nil {
		t.Fatalf("auto is the default and is not stored: %v", got)
	}
	bad := cli.Run(t, "sshctl", nil, "--json", "host", "update", "win", "--transfer", "carrier-pigeon", "--offline")
	if got := issue80JSON(t, bad); bad.ProcessExit != 2 || got["ok"] != false || got["error"] != "invalid_arguments" {
		t.Fatalf("host update --transfer bogus = %s", compiledOutputIdentity(bad))
	}

	request, err := json.Marshal(map[string]any{
		"version": 1, "op": "host.upsert", "alias": "win",
		"host": map[string]any{
			"address": "192.0.2.80", "user": "runner", "transfer": "shell",
			"password_file": passwordPath, "offline": true, "verify": false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	upsert := cli.Run(t, "sshctl", request, "request", "-")
	if got := issue80JSON(t, upsert); upsert.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("request host.upsert transfer = %s", compiledOutputIdentity(upsert))
	}
	if got := show(t); got["transfer"] != "shell" {
		t.Fatalf("host show after request = %v", got)
	}
}

// A target that only offers the sftp subsystem refuses exec requests. Without
// an explicit SFTP choice that is reported as an unsupported shell, and an
// explicit shell override wins over a stored transfer: sftp.
func TestCompiledExecRefusedIsAnUnsupportedRemoteShell(t *testing.T) {
	env := newSFTPEnv(t, "")
	local := filepath.Join(env.cli.temp, "f.bin")
	issue80WriteFile(t, local, []byte("x"))
	remote := filepath.Join(t.TempDir(), "f.bin")
	result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, remote, filepath.Join(env.cli.temp, "out"))
	issue80RequireFailure(t, result, 1, "remote_shell_unsupported", "discovery")
	result = env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, remote)
	got := issue80RequireFailure(t, result, 1, "remote_shell_unsupported", "discovery")
	if hint, _ := got["hint"].(string); !strings.Contains(hint, "--sftp") {
		t.Fatalf("hint does not point to SFTP: %v", got)
	}
	if _, err := os.Stat(remote); err == nil {
		t.Fatal("a failed put published a file")
	}

	pinned := newSFTPEnv(t, "sftp")
	body, err := json.Marshal(map[string]any{
		"version": 1, "op": "put", "alias": pinned.alias, "local_path": local, "remote_path": remote, "transfer": "shell",
	})
	if err != nil {
		t.Fatal(err)
	}
	result = pinned.cli.Run(t, "sshctl", body, "request", "-")
	issue80RequireFailure(t, result, 1, "remote_shell_unsupported", "discovery")
}

func TestCompiledSFTPPutRejectsDirectoryDestination(t *testing.T) {
	for _, tc := range []struct {
		name        string
		posixRename bool
	}{
		{name: "posix-rename", posixRename: true},
		{name: "fallback without posix-rename"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.posixRename {
				if err := sftp.SetSFTPExtensions(); err != nil {
					t.Fatal(err)
				}
				// pkg/sftp exposes no getter for the active extension list, so
				// restore the documented defaults.
				t.Cleanup(func() {
					if err := sftp.SetSFTPExtensions("hardlink@openssh.com", "posix-rename@openssh.com", "statvfs@openssh.com"); err != nil {
						t.Error(err)
					}
				})
			}
			env := newSFTPEnv(t, "sftp")
			local := filepath.Join(env.cli.temp, "artifact.bin")
			issue80WriteFile(t, local, []byte("data"))
			dest := t.TempDir()
			issue80WriteFile(t, filepath.Join(dest, "keep.txt"), []byte("keep"))
			result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, dest)
			got := issue80RequireFailure(t, result, 1, "remote_write_failed", "remote_write")
			if message, _ := got["message"].(string); !strings.Contains(message, "is a directory") {
				t.Fatalf("message = %v", got["message"])
			}
			if kept, err := os.ReadFile(filepath.Join(dest, "keep.txt")); err != nil || string(kept) != "keep" { //nolint:gosec // test-owned fixture path
				t.Fatalf("destination directory was displaced: %v %q", err, kept)
			}
			entries, _ := os.ReadDir(filepath.Dir(dest))
			for _, entry := range entries {
				if strings.Contains(entry.Name(), ".ssm-") {
					t.Fatalf("leftover %s", entry.Name())
				}
			}
		})
	}
}

// A deadline that expires mid-upload closes the transfer's sftp client; the
// temporary file must still be cleaned up (over a fresh sftp session).
func TestCompiledSFTPPutTimeoutCleansTemporaryFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the in-process sftp server addresses the local file system with POSIX paths")
	}
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: issue80Password, SFTP: true, RejectExec: true, SFTPReadDelay: 40 * time.Millisecond,
	})
	cli.TrustSSHHost(t, server)
	connection := server.Connection("slow", issue80Password)
	connection.Transfer = "sftp"
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{connection}})
	data, _ := sftpPayload(6 << 20)
	local := filepath.Join(cli.temp, "big.bin")
	issue80WriteFile(t, local, data)
	remoteDir := t.TempDir()
	remote := filepath.Join(remoteDir, "big.bin")
	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "slow", local, remote, "--timeout", "1s")
	issue80RequireFailure(t, result, 1, "transfer_timeout", "timeout")
	if _, err := os.Stat(remote); err == nil {
		t.Fatal("a timed-out put published the destination")
	}
	entries, err := os.ReadDir(remoteDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".ssm-upload.") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}
