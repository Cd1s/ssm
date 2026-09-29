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

	"ssm/internal/config"
)

const issue80Password = "ISSUE80_TRANSFER_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

type issue80Env struct {
	cli    *compiledCLIHarness
	server *compiledSSHFixture
	alias  string
}

func newIssue80Env(t *testing.T, options compiledSSHFixtureOptions) issue80Env {
	t.Helper()
	options.Password = issue80Password
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, options)
	cli.TrustSSHHost(t, server)
	const alias = "issue80"
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection(alias, issue80Password)}})
	return issue80Env{cli: cli, server: server, alias: alias}
}

func issue80JSON(t *testing.T, result compiledCLIResult) map[string]any {
	t.Helper()
	return decodeExactlyOneJSONObject(t, result.Stdout)
}

// issue80LastJSON decodes the trailing JSON document; a failed local tar replays its
// own (redacted) stdout diagnostics ahead of the machine document.
func issue80LastJSON(t *testing.T, result compiledCLIResult) map[string]any {
	t.Helper()
	start := strings.LastIndex(result.Stdout, "\n{") + 1
	return decodeExactlyOneJSONObject(t, result.Stdout[start:])
}

func issue80RequireFailure(t *testing.T, result compiledCLIResult, wantExit int, wantError, wantStage string) map[string]any {
	t.Helper()
	got := issue80JSON(t, result)
	if result.ProcessExit != wantExit || got["ok"] != false || got["error"] != wantError || got["stage"] != wantStage {
		t.Fatalf("failure = exit %d %v, want exit=%d error=%s stage=%s", result.ProcessExit, got, wantExit, wantError, wantStage)
	}
	if strings.Contains(result.Stdout+result.Stderr, issue80Password) {
		t.Fatalf("credential canary leaked: %s", compiledOutputIdentity(result))
	}
	return got
}

func issue80WriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func issue80EmptyPathDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// --- directory put -------------------------------------------------------

func TestCompiledDirectoryPutReportsRemoteExtractFailureWithoutFallback(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{name: "large payload local tar sees EPIPE", size: 6 << 20},
		{name: "small payload local tar finishes first", size: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newIssue80Env(t, compiledSSHFixtureOptions{UploadTarFailStderr: "tar: ./item.bin: Cannot open: Permission denied"})
			local := filepath.Join(env.cli.temp, "src")
			issue80WriteFile(t, filepath.Join(local, "item.bin"), bytes.Repeat([]byte("x"), tc.size))
			remote := filepath.Join(t.TempDir(), "dest")
			result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, remote)
			got := issue80RequireFailure(t, result, 1, "remote_write_failed", "remote_extract")
			if message, _ := got["message"].(string); !strings.Contains(message, "Permission denied") {
				t.Fatalf("remote tar message not reported first-hand: %v", got)
			}
			if got["kind"] != "directory" || got["direction"] != "put" {
				t.Fatalf("outcome identity = %v", got)
			}
			if hint, _ := got["hint"].(string); !strings.Contains(hint, "partially extracted") {
				t.Fatalf("hint does not warn about partial writes: %v", got)
			}
			if entries, err := os.ReadDir(remote); err == nil && len(entries) != 0 {
				t.Fatalf("per-file fallback wrote %d entries", len(entries))
			}
			// One session for the tar extractor; the per-file fallback would
			// open more (one per file).
			if sessions := env.server.SessionCount(); sessions != 1 {
				t.Fatalf("SSH sessions = %d, want 1 (no fallback)", sessions)
			}
		})
	}
}

func TestCompiledDirectoryPutFailingLocalTarDoesNotFallBack(t *testing.T) {
	env := newIssue80Env(t, compiledSSHFixtureOptions{})
	local := filepath.Join(env.cli.temp, "src")
	issue80WriteFile(t, filepath.Join(local, "item.txt"), []byte("body"))
	remote := filepath.Join(t.TempDir(), "dest")
	result := env.cli.RunWithEnv(t, "sshctl", nil, map[string]string{
		"PATH":                env.cli.TarFailureHelperDir(t),
		"SSM_TEST_TAR_HELPER": "1",
	}, "--offline", "--json", "put", env.alias, local, remote)
	// The helper tar emits garbage, so the remote extractor exits non-zero too;
	// the remote exit decides, and the local diagnostics are appended.
	got := issue80RequireFailure(t, result, 1, "remote_write_failed", "remote_extract")
	if message, _ := got["message"].(string); !strings.Contains(message, "local tar also reported") {
		t.Fatalf("local tar failure not mentioned: %v", got)
	}
	if _, err := os.Stat(filepath.Join(remote, "item.txt")); err == nil {
		t.Fatal("a failing local tar fell back to per-file upload")
	}
}

func TestCompiledDirectoryPutFallsBackOnlyWhenLocalTarIsMissing(t *testing.T) {
	env := newIssue80Env(t, compiledSSHFixtureOptions{})
	local := filepath.Join(env.cli.temp, "src")
	issue80WriteFile(t, filepath.Join(local, "sub", "item.txt"), []byte("fallback body"))
	remote := filepath.Join(t.TempDir(), "dest")
	result := env.cli.RunWithEnv(t, "sshctl", nil, map[string]string{"PATH": issue80EmptyPathDir(t)},
		"--offline", "--json", "put", env.alias, local, remote)
	got := issue80JSON(t, result)
	if result.ProcessExit != 0 || got["ok"] != true || got["kind"] != "directory" {
		t.Fatalf("fallback with missing tar failed: %s", compiledOutputIdentity(result))
	}
	data, err := os.ReadFile(filepath.Join(remote, "sub", "item.txt")) //nolint:gosec // beneath test-owned remote root
	if err != nil || string(data) != "fallback body" {
		t.Fatalf("fallback data=%q err=%v", data, err)
	}
}

// --- directory get -------------------------------------------------------

func TestCompiledDirectoryGetFailsInBoundedTimeWhenLocalTarExits(t *testing.T) {
	env := newIssue80Env(t, compiledSSHFixtureOptions{})
	remote := filepath.Join(t.TempDir(), "remote-tree")
	// Larger than the SSH channel window so an undrained stream would block the
	// remote tar forever.
	issue80WriteFile(t, filepath.Join(remote, "big.bin"), bytes.Repeat([]byte("d"), 16<<20))
	local := filepath.Join(env.cli.temp, "downloaded")
	started := time.Now()
	result := env.cli.RunWithEnv(t, "sshctl", nil, map[string]string{
		"PATH":                env.cli.TarFailureHelperDir(t),
		"SSM_TEST_TAR_HELPER": "1",
	}, "--offline", "--json", "get", env.alias, remote, local)
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("get took %s; local tar failure must end the transfer promptly", elapsed)
	}
	got := issue80LastJSON(t, result)
	if result.ProcessExit != 1 || got["ok"] != false || got["error"] != "local_write_failed" || got["stage"] != "local_write" {
		t.Fatalf("directory get failure = exit %d %v", result.ProcessExit, got)
	}
	if _, err := os.Stat(local); err == nil {
		t.Fatal("failed directory download published the destination")
	}
}

func TestCompiledDirectoryGetRejectsSHA256AndAcceptsTimeout(t *testing.T) {
	env := newIssue80Env(t, compiledSSHFixtureOptions{})
	remote := filepath.Join(t.TempDir(), "remote-tree")
	issue80WriteFile(t, filepath.Join(remote, "a.txt"), []byte("a"))
	rejected := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, filepath.Join(env.cli.temp, "d1"), "--sha256", "--json")
	got := issue80JSON(t, rejected)
	if got["error"] != "unsupported_transfer_option" || got["kind"] != "directory" {
		t.Fatalf("directory get --sha256 = %v", got)
	}
	local := filepath.Join(env.cli.temp, "d2")
	accepted := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, local, "--timeout", "30s", "--json")
	if body := issue80JSON(t, accepted); accepted.ProcessExit != 0 || body["ok"] != true {
		t.Fatalf("directory get --timeout = %s", compiledOutputIdentity(accepted))
	}
	if data, err := os.ReadFile(filepath.Join(local, "a.txt")); err != nil || string(data) != "a" { //nolint:gosec // beneath test-owned download root
		t.Fatalf("downloaded data=%q err=%v", data, err)
	}
}

// --- put --sha256 --------------------------------------------------------

func TestCompiledPutSHA256ToolDetection(t *testing.T) {
	body := []byte("issue80 digest body\n")
	sum := sha256.Sum256(body)
	wantDigest := hex.EncodeToString(sum[:])

	t.Run("only shasum available succeeds", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{RemoteDigestTools: []string{"shasum"}})
		local := filepath.Join(env.cli.temp, "payload")
		issue80WriteFile(t, local, body)
		remote := filepath.Join(t.TempDir(), "out.bin")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, remote, "--sha256")
		got := issue80JSON(t, result)
		if result.ProcessExit != 0 || got["ok"] != true || got["integrity"] != "sha256_verified" || got["remote_sha256"] != wantDigest {
			t.Fatalf("shasum-only put = %s", compiledOutputIdentity(result))
		}
		// The remote script must probe the three tools in the documented order.
		script := strings.Join(env.server.Commands(), "\n")
		iSum, iShasum, iOpenssl := strings.Index(script, "command -v sha256sum"), strings.Index(script, "command -v shasum"), strings.Index(script, "command -v openssl")
		if iSum < 0 || iShasum < iSum || iOpenssl < iShasum || !strings.Contains(script, "shasum -a 256") || !strings.Contains(script, "openssl dgst -sha256") {
			t.Fatalf("remote probe order/commands wrong: %s", script)
		}
	})

	t.Run("no digest tool returns integrity_tool_unavailable", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{RemoteDigestTools: []string{}})
		local := filepath.Join(env.cli.temp, "payload")
		issue80WriteFile(t, local, body)
		remote := filepath.Join(t.TempDir(), "out.bin")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, remote, "--sha256")
		got := issue80RequireFailure(t, result, 1, "integrity_tool_unavailable", "capability")
		if hint, _ := got["hint"].(string); !strings.Contains(hint, "without --sha256") {
			t.Fatalf("hint = %v", got["hint"])
		}
		if _, err := os.Stat(remote); err == nil {
			t.Fatal("destination exists although integrity could not be verified")
		}
	})

	t.Run("large payload still reports the missing tool", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{RemoteDigestTools: []string{}})
		local := filepath.Join(env.cli.temp, "payload")
		issue80WriteFile(t, local, bytes.Repeat([]byte("z"), 8<<20))
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, filepath.Join(t.TempDir(), "out.bin"), "--sha256")
		issue80RequireFailure(t, result, 1, "integrity_tool_unavailable", "capability")
	})

	t.Run("without --sha256 the probe is not required", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{RemoteDigestTools: []string{}})
		local := filepath.Join(env.cli.temp, "payload")
		issue80WriteFile(t, local, body)
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, filepath.Join(t.TempDir(), "out.bin"))
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("plain put on a host without digest tools = %s", compiledOutputIdentity(result))
		}
	})
}

// --- parent directory mode ----------------------------------------------

func TestCompiledPutParentDirectoryMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not observable on Windows")
	}
	modeOf := func(t *testing.T, path string) os.FileMode {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}
	t.Run("default is 0755", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "site.conf")
		issue80WriteFile(t, local, []byte("conf"))
		root := t.TempDir()
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, filepath.Join(root, "new", "deep", "site.conf"))
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("put = %s", compiledOutputIdentity(result))
		}
		for _, dir := range []string{"new", filepath.Join("new", "deep")} {
			if mode := modeOf(t, filepath.Join(root, dir)); mode != 0o755 {
				t.Fatalf("%s mode = %o, want 755", dir, mode)
			}
		}
		if !strings.Contains(strings.Join(env.server.Commands(), "\n"), "umask 022; mkdir -p --") {
			t.Fatalf("command did not request 0755 parents: %v", env.server.Commands())
		}
	})
	t.Run("--dir-mode overrides", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "site.conf")
		issue80WriteFile(t, local, []byte("conf"))
		root := t.TempDir()
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, filepath.Join(root, "priv", "site.conf"), "--dir-mode", "0750")
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("put --dir-mode = %s", compiledOutputIdentity(result))
		}
		if mode := modeOf(t, filepath.Join(root, "priv")); mode != 0o750 {
			t.Fatalf("mode = %o, want 750", mode)
		}
	})
	t.Run("request dir_mode", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "site.conf")
		issue80WriteFile(t, local, []byte("conf"))
		root := t.TempDir()
		request, err := json.Marshal(map[string]any{
			"version": 1, "op": "put", "alias": env.alias, "local_path": local,
			"remote_path": filepath.Join(root, "req", "site.conf"), "dir_mode": "0700",
		})
		if err != nil {
			t.Fatal(err)
		}
		result := env.cli.Run(t, "sshctl", request, "request", "-")
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("request put dir_mode = %s", compiledOutputIdentity(result))
		}
		if mode := modeOf(t, filepath.Join(root, "req")); mode != 0o700 {
			t.Fatalf("mode = %o, want 700", mode)
		}
	})
	t.Run("invalid mode is rejected before connecting", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "site.conf")
		issue80WriteFile(t, local, []byte("conf"))
		for _, bad := range []string{"0999", "1777", "rwx", "0", "0500", "0644"} {
			result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, "/remote/x", "--dir-mode", bad)
			issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
		}
		if env.server.ConnectionCount() != 0 {
			t.Fatal("invalid --dir-mode reached the network")
		}
	})
	t.Run("directory put honours --dir-mode for the created root", func(t *testing.T) {
		env := newIssue80Env(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "src")
		issue80WriteFile(t, filepath.Join(local, "a.txt"), []byte("a"))
		root := t.TempDir()
		result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", env.alias, local, filepath.Join(root, "tree"), "--dir-mode", "0711")
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("directory put --dir-mode = %s", compiledOutputIdentity(result))
		}
		if mode := modeOf(t, filepath.Join(root, "tree")); mode != 0o711 {
			t.Fatalf("mode = %o, want 711", mode)
		}
	})
}

// --- get flag parity -----------------------------------------------------

func TestCompiledGetAcceptsPutFlagSet(t *testing.T) {
	body := []byte("issue80 get body\n")
	sum := sha256.Sum256(body)
	wantDigest := hex.EncodeToString(sum[:])
	newEnv := func(t *testing.T, options compiledSSHFixtureOptions) (issue80Env, string) {
		env := newIssue80Env(t, options)
		remote := filepath.Join(t.TempDir(), "remote.bin")
		issue80WriteFile(t, remote, body)
		return env, remote
	}
	assertDownloaded := func(t *testing.T, path string) {
		t.Helper()
		if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, body) { //nolint:gosec // test-owned download destination
			t.Fatalf("downloaded data=%q err=%v", data, err)
		}
	}

	t.Run("trailing --json", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "out")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, local, "--json")
		got := issue80JSON(t, result)
		if result.ProcessExit != 0 || got["ok"] != true || got["action"] != "get" || got["kind"] != "file" {
			t.Fatalf("get --json = %s", compiledOutputIdentity(result))
		}
		assertDownloaded(t, local)
	})
	t.Run("leading --json", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "out")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", "--json", env.alias, remote, local)
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("get with leading --json = %s", compiledOutputIdentity(result))
		}
	})
	t.Run("--timeout", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "out")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, local, "--timeout", "30s", "--json")
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("get --timeout = %s", compiledOutputIdentity(result))
		}
		assertDownloaded(t, local)
		result = env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, local, "--timeout=30s", "--json")
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("get --timeout=30s = %s", compiledOutputIdentity(result))
		}
	})
	t.Run("invalid --timeout", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, filepath.Join(env.cli.temp, "out"), "--timeout", "soon", "--json")
		issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
	})
	t.Run("--sha256 verifies and reports digests", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{RemoteDigestTools: []string{"openssl"}})
		local := filepath.Join(env.cli.temp, "out")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, local, "--sha256", "--json")
		got := issue80JSON(t, result)
		if result.ProcessExit != 0 || got["ok"] != true || got["integrity"] != "sha256_verified" ||
			got["local_sha256"] != wantDigest || got["remote_sha256"] != wantDigest {
			t.Fatalf("get --sha256 = %s", compiledOutputIdentity(result))
		}
		assertDownloaded(t, local)
	})
	t.Run("--sha256 mismatch fails and publishes nothing", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{DownloadDigestOverride: strings.Repeat("0", 64)})
		local := filepath.Join(env.cli.temp, "out")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, local, "--sha256", "--json")
		got := issue80RequireFailure(t, result, 1, "integrity_failed", "integrity")
		if got["integrity"] != "mismatch" {
			t.Fatalf("mismatch outcome = %v", got)
		}
		if _, err := os.Stat(local); err == nil {
			t.Fatal("mismatching download was published")
		}
		matches, _ := filepath.Glob(filepath.Join(env.cli.temp, ".ssm-get-*"))
		if len(matches) != 0 {
			t.Fatalf("staging files left behind: %v", matches)
		}
	})
	t.Run("--sha256 without remote tool", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{RemoteDigestTools: []string{}})
		local := filepath.Join(env.cli.temp, "out")
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, local, "--sha256", "--json")
		issue80RequireFailure(t, result, 1, "integrity_tool_unavailable", "capability")
		if _, err := os.Stat(local); err == nil {
			t.Fatal("download published without verification")
		}
	})
	t.Run("--resume is rejected explicitly", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, filepath.Join(env.cli.temp, "out"), "--resume=v1", "--json")
		got := issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
		if message, _ := got["message"].(string); !strings.Contains(message, "--resume") {
			t.Fatalf("message = %v", got["message"])
		}
	})
	t.Run("unknown flag and wrong arity stay invalid", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		result := env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, "--json")
		issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
		result = env.cli.Run(t, "sshctl", nil, "--offline", "get", env.alias, remote, filepath.Join(env.cli.temp, "out"), "--bogus", "--json")
		issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
	})
	t.Run("ssm entry point accepts the same flags", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "out")
		result := env.cli.Run(t, "ssm", nil, "--offline", "get", env.alias, remote, local, "--sha256", "--timeout", "30s", "--json")
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true || got["integrity"] != "sha256_verified" {
			t.Fatalf("ssm get flags = %s", compiledOutputIdentity(result))
		}
		assertDownloaded(t, local)
	})
	t.Run("request get accepts sha256 and timeout", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		local := filepath.Join(env.cli.temp, "out")
		request, err := json.Marshal(map[string]any{
			"version": 1, "op": "get", "alias": env.alias, "remote_path": remote, "local_path": local,
			"sha256": true, "timeout": "30s",
		})
		if err != nil {
			t.Fatal(err)
		}
		result := env.cli.Run(t, "sshctl", request, "request", "-")
		if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true || got["integrity"] != "sha256_verified" {
			t.Fatalf("request get = %s", compiledOutputIdentity(result))
		}
		assertDownloaded(t, local)
	})
	t.Run("request get still rejects unknown fields", func(t *testing.T) {
		env, remote := newEnv(t, compiledSSHFixtureOptions{})
		request, err := json.Marshal(map[string]any{
			"version": 1, "op": "get", "alias": env.alias, "remote_path": remote,
			"local_path": filepath.Join(env.cli.temp, "out"), "resume": "v1",
		})
		if err != nil {
			t.Fatal(err)
		}
		result := env.cli.Run(t, "sshctl", request, "request", "-")
		if got := issue80JSON(t, result); result.ProcessExit == 0 || got["ok"] != false {
			t.Fatalf("request get with resume = %s", compiledOutputIdentity(result))
		}
	})
}
