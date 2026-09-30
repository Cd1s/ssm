package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ssm/internal/config"
)

// Issue #86: sshctl cp streams one file from host A to host B through the
// local machine. Both hosts are in-process fake SSH servers that share the
// test's file system, so the "remote" paths of A and B live in separate
// directories.

const cpPassword = "CP86_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

type cpEnv struct {
	cli      *compiledCLIHarness
	a, b     *compiledSSHFixture
	aDir     string
	bDir     string
	localTmp string
}

func newCPEnv(t *testing.T, a, b compiledSSHFixtureOptions) cpEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake remote hosts address the local file system with POSIX paths")
	}
	cli := newCompiledCLIHarness(t)
	a.Password, b.Password = cpPassword, cpPassword
	env := cpEnv{cli: cli, a: newCompiledSSHFixture(t, a), b: newCompiledSSHFixture(t, b), aDir: t.TempDir(), bDir: t.TempDir(), localTmp: t.TempDir()}
	cli.TrustSSHHost(t, env.a)
	cli.TrustSSHHost(t, env.b)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{
		env.a.Connection("src", cpPassword), env.b.Connection("dst", cpPassword),
	}})
	return env
}

// cp runs sshctl cp with an isolated temporary directory so any local temp
// file the copy created would be visible.
func (e cpEnv) cp(t *testing.T, args ...string) compiledCLIResult {
	t.Helper()
	env := map[string]string{"TMPDIR": e.localTmp, "TMP": e.localTmp, "TEMP": e.localTmp}
	return e.cli.RunWithEnv(t, "sshctl", nil, env, append([]string{"--offline"}, args...)...)
}

func (e cpEnv) requireNoLocalTemp(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(e.localTmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, entry := range entries {
			names[i] = entry.Name()
		}
		t.Fatalf("cp left local temporary files: %v", names)
	}
}

func requireNoStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".compiled-ssh-upload-") || strings.Contains(entry.Name(), ".ssm-") {
			t.Fatalf("temporary file left behind in %s: %s", dir, entry.Name())
		}
	}
}

func cpPayload(size int) ([]byte, string) {
	data := bytes.Repeat([]byte("cp-relay-payload-0123456789abcdef\n"), size/34+1)[:size]
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:])
}

func TestCompiledCopyRelaysAFileBetweenHostsAndVerifiesThreeDigests(t *testing.T) {
	env := newCPEnv(t, compiledSSHFixtureOptions{}, compiledSSHFixtureOptions{})
	data, digest := cpPayload(3<<20 + 11)
	source := filepath.Join(env.aDir, "release.bin")
	issue80WriteFile(t, source, data)
	if err := os.Chmod(source, 0o640); err != nil { //nolint:gosec // the test needs a group-readable source to verify mode preservation
		t.Fatal(err)
	}
	destination := filepath.Join(env.bDir, "new", "release.bin")

	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination)
	got := issue80JSON(t, result)
	if result.ProcessExit != 0 || got["ok"] != true || got["action"] != "cp" || got["direction"] != "cp" || got["kind"] != "file" ||
		got["route"] != "local_relay" || got["stage"] != "complete" || got["integrity"] != "sha256_verified" || got["atomic"] != true ||
		got["bytes"] != float64(len(data)) {
		t.Fatalf("cp = %s", result.Stdout)
	}
	for _, field := range []string{"source_sha256", "local_sha256", "destination_sha256"} {
		if got[field] != digest {
			t.Fatalf("%s = %v, want %s", field, got[field], digest)
		}
	}
	if endpoint, _ := got["source"].(map[string]any); endpoint["alias"] != "src" || endpoint["path"] != source {
		t.Fatalf("source endpoint = %v", got["source"])
	}
	if endpoint, _ := got["destination"].(map[string]any); endpoint["alias"] != "dst" || endpoint["path"] != destination {
		t.Fatalf("destination endpoint = %v", got["destination"])
	}
	if written, err := os.ReadFile(destination); err != nil || !bytes.Equal(written, data) { //nolint:gosec // test-owned fixture path
		t.Fatalf("destination bytes differ: %v", err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("destination mode = %v (%v), want the source's 640", info, err)
	}
	if kept, err := os.ReadFile(source); err != nil || !bytes.Equal(kept, data) { //nolint:gosec // test-owned fixture path
		t.Fatalf("source changed: %v", err)
	}
	requireNoStaging(t, filepath.Dir(destination))
	env.requireNoLocalTemp(t)
	if env.a.ConnectionCount() != 1 || env.b.ConnectionCount() != 1 {
		t.Fatalf("connections a=%d b=%d, want one each", env.a.ConnectionCount(), env.b.ConnectionCount())
	}
	if strings.Contains(result.Stdout+result.Stderr, cpPassword) {
		t.Fatalf("credential canary leaked: %s", compiledOutputIdentity(result))
	}

	human := env.cp(t, "cp", "src:"+source, "dst:"+destination)
	if human.ProcessExit != 0 || !strings.Contains(human.Stdout, "ok=1\n") || !strings.Contains(human.Stdout, "sha256="+digest) {
		t.Fatalf("human cp = exit %d stdout=%q stderr=%q", human.ProcessExit, human.Stdout, human.Stderr)
	}
	env.requireNoLocalTemp(t)
}

func TestCompiledCopyReplacesAnExistingDestinationAtomically(t *testing.T) {
	env := newCPEnv(t, compiledSSHFixtureOptions{}, compiledSSHFixtureOptions{})
	source := filepath.Join(env.aDir, "a.txt")
	issue80WriteFile(t, source, []byte("new contents"))
	destination := filepath.Join(env.bDir, "b.txt")
	issue80WriteFile(t, destination, []byte("old"))

	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination)
	if got := issue80JSON(t, result); result.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("cp = %s", result.Stdout)
	}
	if written, _ := os.ReadFile(destination); string(written) != "new contents" { //nolint:gosec // test-owned fixture path
		t.Fatalf("destination = %q", written)
	}
	requireNoStaging(t, env.bDir)
}

func TestCompiledCopyDigestMismatchLeavesNoPartialFile(t *testing.T) {
	// The source host reports a wrong digest for its file; the destination
	// refuses to publish bytes that do not match it.
	env := newCPEnv(t, compiledSSHFixtureOptions{DownloadDigestOverride: strings.Repeat("0", 64)}, compiledSSHFixtureOptions{})
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, []byte("payload that does not match the reported digest"))

	fresh := filepath.Join(env.bDir, "fresh.bin")
	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+fresh)
	got := issue80RequireFailure(t, result, 1, "integrity_failed", "integrity")
	if got["integrity"] != "mismatch" || got["ok"] != false {
		t.Fatalf("mismatch document = %v", got)
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("a mismatching copy published %s: %v", fresh, err)
	}
	requireNoStaging(t, env.bDir)

	existing := filepath.Join(env.bDir, "existing.bin")
	issue80WriteFile(t, existing, []byte("keep me"))
	result = env.cp(t, "--json", "cp", "src:"+source, "dst:"+existing)
	issue80RequireFailure(t, result, 1, "integrity_failed", "integrity")
	if kept, _ := os.ReadFile(existing); string(kept) != "keep me" { //nolint:gosec // test-owned fixture path
		t.Fatalf("a failed copy replaced the destination: %q", kept)
	}
	requireNoStaging(t, env.bDir)
	env.requireNoLocalTemp(t)
}

func TestCompiledCopyFailedDestinationWriteLeavesNothingBehind(t *testing.T) {
	env := newCPEnv(t, compiledSSHFixtureOptions{}, compiledSSHFixtureOptions{})
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, []byte("payload"))
	blocker := filepath.Join(env.bDir, "file")
	issue80WriteFile(t, blocker, []byte("not a directory"))

	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+filepath.Join(blocker, "sub", "b.bin"))
	// The remote reports "permission denied", which put and cp both map to the
	// connection-class exit 255 (see ExitForError).
	issue80RequireFailure(t, result, 255, "remote_write_failed", "remote_write")
	if kept, _ := os.ReadFile(blocker); string(kept) != "not a directory" { //nolint:gosec // test-owned fixture path
		t.Fatalf("blocker changed: %q", kept)
	}
	requireNoStaging(t, env.bDir)
	env.requireNoLocalTemp(t)
}

func TestCompiledCopyScopeAndErrors(t *testing.T) {
	env := newCPEnv(t, compiledSSHFixtureOptions{}, compiledSSHFixtureOptions{})
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, []byte("payload"))
	destination := filepath.Join(env.bDir, "b.bin")

	t.Run("directory source is unsupported before B is contacted", func(t *testing.T) {
		result := env.cp(t, "--json", "cp", "src:"+env.aDir, "dst:"+destination)
		issue80RequireFailure(t, result, 1, "unsupported_transfer_option", "validate")
		if env.b.ConnectionCount() != 0 {
			t.Fatal("a directory source reached the destination host")
		}
	})
	t.Run("missing source", func(t *testing.T) {
		result := env.cp(t, "--json", "cp", "src:"+filepath.Join(env.aDir, "nope"), "dst:"+destination)
		issue80RequireFailure(t, result, 1, "remote_read_failed", "remote_read")
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatal("a missing source created the destination")
		}
	})
	t.Run("unknown alias", func(t *testing.T) {
		result := env.cp(t, "--json", "cp", "ghost:"+source, "dst:"+destination)
		got := issue80JSON(t, result)
		if result.ProcessExit != 255 || got["error"] != "alias_not_found" {
			t.Fatalf("cp with an unknown alias = exit %d %s", result.ProcessExit, result.Stdout)
		}
	})
	t.Run("bad arguments", func(t *testing.T) {
		for _, args := range [][]string{
			{"cp", "src:" + source},
			{"cp", source, "dst:" + destination},
			{"cp", "src:", "dst:" + destination},
			{"cp", "src:" + source, "dst:" + destination, "--timeout", "0s"},
			{"cp", "src:" + source, "dst:" + destination, "--bogus"},
		} {
			result := env.cp(t, append([]string{"--json"}, args...)...)
			issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
		}
	})
	t.Run("direct is not implemented and says why", func(t *testing.T) {
		connections := env.a.ConnectionCount()
		result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination, "--direct")
		got := issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
		if message, _ := got["message"].(string); !strings.Contains(message, "--direct") || !strings.Contains(message, "credentials") {
			t.Fatalf("message = %q, want the security reason", message)
		}
		if env.a.ConnectionCount() != connections {
			t.Fatal("--direct opened a connection")
		}
	})
	t.Run("help documents the flags and the direct decision", func(t *testing.T) {
		result := env.cp(t, "cp", "--help")
		for _, want := range []string{"sshctl cp <alias-a>:<path> <alias-b>:<path>", "--timeout", "--json", "--direct", "explicit decision", "local_relay"} {
			if !strings.Contains(result.Stdout, want) {
				t.Fatalf("cp help lacks %q: %s", want, result.Stdout)
			}
		}
	})
}

func TestCompiledCopyRefusesTheSameFile(t *testing.T) {
	env := newCPEnv(t, compiledSSHFixtureOptions{}, compiledSSHFixtureOptions{})
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, []byte("payload"))
	for _, destination := range []string{source, filepath.Join(env.aDir, ".", "a.bin")} {
		result := env.cp(t, "--json", "cp", "src:"+source, "src:"+destination)
		issue80RequireFailure(t, result, 2, "invalid_arguments", "validate")
	}
	if kept, _ := os.ReadFile(source); string(kept) != "payload" { //nolint:gosec // test-owned fixture path
		t.Fatalf("source changed: %q", kept)
	}
	if env.a.ConnectionCount() != 0 {
		t.Fatal("a same-file cp opened a connection")
	}
}

func TestCompiledCopyNeedsASHA256ToolOnBothHosts(t *testing.T) {
	for name, options := range map[string][2]compiledSSHFixtureOptions{
		"source":      {{RemoteDigestTools: []string{}}, {}},
		"destination": {{}, {RemoteDigestTools: []string{}}},
	} {
		t.Run(name, func(t *testing.T) {
			env := newCPEnv(t, options[0], options[1])
			source := filepath.Join(env.aDir, "a.bin")
			issue80WriteFile(t, source, []byte("payload"))
			destination := filepath.Join(env.bDir, "b.bin")
			result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination)
			issue80RequireFailure(t, result, 1, "integrity_tool_unavailable", "capability")
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("a copy without a digest tool published the destination")
			}
			requireNoStaging(t, env.bDir)
		})
	}
}

func TestCompiledCopyWorksThroughJumpHosts(t *testing.T) {
	env := newCPEnv(t, compiledSSHFixtureOptions{}, compiledSSHFixtureOptions{})
	jump := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: cpPassword, AllowForward: true})
	env.cli.TrustSSHHost(t, jump)
	src, dst := env.a.Connection("src", cpPassword), env.b.Connection("dst", cpPassword)
	src.ProxyJump, dst.ProxyJump = "jump", "jump"
	env.cli.SaveVault(t, &config.Vault{Connections: []config.Connection{src, dst, jump.Connection("jump", cpPassword)}})
	data, digest := cpPayload(1 << 20)
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, data)
	destination := filepath.Join(env.bDir, "b.bin")

	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination)
	got := issue80JSON(t, result)
	if result.ProcessExit != 0 || got["ok"] != true || got["destination_sha256"] != digest {
		t.Fatalf("cp through jump = exit %d %s", result.ProcessExit, result.Stdout)
	}
	if written, _ := os.ReadFile(destination); !bytes.Equal(written, data) { //nolint:gosec // test-owned fixture path
		t.Fatal("destination bytes differ")
	}
	if forwards := jump.Forwards(); len(forwards) != 2 {
		t.Fatalf("jump forwards = %v, want one per endpoint", forwards)
	}
	env.requireNoLocalTemp(t)
}
