//go:build unix

package main

import (
	"archive/tar"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestCompiledDirectoryGetDropsRemoteOwnerAndSetuid(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires root on Linux to verify tar owner and setuid handling")
	}
	env := newIssue80Env(t, compiledSSHFixtureOptions{ExecHook: compiledDirectoryGetExecHook(compiledDirectoryGetArchive(t,
		tar.Header{Name: "setid", Typeflag: tar.TypeReg, Mode: 0o4755, Uid: 12345, Gid: 23456, Size: 1},
	))})
	local := filepath.Join(env.cli.temp, "downloaded")
	result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, "/remote/tree", local)
	got := issue80LastJSON(t, result)
	if result.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("owner/setuid get = exit %d %v", result.ProcessExit, got)
	}
	info, err := os.Stat(filepath.Join(local, "setid"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("downloaded mode = %v, want 0755 without special bits", info.Mode())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		t.Fatalf("downloaded uid = %v, want 0", info.Sys())
	}
}
