package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func compiledDirectoryGetArchive(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, header := range headers {
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == 0 {
			if _, err := writer.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func compiledDirectoryGetExecHook(archive []byte) func(compiledExecRequest) (uint32, bool) {
	return func(request compiledExecRequest) (uint32, bool) {
		switch {
		case strings.HasPrefix(request.Command, "if [ -d "):
			_, _ = io.WriteString(request.Channel, "DIR\n")
			return 0, true
		case strings.Contains(request.Command, "tar -C ") && strings.Contains(request.Command, " -cf - ."):
			if _, err := request.Channel.Write(archive); err != nil {
				return 1, true
			}
			return 0, true
		default:
			return 0, false
		}
	}
}

func assertNoDirectoryGetArtifacts(t *testing.T, local string) {
	t.Helper()
	if entries, err := os.ReadDir(local); err == nil {
		if len(entries) != 0 {
			t.Fatalf("failed get published %d local entries", len(entries))
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat failed local destination: %v", err)
	}
	artifacts, err := filepath.Glob(filepath.Join(filepath.Dir(local), ".ssm-get-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("staging artifacts remain: %v", artifacts)
	}
}

func TestCompiledDirectoryGetRejectsSpecialEntryBeforePublish(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GNU tar device extraction is Linux-specific")
	}
	env := newIssue80Env(t, compiledSSHFixtureOptions{ExecHook: compiledDirectoryGetExecHook(compiledDirectoryGetArchive(t,
		tar.Header{Name: "device", Typeflag: tar.TypeChar, Mode: 0o600, Devmajor: 1, Devminor: 3},
		tar.Header{Name: "regular.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
	))})
	local := filepath.Join(env.cli.temp, "downloaded")
	result := env.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", env.alias, "/remote/tree", local)
	got := issue80LastJSON(t, result)
	if result.ProcessExit != 1 || got["ok"] != false || got["error"] != "local_write_failed" {
		t.Fatalf("special-entry get = exit %d %v", result.ProcessExit, got)
	}
	// An unprivileged tar refuses the device node itself ("Cannot mknod"); as
	// root tar creates it and ssm's own scan must reject it. Either way the
	// destination must stay unpublished.
	wantDetail := "Cannot mknod"
	if os.Geteuid() == 0 {
		wantDetail = "unsupported special file"
	}
	if !strings.Contains(result.Stdout+result.Stderr, wantDetail) {
		t.Fatalf("special-entry error omitted detail %q: %s", wantDetail, compiledOutputIdentity(result))
	}
	assertNoDirectoryGetArtifacts(t, local)
}
