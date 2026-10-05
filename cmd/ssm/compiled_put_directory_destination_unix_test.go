//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompiledPutDirectoryDestinationReportsRemoteWriteFailure(t *testing.T) {
	const alias = "put-directory"
	cli, _ := newCompiledExecRunHarness(t, alias)
	localFile := filepath.Join(cli.temp, "source.txt")
	if err := os.WriteFile(localFile, []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteRoot := t.TempDir()
	remoteDir := filepath.Join(remoteRoot, "existing")
	if err := os.Mkdir(remoteDir, 0o755); err != nil { //nolint:gosec // test fixture directory under t.TempDir
		t.Fatal(err)
	}

	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", alias, localFile, remoteDir)
	if result.ProcessExit == 0 || result.Stderr != "" {
		t.Fatalf("directory destination was not rejected as a JSON failure: %s", compiledOutputIdentity(result))
	}
	failure := decodeExactlyOneJSONObject(t, result.Stdout)
	if failure["ok"] != false {
		t.Fatalf("ok = %v, want false", failure["ok"])
	}
	if failure["error"] != "remote_write_failed" {
		t.Fatalf("error = %v, want remote_write_failed", failure["error"])
	}
	if failure["hint"] != "retry; the remote temporary file is cleaned and the final path is unchanged" {
		t.Fatalf("hint = %v, want the remote-write classification hint", failure["hint"])
	}

	entries, err := os.ReadDir(remoteDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory destination contains leftover entries: %v", entries)
	}
	entries, err = os.ReadDir(remoteRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "existing" {
		t.Fatalf("upload left sibling temporary files: %v", entries)
	}
}
