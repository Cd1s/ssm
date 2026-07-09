package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRemoteRunArgsSinglePassthrough(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{`cd /tmp && echo "hi"`})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != `cd /tmp && echo "hi"` {
		t.Fatalf("command = %q", spec.Command)
	}
}

func TestParseRemoteRunArgsMultiArgQuoted(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"bash", "-c", "echo hi"})
	if err != nil {
		t.Fatal(err)
	}
	want := "'bash' '-c' 'echo hi'"
	if spec.Command != want {
		t.Fatalf("command = %q, want %q", spec.Command, want)
	}
}

func TestParseRemoteRunArgsRawJoin(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"--raw", "bash", "-c", "echo hi"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "bash -c echo hi" {
		t.Fatalf("command = %q", spec.Command)
	}
}

func TestParseRemoteRunArgsDoubleDash(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"--", "echo", "hello world"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "'echo' 'hello world'" {
		t.Fatalf("command = %q", spec.Command)
	}
}

func TestParseRemoteRunArgsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	body := "echo from-file\necho line2"
	if err := os.WriteFile(path, []byte(body+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := parseRemoteRunArgs([]string{"-f", path})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != body {
		t.Fatalf("command = %q, want %q", spec.Command, body)
	}
}

func TestParseRemoteRunArgsFileEquals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(path, []byte("true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := parseRemoteRunArgs([]string{"--file=" + path})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "true" {
		t.Fatalf("command = %q", spec.Command)
	}
}

func TestParseRemoteRunArgsStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	go func() {
		_, _ = w.WriteString("echo stdin-script\n")
		_ = w.Close()
	}()

	spec, err := parseRemoteRunArgs([]string{"-s"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "echo stdin-script" {
		t.Fatalf("command = %q", spec.Command)
	}
}

func TestParseRemoteRunArgsRejectsMixedSources(t *testing.T) {
	for _, args := range [][]string{
		{"-s", "echo hi"},
		{"-f", "/tmp/x", "echo hi"},
		{"--raw", "-s"},
	} {
		if _, err := parseRemoteRunArgs(args); err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
}

func TestParseRemoteRunArgsRejectsUnknownFlag(t *testing.T) {
	_, err := parseRemoteRunArgs([]string{"--nope", "echo"})
	if err == nil || !strings.Contains(err.Error(), "unknown run option") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRemoteRunArgsMissingCommand(t *testing.T) {
	_, err := parseRemoteRunArgs(nil)
	if err == nil {
		t.Fatal("expected missing command error")
	}
}
