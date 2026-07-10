package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestParseRemoteRunArgsEnvPrefix(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"FOO=bar", "printenv", "FOO"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "FOO='bar' 'printenv' 'FOO'" {
		t.Fatalf("command = %q", spec.Command)
	}
}

func TestParseRemoteRunArgsTrace(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"--trace", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Trace || spec.Command != "true" {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestParseRemoteRunArgsTimeout(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"--timeout", "10s", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Timeout != 10*time.Second || spec.Command != "true" {
		t.Fatalf("spec = %+v", spec)
	}
	spec, err = parseRemoteRunArgs([]string{"--timeout=30", "hostname"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Timeout != 30*time.Second {
		t.Fatalf("timeout = %v", spec.Timeout)
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
	if spec.Command != "" || len(spec.Scripts) != 1 {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.Scripts[0].Body != body+"\n" || spec.Scripts[0].Interpreter != "sh" {
		t.Fatalf("script = %+v", spec.Scripts[0])
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
	if spec.Command != "" || len(spec.Scripts) != 1 || spec.Scripts[0].Body != "true\n" {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestParseRemoteRunArgsSecretAndPlan(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"--plan", "--secret", "TOKEN=abc", "printenv", "TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Plan || spec.Secrets["TOKEN"] != "abc" {
		t.Fatalf("%+v", spec)
	}
}

func TestParseRemoteRunArgsRejectsInvalidSecretName(t *testing.T) {
	for _, value := range []string{"1TOKEN=value", "BAD-NAME=value", "TOKEN"} {
		if _, err := parseRemoteRunArgs([]string{"--secret", value, "true"}); err == nil {
			t.Fatalf("accepted invalid secret %q", value)
		}
	}
}

func TestParseRemoteRunArgsRejectsNULSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("before\x00after"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseRemoteRunArgs([]string{"--secret", "TOKEN=@" + path, "true"}); err == nil {
		t.Fatal("accepted a NUL secret")
	}
}

func TestParseRemoteRunArgsMultiScripts(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.sh")
	b := filepath.Join(dir, "b.sh")
	_ = os.WriteFile(a, []byte("echo a\n"), 0600)
	_ = os.WriteFile(b, []byte("echo b\n"), 0600)
	spec, err := parseRemoteRunArgs([]string{"--scripts", a + "," + b})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Scripts) != 2 {
		t.Fatalf("scripts=%d", len(spec.Scripts))
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
	if spec.Command != "" || len(spec.Scripts) != 1 || spec.Scripts[0].Body != "echo stdin-script\n" {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestParseRemoteRunArgsScriptShellAndArgs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\r\nprintf '%s\\n' \"$1\"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := parseRemoteRunArgs([]string{"--shell", "auto", "-f", path, "--", "hello ' world"})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Scripts) != 1 {
		t.Fatalf("scripts = %d", len(spec.Scripts))
	}
	script := spec.Scripts[0]
	if script.Interpreter != "bash" || len(script.Args) != 1 || script.Args[0] != "hello ' world" {
		t.Fatalf("script = %+v", script)
	}
	if strings.Contains(script.Body, "\r") {
		t.Fatalf("CRLF was not normalized: %q", script.Body)
	}
}

func TestParseRemoteRunArgsArgvQuotesSingleArgument(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"--argv", "name with spaces"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "'name with spaces'" {
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
