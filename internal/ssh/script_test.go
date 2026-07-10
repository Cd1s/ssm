package ssh

import (
	"os/exec"
	"strings"
	"testing"

	"ssm/internal/config"
)

func TestPrepareScriptNormalizesAndDetectsShell(t *testing.T) {
	script, err := PrepareScript("generated.sh", []byte("\xef\xbb\xbf#!/usr/bin/env bash\r\necho \"it's fine\"\r\n"), "auto", []string{"one"})
	if err != nil {
		t.Fatal(err)
	}
	if script.Interpreter != "bash" {
		t.Fatalf("interpreter = %q", script.Interpreter)
	}
	if strings.Contains(script.Body, "\r") || strings.HasPrefix(script.Body, "\xef\xbb\xbf") {
		t.Fatalf("body was not normalized: %q", script.Body)
	}
	if len(script.Args) != 1 || script.Args[0] != "one" {
		t.Fatalf("args = %#v", script.Args)
	}
}

func TestPrepareScriptRejectsUnsafeInput(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":         []byte(" \r\n\t"),
		"nul":           []byte("echo before\x00echo after\n"),
		"non-shell":     []byte("#!/usr/bin/env python3\nprint('hi')\n"),
		"invalid-env":   []byte("#!/usr/bin/env -S\ntrue\n"),
		"oversize-data": make([]byte, MaxScriptBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareScript("bad", data, "auto", nil); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if _, err := PrepareScript("bad-arg", []byte("true\n"), "sh", []string{"bad\x00arg"}); err == nil {
		t.Fatal("expected NUL argument error")
	}
}

func TestScriptRunnerExecutesStdinWithExactArgsAndSecrets(t *testing.T) {
	body := `printf 'arg1=<%s>\n' "$1"
printf 'arg2=<%s>\n' "$2"
printf 'token=<%s>\n' "$TOKEN"
printf 'quote=<%s>\n' "single' and \"double\""
`
	script, err := PrepareScript("runner.sh", []byte(body), "sh", []string{"hello world", "it's exact"})
	if err != nil {
		t.Fatal(err)
	}
	remote := BuildScriptRemoteCommand(BuildScriptRunner(script), map[string]string{"TOKEN": "secret with ' quote"})
	cmd := exec.Command("sh", "-c", remote) //nolint:gosec // fixed test runner exercising generated quoting
	cmd.Stdin = strings.NewReader(script.Body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runner failed: %v\n%s\nremote=%s", err, out, RedactSecrets(remote, map[string]string{"TOKEN": "secret with ' quote"}))
	}
	want := "arg1=<hello world>\narg2=<it's exact>\ntoken=<secret with ' quote>\nquote=<single' and \"double\">\n"
	if string(out) != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestScriptPlanDoesNotExposeBodyOrSecret(t *testing.T) {
	script, err := PrepareScript("danger.sh", []byte("sudo reboot\n"), "sh", nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := "plan-secret-value"
	res := Run(config.Connection{Name: "test", Host: "192.0.2.1", Port: 22, User: "root"}, &config.Vault{}, RunOptions{
		Command:        BuildScriptRunner(script),
		Input:          script.Body,
		RiskCommand:    script.Body,
		Secrets:        map[string]string{"TOKEN": secret},
		PlanOnly:       true,
		Interpreter:    script.Interpreter,
		ScriptLabel:    script.Label,
		RequestedAlias: "test",
	})
	if !res.OK || !res.Plan || res.Risk != "high" {
		t.Fatalf("result = %+v", res)
	}
	if strings.Contains(res.RemoteCommand, secret) || strings.Contains(res.RemoteCommand, "sudo reboot") {
		t.Fatalf("plan leaked input: %+v", res)
	}
	if res.ScriptSHA256 != ScriptDigest(script.Body) || res.InputBytes != len(script.Body) {
		t.Fatalf("script metadata = %+v", res)
	}
}
