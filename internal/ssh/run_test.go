package ssh

import (
	"strings"
	"testing"

	"ssm/internal/config"
)

func TestBuildRemoteCommandSecrets(t *testing.T) {
	cmd := BuildRemoteCommand("printenv TOKEN", map[string]string{"TOKEN": "s3cret"})
	if cmd != "TOKEN='s3cret' printenv TOKEN" {
		t.Fatalf("cmd=%q", cmd)
	}
}

func TestShellCommandSecretsAreExportedForWholeCommand(t *testing.T) {
	res := Run(config.Connection{Name: "plan", Host: "192.0.2.1", User: "root"}, &config.Vault{}, RunOptions{
		Command:  "printf '%s' \"$TOKEN\"; printenv TOKEN",
		Secrets:  map[string]string{"TOKEN": "whole-shell-secret"},
		Mode:     "shell_command",
		PlanOnly: true,
	})
	if !strings.Contains(res.RemoteCommand, "export TOKEN='***';") {
		t.Fatalf("shell secret was not exported: %q", res.RemoteCommand)
	}
	if strings.Contains(res.RemoteCommand, "whole-shell-secret") {
		t.Fatalf("shell secret leaked: %q", res.RemoteCommand)
	}
}

func TestRunPlanPreservesNonSecretCommandMetadata(t *testing.T) {
	const command = "printf 'token=<caller supplied output>'"
	res := Run(config.Connection{
		Name: "plan", Host: "192.0.2.1", User: "root",
	}, &config.Vault{}, RunOptions{
		Command: command, Mode: "shell_command", PlanOnly: true,
	})
	if res.RemoteCommand != command {
		t.Fatalf("remote command=%q, want=%q", res.RemoteCommand, command)
	}
}

func TestRedactSecrets(t *testing.T) {
	full := BuildRemoteCommand("echo hi", map[string]string{"TOKEN": "s3cret-value"})
	got := RedactSecrets(full, map[string]string{"TOKEN": "s3cret-value"})
	if got != "TOKEN='***' echo hi" && got == full {
		t.Fatalf("not redacted: %q", got)
	}
	if contains(got, "s3cret-value") {
		t.Fatalf("secret leaked: %q", got)
	}
}

func TestRedactShortSecretDoesNotCorruptCommand(t *testing.T) {
	full := BuildScriptRemoteCommand("exec 'bash' '-s' '--'", map[string]string{"TOKEN": "a"})
	got := RedactSecrets(full, map[string]string{"TOKEN": "a"})
	if strings.Contains(got, "TOKEN='a'") {
		t.Fatalf("secret leaked: %q", got)
	}
	if !strings.Contains(got, "bash") {
		t.Fatalf("short secret corrupted command: %q", got)
	}
}

func TestAssessRisk(t *testing.T) {
	if AssessRisk("hostname") != "low" {
		t.Fatal("hostname should be low")
	}
	if AssessRisk("sudo reboot") != "high" {
		t.Fatal("reboot should be high")
	}
}

func TestExpandMapJobsMultiScript(t *testing.T) {
	jobs := ExpandMapJobs([]string{"h1", "h2"}, "", []ScriptSpec{
		{Label: "a.sh", Body: "echo a\n", Interpreter: "sh"},
		{Label: "b.sh", Body: "echo b\n", Interpreter: "sh"},
	}, nil, "script", false)
	if len(jobs) != 4 {
		t.Fatalf("want 4 jobs, got %d", len(jobs))
	}
	if jobs[0].Input != "echo a\n" || !strings.Contains(jobs[0].Command, "exec 'sh' '-s' '--'") {
		t.Fatalf("job did not use stdin runner: %+v", jobs[0])
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && (func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})()))
}
