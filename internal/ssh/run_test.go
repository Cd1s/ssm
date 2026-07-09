package ssh

import "testing"

func TestBuildRemoteCommandSecrets(t *testing.T) {
	cmd := BuildRemoteCommand("printenv TOKEN", map[string]string{"TOKEN": "s3cret"})
	if cmd != "TOKEN='s3cret' printenv TOKEN" {
		t.Fatalf("cmd=%q", cmd)
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
		{Label: "a.sh", Body: "echo a"},
		{Label: "b.sh", Body: "echo b"},
	}, nil)
	if len(jobs) != 4 {
		t.Fatalf("want 4 jobs, got %d", len(jobs))
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
