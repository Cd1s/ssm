//go:build unix

package ssh

import (
	"os/exec"
	"strings"
	"testing"
)

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
	cmd := exec.Command("sh", "-c", remote) //nolint:gosec // fixed Unix test runner exercising generated quoting
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
