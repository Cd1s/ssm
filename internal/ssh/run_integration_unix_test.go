//go:build unix

package ssh

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/machinecontract"
)

func TestRunTransportsScriptOverSSHStdin(t *testing.T) {
	conn, vault := startRunTestSSHServer(t)
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, conn)

	body := `printf 'arg=<%s>\n' "$1"
printf 'token=<%s>\n' "$TOKEN"
printf 'quote=<%s>\n' "single' and \"double\""
`
	script, err := PrepareScript("integration.sh", []byte(body), "sh", []string{"hello ' world"})
	if err != nil {
		t.Fatal(err)
	}
	tokenValue := strings.Repeat("token", 2) + " ' exact"
	res := Run(conn, vault, RunOptions{
		Command:        BuildScriptRunner(script),
		Input:          script.Body,
		RiskCommand:    script.Body,
		Secrets:        map[string]string{"TOKEN": tokenValue},
		Capture:        true,
		NoReuse:        true,
		Interpreter:    script.Interpreter,
		ScriptLabel:    script.Label,
		RequestedAlias: conn.Name,
	})
	if !res.OK || res.Exit != 0 {
		t.Fatalf("run failed: %+v", res)
	}
	want := "arg=<hello ' world>\ntoken=<tokentoken ' exact>\nquote=<single' and \"double\">\n"
	if res.Stdout != want || res.Stderr != "" {
		t.Fatalf("stdout=%q stderr=%q want=%q", res.Stdout, res.Stderr, want)
	}
	if strings.Contains(res.RemoteCommand, body) || strings.Contains(res.RemoteCommand, tokenValue) {
		t.Fatalf("remote command leaked input: %q", res.RemoteCommand)
	}
	if res.ScriptSHA256 != ScriptDigest(script.Body) || res.InputBytes != len(script.Body) {
		t.Fatalf("script metadata = %+v", res)
	}
}

func TestRunClassifiesRemoteScriptExit(t *testing.T) {
	conn, vault := startRunTestSSHServer(t)
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, conn)
	script, err := PrepareScript("failure.sh", []byte("printf failure >&2\nexit 9\n"), "sh", nil)
	if err != nil {
		t.Fatal(err)
	}
	res := Run(conn, vault, RunOptions{
		Command:        BuildScriptRunner(script),
		Input:          script.Body,
		RiskCommand:    script.Body,
		Capture:        true,
		NoReuse:        true,
		Interpreter:    script.Interpreter,
		ScriptLabel:    script.Label,
		RequestedAlias: conn.Name,
	})
	if res.OK || res.Exit != 9 || res.Error != "remote_script_failed" || res.Stderr != "failure" || res.Message == "" || res.Hint == "" || res.Stage != "remote_execution" {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunClassifiesScriptExit127FromCapturedSSHDiagnostics(t *testing.T) {
	conn, vault := startRunTestSSHServer(t)
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, conn)

	for _, test := range []struct {
		name       string
		body       string
		wantError  string
		wantStage  string
		wantStderr string
	}{
		{
			name:       "stable interpreter marker",
			body:       fmt.Sprintf("printf '%%s\\n' %s >&2\nexit 127\n", ShellQuote(machinecontract.InterpreterNotFoundDiagnostic("sh"))),
			wantError:  "interpreter_not_found",
			wantStage:  "interpreter",
			wantStderr: machinecontract.InterpreterNotFoundDiagnostic("sh") + "\n",
		},
		{
			name:       "ordinary script exit",
			body:       "printf '%s\\n' 'ordinary exit 127' >&2\nexit 127\n",
			wantError:  "remote_script_failed",
			wantStage:  "remote_execution",
			wantStderr: "ordinary exit 127\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			script, err := PrepareScript("exit-127.sh", []byte(test.body), "sh", nil)
			if err != nil {
				t.Fatal(err)
			}
			res := Run(conn, vault, RunOptions{
				Command:        BuildScriptRunner(script),
				Input:          script.Body,
				RiskCommand:    script.Body,
				Capture:        true,
				NoReuse:        true,
				Interpreter:    script.Interpreter,
				ScriptLabel:    script.Label,
				RequestedAlias: conn.Name,
			})
			if res.OK || res.Exit != 127 || res.Error != test.wantError || res.Stage != test.wantStage {
				t.Fatalf("result = %+v", res)
			}
			if res.Stdout != "" || res.Stderr != test.wantStderr {
				t.Fatalf("captured placement stdout=%q stderr=%q", res.Stdout, res.Stderr)
			}
		})
	}
}

func TestRunScriptPreflightRejectsSyntaxWithoutExecuting(t *testing.T) {
	conn, vault := startRunTestSSHServer(t)
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, conn)
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	body := "printf touched > " + ShellQuote(marker) + "\nif then\n"
	script, err := PrepareScript("invalid.sh", []byte(body), "sh", nil)
	if err != nil {
		t.Fatal(err)
	}
	res := RunScriptPreflight(conn, vault, script, true, conn.Name, conn.Name)
	if res.OK || res.Error != "script_syntax_error" || res.Preflight != "failed" || res.Message == "" || res.Hint == "" || res.Stage != "syntax_preflight" {
		t.Fatalf("preflight = %+v", res)
	}
	if res.Stderr != "" || strings.Contains(res.Hint, "if then") {
		t.Fatalf("preflight leaked parser source: %+v", res)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("invalid script executed before rejection: %v", err)
	}
}

func TestRunReusesConnectionWithoutProbeSession(t *testing.T) {
	ClosePool()
	t.Cleanup(ClosePool)
	conn, vault, stats := startTrackedRunTestSSHServer(t)
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, conn)
	stats.connections.Store(0)
	stats.sessions.Store(0)

	for _, command := range []string{"printf first", "printf second"} {
		res := Run(conn, vault, RunOptions{
			Command:        command,
			Capture:        true,
			RequestedAlias: conn.Name,
			Mode:           "argv",
		})
		if !res.OK {
			t.Fatalf("run failed: %+v", res)
		}
	}
	if got := stats.connections.Load(); got != 1 {
		t.Fatalf("SSH connections = %d, want 1", got)
	}
	if got := stats.sessions.Load(); got != 2 {
		t.Fatalf("SSH sessions = %d, want exactly the two command sessions", got)
	}
}

func serveRunTestSession(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		cmd := exec.Command("sh", "-c", payload.Command) //nolint:gosec // deliberate in-process Unix SSH exec server
		cmd.Stdin = channel
		cmd.Stdout = channel
		cmd.Stderr = channel.Stderr()
		status := 0
		if err := cmd.Run(); err != nil {
			status = 255
			if exitErr, ok := err.(*exec.ExitError); ok {
				status = exitErr.ExitCode()
			}
		}
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{uint32(status)}))
		return
	}
}
