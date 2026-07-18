package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

func TestRunTransportsScriptOverSSHStdin(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal("sh is required for the in-process SSH integration test")
	}
	conn, vault := startRunTestSSHServer(t)
	t.Setenv("HOME", t.TempDir())
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
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal("sh is required for the in-process SSH integration test")
	}
	conn, vault := startRunTestSSHServer(t)
	t.Setenv("HOME", t.TempDir())
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

func TestRunScriptPreflightRejectsSyntaxWithoutExecuting(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal("sh is required for the in-process SSH integration test")
	}
	conn, vault := startRunTestSSHServer(t)
	t.Setenv("HOME", t.TempDir())
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
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal("sh is required for the in-process SSH integration test")
	}
	ClosePool()
	t.Cleanup(ClosePool)
	conn, vault, stats := startTrackedRunTestSSHServer(t)
	t.Setenv("HOME", t.TempDir())
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

type runTestServerStats struct {
	connections atomic.Int64
	sessions    atomic.Int64
}

func startRunTestSSHServer(t *testing.T) (config.Connection, *config.Vault) {
	t.Helper()
	conn, vault, _ := startTrackedRunTestSSHServer(t)
	return conn, vault
}

func startTrackedRunTestSSHServer(t *testing.T) (config.Connection, *config.Vault, *runTestServerStats) {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := gossh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return nil, fmt.Errorf("unexpected public key")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	stats := &runTestServerStats{}
	go serveRunTestSSH(listener, serverConfig, stats)

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(clientPrivate, "ssm-run-integration")
	if err != nil {
		t.Fatal(err)
	}
	vault := &config.Vault{Keys: []config.SSHKey{{Name: "integration", PrivateKey: string(pem.EncodeToMemory(block))}}}
	conn := config.Connection{Name: "integration", Host: "127.0.0.1", Port: port, User: "test", KeyName: "integration"}
	return conn, vault, stats
}

func trustRunTestHost(t *testing.T, connection config.Connection) {
	t.Helper()
	inspection, err := InspectHostKey(connection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptHostKey(connection, inspection.ObservedFingerprint); err != nil {
		t.Fatal(err)
	}
}

func serveRunTestSSH(listener net.Listener, cfg *gossh.ServerConfig, stats *runTestServerStats) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			serverConn, channels, requests, err := gossh.NewServerConn(raw, cfg)
			if err != nil {
				_ = raw.Close()
				return
			}
			stats.connections.Add(1)
			defer func() { _ = serverConn.Close() }()
			go gossh.DiscardRequests(requests)
			for newChannel := range channels {
				if newChannel.ChannelType() != "session" {
					_ = newChannel.Reject(gossh.UnknownChannelType, "session only")
					continue
				}
				channel, channelRequests, err := newChannel.Accept()
				if err != nil {
					continue
				}
				stats.sessions.Add(1)
				go serveRunTestSession(channel, channelRequests)
			}
		}()
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
		cmd := exec.Command("sh", "-c", payload.Command) //nolint:gosec // deliberate in-process SSH exec server
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
