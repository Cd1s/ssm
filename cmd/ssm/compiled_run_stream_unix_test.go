//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
)

// compiledExecSSHFixture is a Unix-only SSH server that runs each exec
// request with the local sh and forwards SSH signal requests to it, so
// streaming and interruption can be observed end to end.
type compiledExecSSHFixture struct {
	listener net.Listener
	signer   gossh.Signer
	password string

	mu      sync.Mutex
	signals []string
}

func newCompiledExecSSHFixture(t *testing.T, password string) *compiledExecSSHFixture {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &compiledExecSSHFixture{listener: listener, signer: signer, password: password}
	serverConfig := &gossh.ServerConfig{
		PasswordCallback: func(_ gossh.ConnMetadata, supplied []byte) (*gossh.Permissions, error) {
			if string(supplied) != password {
				return nil, errors.New("authentication failed")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)
	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				fixture.serve(raw, serverConfig)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		connections.Wait()
	})
	return fixture
}

func (f *compiledExecSSHFixture) serve(raw net.Conn, serverConfig *gossh.ServerConfig) {
	serverConn, channels, requests, err := gossh.NewServerConn(raw, serverConfig)
	if err != nil {
		_ = raw.Close()
		return
	}
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
		go f.session(channel, channelRequests)
	}
}

func (f *compiledExecSSHFixture) session(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	var command *exec.Cmd
	exited := make(chan struct{})
	for request := range requests {
		switch request.Type {
		case "exec":
			var payload struct{ Command string }
			if command != nil || gossh.Unmarshal(request.Payload, &payload) != nil {
				_ = request.Reply(false, nil)
				continue
			}
			command = exec.Command("sh", "-c", payload.Command) //nolint:gosec // deliberate in-process Unix SSH exec fixture
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			command.Stdin = channel
			command.Stdout = channel
			command.Stderr = channel.Stderr()
			if err := command.Start(); err != nil {
				_ = request.Reply(false, nil)
				return
			}
			_ = request.Reply(true, nil)
			go func() {
				defer close(exited)
				err := command.Wait()
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
						name := strings.TrimPrefix(unixSignalName(status.Signal()), "SIG")
						_, _ = channel.SendRequest("exit-signal", false, gossh.Marshal(struct {
							Signal     string
							CoreDumped bool
							Error      string
							Lang       string
						}{Signal: name}))
						_ = channel.Close()
						return
					}
				}
				_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{uint32(command.ProcessState.ExitCode())})) //nolint:gosec // exit codes are 0-255
				_ = channel.Close()
			}()
		case "signal":
			var payload struct{ Signal string }
			if gossh.Unmarshal(request.Payload, &payload) != nil {
				continue
			}
			f.mu.Lock()
			f.signals = append(f.signals, payload.Signal)
			f.mu.Unlock()
			if command != nil && command.Process != nil {
				if signal, ok := map[string]syscall.Signal{"TERM": syscall.SIGTERM, "INT": syscall.SIGINT, "HUP": syscall.SIGHUP}[payload.Signal]; ok {
					_ = syscall.Kill(-command.Process.Pid, signal)
				}
			}
		default:
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
		}
	}
	if command != nil && command.Process != nil {
		// The client is gone: stop the whole remote process group so no
		// fixture command outlives the test.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-exited
	}
}

func unixSignalName(signal syscall.Signal) string {
	switch signal {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGKILL:
		return "SIGKILL"
	default:
		return "SIG" + strconv.Itoa(int(signal))
	}
}

func (f *compiledExecSSHFixture) Signals() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.signals...)
}

func (f *compiledExecSSHFixture) Connection(alias string) config.Connection {
	host, portText, _ := net.SplitHostPort(f.listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	return config.Connection{Name: alias, Host: host, Port: port, User: "fixture", Password: f.password}
}

func trustCompiledExecSSHHost(t *testing.T, h *compiledCLIHarness, fixture *compiledExecSSHFixture) {
	t.Helper()
	directory := filepath.Join(h.home, ".ssh")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(fixture.listener.Addr().String())}, fixture.signer.PublicKey()) + "\n"
	file, err := os.OpenFile(filepath.Join(directory, "known_hosts"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // path is beneath the harness's isolated home
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(line); err != nil {
		t.Fatal(err)
	}
}

func newCompiledExecRunHarness(t *testing.T, alias string) (*compiledCLIHarness, *compiledExecSSHFixture) {
	t.Helper()
	const password = "STREAM_RUN_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	cli := newCompiledCLIHarness(t)
	fixture := newCompiledExecSSHFixture(t, password)
	trustCompiledExecSSHHost(t, cli, fixture)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{fixture.Connection(alias)}})
	return cli, fixture
}

// startCompiledCLI starts a compiled CLI with a live stdout pipe.
func (h *compiledCLIHarness) startCompiledCLI(t *testing.T, env map[string]string, args ...string) (*exec.Cmd, io.ReadCloser, *bytes.Buffer) {
	t.Helper()
	overrides := map[string]string{"SSM_MASTER_PASS_FILE": h.passPath}
	for key, value := range env {
		overrides[key] = value
	}
	cmd := exec.Command(h.paths["sshctl"], args...) //nolint:gosec // executable is the test-built compiled CLI
	cmd.Args[0] = "sshctl"
	cmd.Env = isolatedCompiledCLIEnvironmentWith(h.home, h.temp, overrides)
	cmd.Stdin = bytes.NewReader(nil)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd, stdout, &stderr
}

func assertNoDiagnosticSpools(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".ssm-diagnostic-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("human run left diagnostic spool files: %q", matches)
	}
}

func TestCompiledHumanRunStreamsLargeOutputAndRemoteExit(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "stream-large")
	const size = 64 << 20
	result := cli.Run(t, "sshctl", nil, "--offline", "run", "stream-large", "--argv", "sh", "-c", "head -c "+strconv.Itoa(size)+" /dev/zero; exit 7")
	if result.ProcessExit != 7 || len(result.Stdout) != size || result.Stderr != "" {
		t.Fatalf("large human run exit=%d stdout_bytes=%d stderr=%q, want exit=7 stdout_bytes=%d", result.ProcessExit, len(result.Stdout), result.Stderr, size)
	}
	if strings.Trim(result.Stdout, "\x00") != "" {
		t.Fatal("large human run changed output bytes")
	}
	assertNoDiagnosticSpools(t, cli.temp)
}

func TestCompiledHumanRunDeliversOutputBeforeRemoteExit(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "stream-live")
	started := time.Now()
	cmd, stdout, stderr := cli.startCompiledCLI(t, nil, "--offline", "run", "stream-live", "--argv", "sh", "-c", "echo first; sleep 4; echo second")
	reader := bufio.NewReader(stdout)
	first, err := reader.ReadString('\n')
	if err != nil || first != "first\n" {
		t.Fatalf("first streamed line = %q, %v; stderr=%q", first, err, stderr.String())
	}
	if elapsed := time.Since(started); elapsed >= 4*time.Second {
		t.Fatalf("first line arrived after %s, not before the remote command finished", elapsed)
	}
	if cmd.ProcessState != nil {
		t.Fatal("sshctl exited before the remote command finished")
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("streamed run failed: %v; stderr=%q", err, stderr.String())
	}
	if string(rest) != "second\n" {
		t.Fatalf("remaining streamed output = %q", rest)
	}
	assertNoDiagnosticSpools(t, cli.temp)
}

func TestCompiledHumanRunForwardsSIGTERMAndFlushesOutput(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "stream-signal")
	cmd, stdout, stderr := cli.startCompiledCLI(t, nil, "--offline", "run", "stream-signal", "--argv", "sh", "-c",
		"trap 'echo remote-got-term; exit 9' TERM; echo ready; while :; do sleep 0.1; done")
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("ready line = %q, %v; stderr=%q", line, err, stderr.String())
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case <-waitErr:
	case <-time.After(10 * time.Second):
		t.Fatal("interrupted sshctl did not exit")
	}
	if code := cmd.ProcessState.ExitCode(); code != 128+int(syscall.SIGTERM) {
		t.Fatalf("interrupted exit = %d, want %d; stderr=%q", code, 128+int(syscall.SIGTERM), stderr.String())
	}
	if string(rest) != "remote-got-term\n" {
		t.Fatalf("output after signal = %q, want remote trap output", rest)
	}
	if !strings.Contains(stderr.String(), "error=interrupted") {
		t.Fatalf("interrupted stderr = %q", stderr.String())
	}
	if signals := fixture.Signals(); strings.Join(signals, ",") != "TERM" {
		t.Fatalf("remote signals = %q, want TERM", signals)
	}
	assertNoDiagnosticSpools(t, cli.temp)
}

func TestCompiledHumanRunKeepsSignalsIgnoredAtStartup(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "stream-nohup")
	// trap '' HUP makes SIGHUP ignored before exec, as nohup does.
	cmd := exec.Command("sh", "-c", `trap '' HUP; exec "$0" "$@"`, cli.paths["sshctl"], //nolint:gosec // test-built compiled CLI under a fixed shell prelude
		"--offline", "run", "stream-nohup", "--argv", "sh", "-c", "echo ready; sleep 2; echo done")
	cmd.Env = isolatedCompiledCLIEnvironmentWith(cli.home, cli.temp, map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath})
	cmd.Stdin = bytes.NewReader(nil)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("ready line = %q, %v; stderr=%q", line, err, stderr.String())
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("ignored SIGHUP interrupted the run: %v; stderr=%q", err, stderr.String())
	}
	if string(rest) != "done\n" || len(fixture.Signals()) != 0 {
		t.Fatalf("run after ignored SIGHUP: rest=%q remote signals=%q", rest, fixture.Signals())
	}
}

func TestCompiledHumanRunStopsWhenLocalStdoutCloses(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "stream-closed")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, stdout, stderr := cli.startCompiledCLI(t, nil, "--offline", "run", "stream-closed", "--argv", "yes")
	buffer := make([]byte, 4096)
	if _, err := io.ReadFull(stdout, buffer); err != nil {
		t.Fatalf("read streamed output: %v; stderr=%q", err, stderr.String())
	}
	_ = stdout.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("sshctl kept running after its stdout reader closed")
	}
	if cmd.ProcessState.Success() {
		t.Fatal("sshctl reported success after its stdout reader closed")
	}
}

func TestCompiledHumanRunMasksExplicitSecretsInStreamedOutput(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "stream-secret")
	secretPath := filepath.Join(cli.temp, "stream-secret")
	if err := os.WriteFile(secretPath, []byte("STREAM_SECRET_CANARY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := cli.Run(t, "sshctl", nil, "--offline", "run", "stream-secret", "--secret", "TOKEN=@"+secretPath,
		"--argv", "sh", "-c", `printf 'out=%s\n' "$TOKEN"; printf 'err=%s\n' "$TOKEN" >&2`)
	if result.ProcessExit != 0 || result.Stdout != "out=***\n" || result.Stderr != "err=***\n" {
		t.Fatalf("secret masking exit=%d stdout=%q stderr=%q", result.ProcessExit, result.Stdout, result.Stderr)
	}
}

func TestCompiledBufferedHumanRunOverflowDoesNotHang(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "buffered-overflow")
	result := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_RUN_OUTPUT": "buffered"},
		"--offline", "run", "buffered-overflow", "--argv", "sh", "-c", "head -c 16777216 /dev/zero")
	if result.ProcessExit != 1 || result.Stdout != "" || !strings.Contains(result.Stderr, "error=internal") {
		t.Fatalf("buffered overflow exit=%d stdout_bytes=%d stderr=%q", result.ProcessExit, len(result.Stdout), result.Stderr)
	}
	assertNoDiagnosticSpools(t, cli.temp)
}
