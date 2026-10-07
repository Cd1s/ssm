//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"ssm/internal/config"
)

func TestCompiledTunnelReadyAndSignal(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: "pw"})
	cli.TrustSSHHost(t, server)
	connection := server.Connection("tunnel", "pw")
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{connection}})
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	go func() {
		for {
			conn, acceptErr := target.Accept()
			if acceptErr != nil {
				return
			}
			go func() { defer func() { _ = conn.Close() }(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	_, targetPort, _ := net.SplitHostPort(target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cli.paths["sshctl"], "--json", "tunnel", "tunnel", "-L", "127.0.0.1:0:127.0.0.1:"+targetPort) //nolint:gosec // executable and arguments are test-owned fixture values
	cmd.Env = isolatedCompiledCLIEnvironmentWith(cli.home, cli.temp, map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath})
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	lines := make([]map[string]any, 0, 2)
	readyLine := make(chan error, 1)
	go func() {
		if !scanner.Scan() {
			readyLine <- io.EOF
			return
		}
		var value map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &value); err != nil {
			readyLine <- err
			return
		}
		lines = append(lines, value)
		readyLine <- nil
	}()
	if err := <-readyLine; err != nil {
		t.Fatalf("ready JSON: %v stderr=%s", err, stderr.String())
	}
	if !lines[0]["ok"].(bool) || lines[0]["alias"] != "tunnel" {
		t.Fatalf("ready JSON = %+v", lines[0])
	}
	listeners, ok := lines[0]["listeners"].([]any)
	if !ok || len(listeners) != 1 {
		t.Fatalf("ready listeners = %+v", lines[0]["listeners"])
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() {
		t.Fatalf("missing closed JSON, stderr=%s", stderr.String())
	}
	var closed map[string]any
	if err := json.Unmarshal(scanner.Bytes(), &closed); err != nil {
		t.Fatal(err)
	}
	if closed["event"] != "closed" || closed["reason"] != "signal" {
		t.Fatalf("closed JSON = %+v", closed)
	}
	if scanner.Scan() {
		t.Fatal("tunnel emitted more than one ready and one closed JSON line")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("tunnel exit = %v stderr=%s", err, stderr.String())
	}
}

func TestCompiledTunnelArgumentContracts(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	for _, tc := range []struct {
		name  string
		args  []string
		error string
		exit  float64
	}{
		{"missing-forward", []string{"--json", "tunnel", "alias"}, "tunnel_invalid_arguments", 2},
		{"remote-bind", []string{"--json", "tunnel", "alias", "-D", "0.0.0.0:12345"}, "tunnel_remote_bind_refused", 2},
		{"bad-port", []string{"--json", "tunnel", "alias", "-D", "127.0.0.1:65536"}, "tunnel_invalid_arguments", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := cli.Run(t, "sshctl", nil, tc.args...)
			if result.ProcessExit != int(tc.exit) {
				t.Fatalf("exit = %d, want %d stderr=%s", result.ProcessExit, int(tc.exit), result.Stderr)
			}
			var value map[string]any
			if err := json.Unmarshal([]byte(result.Stdout), &value); err != nil {
				t.Fatalf("stdout=%q: %v", result.Stdout, err)
			}
			if value["error"] != tc.error || value["stage"] != "tunnel" {
				t.Fatalf("contract = %+v", value)
			}
		})
	}
}
