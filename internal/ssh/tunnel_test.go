package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func TestParseLocalForward(t *testing.T) {
	valid := []string{"15037:127.0.0.1:5037", "127.0.0.1:15037:target:5037", "[::1]:15037:[::1]:5037"}
	for _, in := range valid {
		if _, err := ParseLocalForward(in); err != nil {
			t.Errorf("ParseLocalForward(%q): %v", in, err)
		}
	}
	invalid := []string{"", "15037", ":target:5037", "127.0.0.1:0:target:1", "127.0.0.1:65536:target:1", "127.0.0.1:1::1", "127.0.0.1:1:target:65536", "a:b:c:d:e"}
	for _, in := range invalid {
		if _, err := ParseLocalForward(in); err == nil {
			t.Errorf("ParseLocalForward(%q) unexpectedly succeeded", in)
		}
	}
}

func TestParseDynamicForward(t *testing.T) {
	for _, in := range []string{"15037", "127.0.0.1:15037", "[::1]:15037"} {
		if _, err := ParseDynamicForward(in); err != nil {
			t.Errorf("ParseDynamicForward(%q): %v", in, err)
		}
	}
	for _, in := range []string{"", "0", "65536", "host:1:2"} {
		if _, err := ParseDynamicForward(in); err == nil {
			t.Errorf("ParseDynamicForward(%q) unexpectedly succeeded", in)
		}
	}
}

func TestRunTunnelRejectsRemoteBindBeforeDial(t *testing.T) {
	_, err := RunTunnel(context.Background(), config.Connection{}, nil, []TunnelSpec{{Kind: "dynamic", Bind: "192.0.2.1", Port: 12345}}, TunnelOptions{})
	if err == nil {
		t.Fatal("remote bind unexpectedly accepted")
	}
	failure, ok := machinecontract.FailureFromError(err)
	if !ok || failure.Error != "tunnel_remote_bind_refused" {
		t.Fatalf("error = %v, failure = %+v", err, failure)
	}
}

func TestRunTunnelDoesNotListenWhileSSHHandshakeFails(t *testing.T) {
	setTestHome(t, t.TempDir())
	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sshListener.Close() }()
	accepted := make(chan net.Conn, 1)
	release := make(chan struct{})
	go func() {
		conn, acceptErr := sshListener.Accept()
		if acceptErr == nil {
			accepted <- conn
			defer func() { _ = conn.Close() }()
			<-release
		}
	}()
	_, sshPortText, _ := net.SplitHostPort(sshListener.Addr().String())
	sshPort, _ := strconv.Atoi(sshPortText)
	connection := config.Connection{Name: "stalled", Host: "127.0.0.1", Port: sshPort, User: "test", Password: "pw"}
	forwardListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, forwardPortText, _ := net.SplitHostPort(forwardListener.Addr().String())
	forwardPort, _ := strconv.Atoi(forwardPortText)
	_ = forwardListener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, runErr := RunTunnel(ctx, connection, nil, []TunnelSpec{{Kind: "dynamic", Bind: "127.0.0.1", Port: forwardPort}}, TunnelOptions{})
		done <- runErr
	}()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("SSH dial did not reach stalled server")
	}
	probe, listenErr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(forwardPort)))
	if listenErr != nil {
		t.Fatalf("forward port was opened before SSH succeeded: %v", listenErr)
	}
	_ = probe.Close()
	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunTunnel did not stop after handshake cancellation")
	}
}

func tunnelServer(t *testing.T) (*jumpTestServer, config.Connection, *config.Vault) {
	t.Helper()
	setTestHome(t, t.TempDir())
	server := startJumpTestServer(t)
	conn := connectionFor(t, server.address)
	trustRunTestHost(t, conn)
	return server, conn, &config.Vault{}
}

func startTunnelEcho(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
				if cw, ok := conn.(*net.TCPConn); ok {
					_ = cw.CloseWrite()
				}
			}()
		}
	}()
	return listener.Addr().String(), func() { close(stop); _ = listener.Close() }
}

func startBlockingTunnelTarget(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	stop := make(chan struct{})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				<-release
			}()
		}
	}()
	return listener.Addr().String(), release, func() { close(stop); _ = listener.Close(); releaseOnce.Do(func() { close(release) }) }
}

func runTunnel(t *testing.T, conn config.Connection, vault *config.Vault, spec TunnelSpec, opts TunnelOptions) (chan TunnelResult, chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan TunnelResult, 2)
	opts.OnReady = func(result TunnelResult) error { ready <- result; return nil }
	done := make(chan error, 1)
	go func() {
		result, err := RunTunnel(ctx, conn, vault, []TunnelSpec{spec}, opts)
		if err == nil {
			ready <- result
		}
		done <- err
	}()
	return ready, done, cancel
}

func listenerAddress(t *testing.T, ready <-chan TunnelResult) string {
	t.Helper()
	select {
	case result := <-ready:
		if len(result.Listeners) != 1 {
			t.Fatalf("listeners = %+v", result.Listeners)
		}
		return result.Listeners[0].Bind
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not become ready")
		return ""
	}
}

func TestRunTunnelLocalForwardMiBAndEOF(t *testing.T) {
	server, conn, vault := tunnelServer(t)
	target, stopTarget := startTunnelEcho(t)
	defer stopTarget()
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	ready, done, cancel := runTunnel(t, conn, vault, TunnelSpec{Kind: "local", Bind: "127.0.0.1", Host: host, TargetPort: port}, TunnelOptions{})
	address := listenerAddress(t, ready)
	client, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(data)
	if _, err := client.Write(data); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	_, err = io.ReadFull(client, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) || sha256.Sum256(got) != wantHash {
		t.Fatalf("echo mismatch: got %d bytes", len(got))
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(server.Targets()) == 0 {
		t.Fatal("SSH server did not receive direct-tcpip")
	}
}

func socksHandshake(t *testing.T, address string, methods ...byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil { //nolint:gosec // test methods are a short fixed SOCKS list
		_ = conn.Close()
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	return conn
}

func socksRequest(t *testing.T, conn net.Conn, cmd, atyp byte, host string, port int) byte {
	t.Helper()
	request := []byte{5, cmd, 0, atyp}
	if port < 0 || port > 65535 {
		t.Fatalf("invalid test port %d", port)
	}
	switch atyp {
	case 1:
		request = append(request, net.ParseIP(host).To4()...)
	case 3:
		request = append(request, byte(len(host))) //nolint:gosec // test host names are bounded below the SOCKS byte limit
		request = append(request, host...)
	case 4:
		request = append(request, net.ParseIP(host).To16()...)
	default:
		request = append(request, 1, 2, 3)
	}
	port16 := uint16(port)                                   //nolint:gosec // validated to 0..65535 immediately above
	request = append(request, byte(port16>>8), byte(port16)) //nolint:gosec // uint16 halves are intentional wire bytes
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	return response[1]
}

// Many clients send a request, half-close their write side, and then read the
// reply until EOF. The end of the request direction must not cut the reply
// short: everything the target sends back has to arrive.
func TestRunTunnelHalfClosedRequestStillGetsCompleteReply(t *testing.T) {
	_, conn, vault := tunnelServer(t)
	target, stopTarget := startTunnelEcho(t)
	defer stopTarget()
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	ready, done, cancel := runTunnel(t, conn, vault, TunnelSpec{Kind: "local", Bind: "127.0.0.1", Host: host, TargetPort: port}, TunnelOptions{})
	address := listenerAddress(t, ready)
	client, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, werr := client.Write(data)
		if cw, ok := client.(*net.TCPConn); ok && werr == nil {
			werr = cw.CloseWrite()
		}
		writeDone <- werr
	}()
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("reading until EOF: %v (got %d of %d bytes)", err, len(got), len(data))
	}
	if werr := <-writeDone; werr != nil {
		t.Fatal(werr)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("half-closed request got %d bytes back, want all %d", len(got), len(data))
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunTunnelSOCKSConnectIPv4DomainAndFailures(t *testing.T) {
	server, conn, vault := tunnelServer(t)
	target, stopTarget := startTunnelEcho(t)
	defer stopTarget()
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	ready, done, cancel := runTunnel(t, conn, vault, TunnelSpec{Kind: "dynamic", Bind: "127.0.0.1"}, TunnelOptions{})
	address := listenerAddress(t, ready)
	client := socksHandshake(t, address, 0)
	if code := socksRequest(t, client, 1, 1, host, port); code != 0 {
		t.Fatalf("IPv4 CONNECT code = %d", code)
	}
	_, _ = client.Write([]byte("ipv4"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "ipv4" {
		t.Fatalf("IPv4 echo = %q, err=%v", buf, err)
	}
	_ = client.Close()
	client = socksHandshake(t, address, 0)
	if code := socksRequest(t, client, 1, 3, "localhost", port); code != 0 {
		t.Fatalf("domain CONNECT code = %d", code)
	}
	_ = client.Close()
	waitUntil(t, "domain target", func() bool {
		for _, target := range server.Targets() {
			if target == "localhost:"+portText {
				return true
			}
		}
		return false
	})
	for _, tc := range []struct {
		name            string
		cmd, atyp, want byte
	}{{"bind", 2, 1, 7}, {"udp", 3, 1, 7}, {"atyp", 1, 9, 8}} {
		t.Run(tc.name, func(t *testing.T) {
			c := socksHandshake(t, address, 0)
			if code := socksRequest(t, c, tc.cmd, tc.atyp, host, port); code != tc.want {
				t.Fatalf("failure code = %d, want %d", code, tc.want)
			}
			_ = c.Close()
		})
	}
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 1, 2})
	response := make([]byte, 2)
	if _, err := io.ReadFull(c, response); err != nil || response[1] != 0xff {
		t.Fatalf("unsupported method response = %v, err=%v", response, err)
	}
	_ = c.Close()
	c = socksHandshake(t, address, 0)
	_, _ = c.Write([]byte{4, 1, 0, 1})
	response = make([]byte, 2)
	if _, err := io.ReadFull(c, response); err != nil || response[1] != 1 {
		t.Fatalf("bad version response = %v, err=%v", response, err)
	}
	_ = c.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A long domain name must reach the far end byte for byte. A reader that does
// not honour the declared length byte (fixed width, off-by-one, truncation at
// a small limit) would deliver a different name, or desynchronise the stream.
func TestRunTunnelSOCKSDomainLengthIsHonoured(t *testing.T) {
	server, conn, vault := tunnelServer(t)
	ready, done, cancel := runTunnel(t, conn, vault, TunnelSpec{Kind: "dynamic", Bind: "127.0.0.1"}, TunnelOptions{})
	address := listenerAddress(t, ready)
	for _, name := range []string{"a.example", "a-fairly-long-host-name.internal.example.org", strings.Repeat("x", 63) + "." + strings.Repeat("y", 63) + ".example", strings.Repeat("z", 255)} {
		client := socksHandshake(t, address, 0)
		if code := socksRequest(t, client, 1, 3, name, 4242); code != 0 && code != 5 {
			t.Fatalf("domain %d bytes: SOCKS code = %d, want success or a refused connection", len(name), code)
		}
		_ = client.Close()
		want := name + ":4242"
		waitUntil(t, "domain of "+strconv.Itoa(len(name))+" bytes", func() bool {
			for _, target := range server.Targets() {
				if target == want {
					return true
				}
			}
			return false
		})
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunTunnelSOCKSMalformedAndHandshakeTimeout(t *testing.T) {
	old := socksHandshakeTimeout
	socksHandshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { socksHandshakeTimeout = old })
	server, conn, vault := tunnelServer(t)
	ready, done, cancel := runTunnel(t, conn, vault, TunnelSpec{Kind: "dynamic", Bind: "127.0.0.1"}, TunnelOptions{})
	address := listenerAddress(t, ready)
	for _, input := range [][]byte{{5}, {5, 1}, {5, 1, 0}, {5, 1, 0, 3, 255, 'a', 'b', 'c', 0, 80}} {
		c, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(input)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = io.ReadAll(c)
		_ = c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if len(server.Targets()) != 0 {
		t.Fatalf("malformed SOCKS request opened target channels: %v", server.Targets())
	}
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	time.Sleep(150 * time.Millisecond)
	_ = c.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunTunnelConcurrentConnectionsAndLimit(t *testing.T) {
	server, conn, vault := tunnelServer(t)
	target, stopTarget := startTunnelEcho(t)
	defer stopTarget()
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	ready, done, cancel := runTunnel(t, conn, vault, TunnelSpec{Kind: "local", Bind: "127.0.0.1", Host: host, TargetPort: port}, TunnelOptions{})
	address := listenerAddress(t, ready)
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.Dial("tcp", address)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close() }()
			payload := []byte(fmt.Sprintf("connection-%03d", i))
			if _, err := c.Write(payload); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
				errs <- fmt.Errorf("connection %d got %q: %v", i, got, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if len(server.Targets()) < 50 {
		t.Fatalf("direct-tcpip targets = %d, want at least 50", len(server.Targets()))
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	oldLimit := tunnelMaxConnections
	tunnelMaxConnections = 3
	t.Cleanup(func() { tunnelMaxConnections = oldLimit })
	target, _, stopTarget = startBlockingTunnelTarget(t)
	host, portText, _ = net.SplitHostPort(target)
	port, _ = strconv.Atoi(portText)
	baselineTargets := len(server.Targets())
	ready, done, cancel = runTunnel(t, conn, vault, TunnelSpec{Kind: "local", Bind: "127.0.0.1", Host: host, TargetPort: port}, TunnelOptions{})
	address = listenerAddress(t, ready)
	connections := make([]net.Conn, 10)
	var err error
	for i := range connections {
		connections[i], err = net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "three limited forwards", func() bool { return len(server.Targets()) >= baselineTargets+3 })
	time.Sleep(100 * time.Millisecond)
	if got := len(server.Targets()); got != baselineTargets+3 {
		t.Fatalf("limited direct-tcpip targets = %d, want exactly %d", got, baselineTargets+3)
	}
	if len(server.Targets()) < baselineTargets+3 {
		t.Fatalf("limited targets = %d", len(server.Targets()))
	}
	for i := 3; i < len(connections); i++ {
		_ = connections[i].SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		_, writeErr := connections[i].Write([]byte("overflow"))
		if writeErr == nil {
			_ = connections[i].SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			buf := make([]byte, len("overflow"))
			if _, readErr := io.ReadFull(connections[i], buf); readErr == nil {
				t.Fatalf("overflow connection %d remained active", i)
			}
		}
	}
	for _, c := range connections {
		_ = c.Close()
	}
	stopTarget()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunTunnelLifecycleReadyDurationAndConnectionLost(t *testing.T) {
	server, conn, vault := tunnelServer(t)
	readyFile := filepath.Join(t.TempDir(), "ready.json")
	ready, done, cancel := runTunnel(t, conn, vault, TunnelSpec{Kind: "dynamic", Bind: "127.0.0.1"}, TunnelOptions{ReadyFile: readyFile})
	address := listenerAddress(t, ready)
	info, err := os.Stat(readyFile)
	// Windows reports every file as 0666; only POSIX modes are meaningful.
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("ready file stat = %v, info=%v", err, info)
	}
	cancel()
	result := <-ready
	if result.Reason != "signal" {
		t.Fatalf("reason = %q", result.Reason)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(readyFile); !os.IsNotExist(err) {
		t.Fatalf("ready file remains: %v", err)
	}
	probe, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = probe.Close()
	ready, done, _ = runTunnel(t, conn, vault, TunnelSpec{Kind: "dynamic", Bind: "127.0.0.1"}, TunnelOptions{Duration: 50 * time.Millisecond})
	_ = listenerAddress(t, ready)
	result = <-ready
	if result.Reason != "duration" {
		t.Fatalf("duration reason = %q", result.Reason)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	before := runtime.NumGoroutine()
	ready, done, _ = runTunnel(t, conn, vault, TunnelSpec{Kind: "dynamic", Bind: "127.0.0.1"}, TunnelOptions{})
	_ = listenerAddress(t, ready)
	server.Close()
	if err := <-done; err == nil {
		t.Fatal("expected connection_lost")
	} else if failure, ok := machinecontract.FailureFromError(err); !ok || failure.Error != machinecontract.CodeConnectionLost {
		t.Fatalf("connection loss = %+v, ok=%v", failure, ok)
	}
	waitUntil(t, "tunnel goroutines", func() bool { return runtime.NumGoroutine() <= before+8 })
}

// runTunnelBounded runs a tunnel that must NOT come up. If host-key
// verification were bypassed the tunnel would establish and block forever, so
// the context is cancelled shortly after and "it started" is reported as a
// failure instead of hanging the test.
func runTunnelBounded(t *testing.T, conn config.Connection) (started bool, err error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		_, runErr := RunTunnel(ctx, conn, &config.Vault{}, []TunnelSpec{{Kind: "dynamic", Bind: "127.0.0.1", Port: 0}}, TunnelOptions{
			OnReady: func(TunnelResult) error { ready <- struct{}{}; return nil },
		})
		done <- runErr
	}()
	select {
	case <-ready:
		cancel()
		<-done
		return true, nil
	case runErr := <-done:
		return false, runErr
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("tunnel neither failed nor came up within 5s")
		return false, nil
	}
}

func TestRunTunnelHostKeyUnknownAndMismatch(t *testing.T) {
	server := startJumpTestServer(t)
	conn := connectionFor(t, server.address)
	setTestHome(t, t.TempDir())
	started, err := runTunnelBounded(t, conn)
	if started {
		t.Fatal("tunnel came up for an unknown host key: host-key verification was bypassed")
	}
	if failure, ok := machinecontract.FailureFromError(err); !ok || failure.Error != machinecontract.CodeHostKeyUnknown {
		t.Fatalf("unknown host key = %+v, ok=%v, err=%v", failure, ok, err)
	}
	setTestHome(t, t.TempDir())
	writeTestKnownHosts(t, os.Getenv("HOME"), knownLine(server.address, newTestSigner(t, "ed25519")))
	started, err = runTunnelBounded(t, conn)
	if started {
		t.Fatal("tunnel came up for a mismatched host key: host-key verification was bypassed")
	}
	if failure, ok := machinecontract.FailureFromError(err); !ok || failure.Error != machinecontract.CodeHostKey {
		t.Fatalf("mismatched host key = %+v, ok=%v, err=%v", failure, ok, err)
	}
}

func TestRunTunnelThroughProxyJump(t *testing.T) {
	setTestHome(t, t.TempDir())
	jump := startJumpTestServer(t)
	target := startJumpTestServer(t)
	connection, vault := jumpVault(t, jump.address, target.address)
	trustRunTestHost(t, vault.Connections[0])
	trustRunTestHost(t, connectionFor(t, target.address))
	address, stopTarget := startTunnelEcho(t)
	defer stopTarget()
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	ready, done, cancel := runTunnel(t, connection, vault, TunnelSpec{Kind: "local", Bind: "127.0.0.1", Host: host, TargetPort: port}, TunnelOptions{})
	listener := listenerAddress(t, ready)
	c, err := net.Dial("tcp", listener)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("jump"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "jump" {
		t.Fatalf("jump echo = %q, err=%v", got, err)
	}
	_ = c.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
