package ssh

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func TestKeepaliveIntervalFromEnvironment(t *testing.T) {
	tests := []struct {
		name  string
		value string
		set   bool
		want  time.Duration
	}{
		{"default", "", false, 15 * time.Second},
		{"empty uses default", "", true, 15 * time.Second},
		{"zero disables", "0", true, 0},
		{"off disables", "off", true, 0},
		{"false disables", "false", true, 0},
		{"duration", "200ms", true, 200 * time.Millisecond},
		{"integer seconds", "3", true, 3 * time.Second},
		{"garbage uses default", "sometimes", true, 15 * time.Second},
		{"negative uses default", "-5s", true, 15 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.set {
				t.Setenv("SSM_KEEPALIVE", test.value)
			} else {
				t.Setenv("SSM_KEEPALIVE", "")
			}
			if got := KeepaliveInterval(); got != test.want {
				t.Fatalf("KeepaliveInterval() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestConnectTimeoutEnvironmentPrecedence(t *testing.T) {
	t.Setenv("SSM_DIAL_TIMEOUT", "9s")
	t.Setenv("SSM_TIMEOUT", "7s")
	t.Setenv("SSM_CONNECT_TIMEOUT", "3s")
	if got := DialTimeout(); got != 3*time.Second {
		t.Fatalf("SSM_CONNECT_TIMEOUT must win: got %v", got)
	}
	t.Setenv("SSM_CONNECT_TIMEOUT", "")
	if got := DialTimeout(); got != 7*time.Second {
		t.Fatalf("SSM_TIMEOUT alias must still work: got %v", got)
	}
}

// silentListener accepts TCP connections and never writes, like an sshd that
// does not answer the handshake.
func silentListener(t *testing.T) (config.Connection, *config.Vault) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, raw)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, raw := range held {
			_ = raw.Close()
		}
	})
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	return config.Connection{Name: "silent", Host: "127.0.0.1", Port: port, User: "test", Password: "unused"}, &config.Vault{}
}

func TestDialSSHFreshBoundsHandshakeWithDefaultTimeoutPath(t *testing.T) {
	setTestHome(t, t.TempDir())
	conn, vault := silentListener(t)
	// No flag is involved: dialSSHFresh applies DialTimeout(), whose default
	// path is the same code SSM_TIMEOUT feeds.
	t.Setenv("SSM_TIMEOUT", "400ms")

	type outcome struct {
		client *gossh.Client
		err    error
	}
	done := make(chan outcome, 1)
	started := time.Now()
	go func() {
		client, err := dialSSHFresh(conn, vault)
		done <- outcome{client, err}
	}()
	select {
	case got := <-done:
		if got.err == nil {
			_ = got.client.Close()
			t.Fatal("handshake against a silent server succeeded")
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("handshake deadline took %s", elapsed)
		}
		failure, ok := machinecontract.FailureFromError(got.err)
		if !ok || failure.Error != machinecontract.CodeHandshakeFailed || failure.Stage != "handshake" {
			t.Fatalf("failure = %+v ok=%v err=%v, want handshake_failed/handshake", failure, ok, got.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("dialSSHFresh hung on a server that never answers the SSH handshake")
	}
}

func TestHostKeyInspectBoundsSilentHandshake(t *testing.T) {
	setTestHome(t, t.TempDir())
	conn, _ := silentListener(t)
	t.Setenv("SSM_CONNECT_TIMEOUT", "400ms")
	done := make(chan error, 1)
	go func() {
		_, err := InspectHostKey(conn)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("inspect succeeded against a silent server")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("InspectHostKey hung on a silent handshake")
	}
}

// keepaliveServer is an SSH server that counts keepalive@openssh.com global
// requests and answers them.
type keepaliveServer struct {
	address    string
	keepalives atomic.Int64
	signer     gossh.Signer
}

func startKeepaliveServer(t *testing.T) *keepaliveServer {
	t.Helper()
	signer := newTestSigner(t, "ed25519")
	server := &keepaliveServer{signer: signer}
	cfg := &gossh.ServerConfig{
		PasswordCallback: func(_ gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			if string(password) != "pw" {
				return nil, errors.New("bad password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server.address = listener.Addr().String()
	go func() {
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
				defer func() { _ = serverConn.Close() }()
				go func() {
					for request := range requests {
						if request.Type == "keepalive@openssh.com" {
							server.keepalives.Add(1)
						}
						if request.WantReply {
							_ = request.Reply(request.Type == "keepalive@openssh.com", nil)
						}
					}
				}()
				for newChannel := range channels {
					_ = newChannel.Reject(gossh.Prohibited, "no channels")
				}
			}()
		}
	}()
	return server
}

// pausableProxy forwards until pause is set, then drops both directions
// silently while keeping the sockets open.
type pausableProxy struct {
	address string
	paused  atomic.Bool
}

func startPausableProxy(t *testing.T, target string) *pausableProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &pausableProxy{address: listener.Addr().String()}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			upstream, err := net.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			var once sync.Once
			closeBoth := func() { _ = client.Close(); _ = upstream.Close() }
			pipe := func(from, to net.Conn) {
				defer once.Do(closeBoth)
				buffer := make([]byte, 32<<10)
				for {
					n, err := from.Read(buffer)
					if n > 0 && !proxy.paused.Load() {
						if _, werr := to.Write(buffer[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			go pipe(client, upstream)
			go pipe(upstream, client)
		}
	}()
	return proxy
}

func connectionFor(t *testing.T, address string) config.Connection {
	t.Helper()
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	return config.Connection{Name: "keepalive", Host: host, Port: port, User: "test", Password: "pw"}
}

func trustAddress(t *testing.T, conn config.Connection) {
	t.Helper()
	trustRunTestHost(t, conn)
}

func TestKeepaliveSendsRequestsAndStopsWithClient(t *testing.T) {
	setTestHome(t, t.TempDir())
	server := startKeepaliveServer(t)
	conn := connectionFor(t, server.address)
	trustAddress(t, conn)
	t.Setenv("SSM_KEEPALIVE", "50ms")

	client, err := dialSSHFresh(conn, &config.Vault{})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for server.keepalives.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := server.keepalives.Load(); got < 3 {
		t.Fatalf("server saw %d keepalive requests, want at least 3", got)
	}

	// The keepalive goroutine must end with the connection so pooled and
	// one-shot clients never leak it.
	finished := make(chan struct{})
	go func() {
		runKeepalive(client, 50*time.Millisecond, keepaliveMaxMisses)
		close(finished)
	}()
	_ = client.Close()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive loop did not exit after the client closed")
	}
}

func TestKeepaliveDisabledSendsNothing(t *testing.T) {
	setTestHome(t, t.TempDir())
	server := startKeepaliveServer(t)
	conn := connectionFor(t, server.address)
	trustAddress(t, conn)
	t.Setenv("SSM_KEEPALIVE", "0")

	client, err := dialSSHFresh(conn, &config.Vault{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	time.Sleep(300 * time.Millisecond)
	if got := server.keepalives.Load(); got != 0 {
		t.Fatalf("SSM_KEEPALIVE=0 still sent %d keepalives", got)
	}
}

func TestKeepaliveClosesClientWhenServerGoesSilent(t *testing.T) {
	setTestHome(t, t.TempDir())
	server := startKeepaliveServer(t)
	proxy := startPausableProxy(t, server.address)
	conn := connectionFor(t, proxy.address)
	trustAddress(t, conn)
	t.Setenv("SSM_KEEPALIVE", "100ms")

	client, err := dialSSHFresh(conn, &config.Vault{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	closed := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(closed)
	}()
	time.Sleep(350 * time.Millisecond)
	select {
	case <-closed:
		t.Fatal("client closed while the path was healthy")
	default:
	}

	proxy.paused.Store(true)
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("keepalive did not close a connection whose path went silent")
	}
}
