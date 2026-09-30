package ssh

import (
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// jumpTestServer is an SSH server that authenticates with password "pw" and
// forwards direct-tcpip channels to any address, like a jump host.
type jumpTestServer struct {
	address      string
	signer       gossh.Signer
	active       atomic.Int64
	forwards     atomic.Int64
	authAttempts atomic.Int64
}

func startJumpTestServer(t *testing.T) *jumpTestServer {
	t.Helper()
	server := &jumpTestServer{signer: newTestSigner(t, "ed25519")}
	cfg := &gossh.ServerConfig{
		PasswordCallback: func(_ gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			server.authAttempts.Add(1)
			if string(password) != "pw" {
				return nil, errors.New("bad password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(server.signer)
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
				server.active.Add(1)
				defer server.active.Add(-1)
				defer func() { _ = serverConn.Close() }()
				go func() {
					for request := range requests {
						if request.WantReply {
							_ = request.Reply(request.Type == "keepalive@openssh.com", nil)
						}
					}
				}()
				for newChannel := range channels {
					if newChannel.ChannelType() != "direct-tcpip" {
						_ = newChannel.Reject(gossh.UnknownChannelType, "forwarding only")
						continue
					}
					go server.forward(newChannel)
				}
			}()
		}
	}()
	return server
}

func (s *jumpTestServer) forward(newChannel gossh.NewChannel) {
	var request struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := gossh.Unmarshal(newChannel.ExtraData(), &request); err != nil {
		_ = newChannel.Reject(gossh.ConnectionFailed, "bad request")
		return
	}
	upstream, err := net.Dial("tcp", net.JoinHostPort(request.Host, strconv.Itoa(int(request.Port))))
	if err != nil {
		_ = newChannel.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = upstream.Close()
		return
	}
	go gossh.DiscardRequests(requests)
	s.forwards.Add(1)
	var once sync.Once
	closeBoth := func() { _ = channel.Close(); _ = upstream.Close() }
	go func() { _, _ = io.Copy(upstream, channel); once.Do(closeBoth) }()
	go func() { _, _ = io.Copy(channel, upstream); once.Do(closeBoth) }()
}

func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func jumpVault(t *testing.T, jumpAddress, targetAddress string) (config.Connection, *config.Vault) {
	t.Helper()
	jump := connectionFor(t, jumpAddress)
	jump.Name = "jump"
	target := connectionFor(t, targetAddress)
	target.Name = "target"
	target.ProxyJump = "jump"
	return target, &config.Vault{Connections: []config.Connection{jump, target}}
}

func TestDialChainClosesJumpClientsWithTarget(t *testing.T) {
	setTestHome(t, t.TempDir())
	jump := startJumpTestServer(t)
	target := startKeepaliveServer(t)
	targetConn, vault := jumpVault(t, jump.address, target.address)
	trustAddress(t, vault.Connections[0])
	trustAddress(t, connectionFor(t, target.address))
	t.Setenv("SSM_KEEPALIVE", "50ms")

	before := runtime.NumGoroutine()
	client, err := dialSSHFresh(targetConn, vault)
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the jump connection", func() bool { return jump.active.Load() == 1 })
	if jump.forwards.Load() != 1 {
		t.Fatalf("jump forwarded %d channels, want 1", jump.forwards.Load())
	}
	_ = client.Close()
	waitUntil(t, "the jump connection to close with the target", func() bool { return jump.active.Load() == 0 })
	waitUntil(t, "goroutines to stop", func() bool { return runtime.NumGoroutine() <= before+2 })
}

func TestDialChainFailureClosesJumpClientsAndNamesTheHop(t *testing.T) {
	setTestHome(t, t.TempDir())
	jump := startJumpTestServer(t)
	target := startKeepaliveServer(t)
	targetConn, vault := jumpVault(t, jump.address, target.address)
	trustAddress(t, vault.Connections[0]) // the target key is deliberately not trusted

	_, err := dialSSHFresh(targetConn, vault)
	failure, ok := machinecontract.FailureFromError(err)
	if !ok || failure.Error != machinecontract.CodeHostKeyUnknown || failure.Via != "target" {
		t.Fatalf("failure = %+v ok=%v err=%v, want host_key_unknown via target", failure, ok, err)
	}
	waitUntil(t, "the jump connection to close after the failed dial", func() bool { return jump.active.Load() == 0 })
}

func TestDialChainUntrustedJumpNeverContactsTarget(t *testing.T) {
	setTestHome(t, t.TempDir())
	jump := startJumpTestServer(t)
	target := startJumpTestServer(t)
	targetConn, vault := jumpVault(t, jump.address, target.address)
	trustAddress(t, connectionFor(t, target.address))

	_, err := dialSSHFresh(targetConn, vault)
	failure, ok := machinecontract.FailureFromError(err)
	if !ok || failure.Error != machinecontract.CodeHostKeyUnknown || failure.Via != "jump" {
		t.Fatalf("failure = %+v ok=%v err=%v, want host_key_unknown via jump", failure, ok, err)
	}
	if jump.authAttempts.Load() != 0 || jump.forwards.Load() != 0 || target.authAttempts.Load() != 0 {
		t.Fatalf("untrusted jump got auth=%d forwards=%d, target auth=%d, want none", jump.authAttempts.Load(), jump.forwards.Load(), target.authAttempts.Load())
	}
}

func TestDialChainBoundsTunnelledHandshake(t *testing.T) {
	setTestHome(t, t.TempDir())
	jump := startJumpTestServer(t)
	silent, _ := silentListener(t)
	trustAddress(t, connectionFor(t, jump.address))
	targetConn, vault := jumpVault(t, jump.address, net.JoinHostPort(silent.Host, strconv.Itoa(silent.Port)))
	t.Setenv("SSM_CONNECT_TIMEOUT", "500ms")

	started := time.Now()
	_, err := dialSSHFresh(targetConn, vault)
	failure, ok := machinecontract.FailureFromError(err)
	if !ok || failure.Error != machinecontract.CodeHandshakeFailed || failure.Stage != "handshake" || failure.Via != "target" {
		t.Fatalf("failure = %+v ok=%v err=%v, want handshake_failed/handshake via target", failure, ok, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("tunnelled handshake deadline took %s", elapsed)
	}
	waitUntil(t, "the jump connection to close", func() bool { return jump.active.Load() == 0 })
}

func TestDialChainRejectsInvalidChainsWithoutDialing(t *testing.T) {
	setTestHome(t, t.TempDir())
	a := config.Connection{Name: "a", Host: "127.0.0.1", Port: 1, User: "u", Password: "pw", ProxyJump: "b"}
	b := config.Connection{Name: "b", Host: "127.0.0.1", Port: 1, User: "u", Password: "pw", ProxyJump: "a"}
	_, err := dialSSHFresh(a, &config.Vault{Connections: []config.Connection{a, b}})
	failure, ok := machinecontract.FailureFromError(err)
	if !ok || failure.Error != "proxy_jump_invalid" || failure.Stage != "validate" || failure.Exit != 2 {
		t.Fatalf("failure = %+v ok=%v err=%v, want proxy_jump_invalid/validate/2", failure, ok, err)
	}
}

func TestPoolKeyChainDistinguishesJumpPaths(t *testing.T) {
	target := config.Connection{Name: "t", Host: "10.0.0.9", Port: 22, User: "u", Password: "pw", ProxyJump: "j1"}
	j1 := config.Connection{Name: "j1", Host: "10.0.0.1", Port: 22, User: "u", Password: "pw"}
	j2 := config.Connection{Name: "j2", Host: "10.0.0.2", Port: 22, User: "u", Password: "pw"}
	vault := &config.Vault{Connections: []config.Connection{target, j1, j2}}
	viaOne := poolKeyChain(target, vault)
	target.ProxyJump = "j2"
	viaTwo := poolKeyChain(target, vault)
	direct := poolKeyChain(config.Connection{Name: "t", Host: "10.0.0.9", Port: 22, User: "u", Password: "pw"}, vault)
	if viaOne == viaTwo || viaOne == direct || viaTwo == direct {
		t.Fatalf("pool keys must differ per chain: %q %q %q", viaOne, viaTwo, direct)
	}
}

func TestInspectHostKeyThroughJumpObservesTheTarget(t *testing.T) {
	setTestHome(t, t.TempDir())
	jump := startJumpTestServer(t)
	target := startJumpTestServer(t)
	targetConn, vault := jumpVault(t, jump.address, target.address)

	if _, err := InspectHostKeyWithVault(targetConn, vault); err == nil {
		t.Fatal("inspect through an untrusted jump host succeeded")
	} else if failure, ok := machinecontract.FailureFromError(err); !ok || failure.Via != "jump" || failure.Error != machinecontract.CodeHostKeyUnknown {
		t.Fatalf("failure = %+v ok=%v, want host_key_unknown via jump", failure, ok)
	}
	trustAddress(t, vault.Connections[0])

	report, err := InspectHostKeyWithVault(targetConn, vault)
	if err != nil {
		t.Fatal(err)
	}
	want := gossh.FingerprintSHA256(target.signer.PublicKey())
	if report.Status != "new" || report.Fingerprint != want {
		t.Fatalf("report = %+v, want status new and the target fingerprint %s", report, want)
	}
	if target.authAttempts.Load() != 0 {
		t.Fatal("host key inspection authenticated to the target")
	}
	accepted, err := AcceptHostKeyWithVault(targetConn, vault, want)
	if err != nil || !accepted.Accepted {
		t.Fatalf("accept = %+v err=%v", accepted, err)
	}
	waitUntil(t, "the jump connection to close", func() bool { return jump.active.Load() == 0 })
}
