package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// limitServer is an in-process SSH server that enforces a per-connection
// session limit the way sshd MaxSessions does: a channel open beyond the limit
// is refused with the administratively-prohibited "open failed" reply while
// the connection and its running sessions stay up.
type limitServer struct {
	connections atomic.Int64
	live        atomic.Int64
	maxLive     atomic.Int64
	interrupted atomic.Int64
	refusals    atomic.Int64
	// silentRequests makes the server swallow global requests without
	// replying, like a half-open peer.
	silentRequests atomic.Bool
	// handshakeDelay stalls each new connection before its SSH handshake.
	handshakeDelay atomic.Int64

	mu    sync.Mutex
	conns []*gossh.ServerConn
	// gate blocks every command named "hold" until it is closed.
	gate chan struct{}
}

func startLimitServer(t *testing.T, limit int) (config.Connection, *config.Vault, *limitServer) {
	t.Helper()
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := gossh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	srv := &limitServer{gate: make(chan struct{})}
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if string(key.Marshal()) != string(clientSigner.PublicKey().Marshal()) {
				return nil, errors.New("unexpected public key")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(newTestSigner(t, "ed25519"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-srv.gate:
		default:
			close(srv.gate)
		}
		_ = listener.Close()
	})
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.serve(raw, cfg, limit)
		}
	}()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	block, err := gossh.MarshalPrivateKey(clientPrivate, "ssm-session-limit")
	if err != nil {
		t.Fatal(err)
	}
	vault := &config.Vault{Keys: []config.SSHKey{{Name: "limit", PrivateKey: string(pem.EncodeToMemory(block))}}}
	conn := config.Connection{Name: "limit", Host: "127.0.0.1", Port: port, User: "test", KeyName: "limit"}
	return conn, vault, srv
}

func (s *limitServer) serve(raw net.Conn, cfg *gossh.ServerConfig, limit int) {
	if d := time.Duration(s.handshakeDelay.Load()); d > 0 {
		time.Sleep(d)
	}
	serverConn, channels, requests, err := gossh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return
	}
	s.connections.Add(1)
	s.mu.Lock()
	s.conns = append(s.conns, serverConn)
	s.mu.Unlock()
	go func() {
		for request := range requests {
			if s.silentRequests.Load() {
				continue
			}
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
		}
	}()
	var open atomic.Int64
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "session only")
			continue
		}
		if int(open.Load()) >= limit {
			s.refusals.Add(1)
			_ = newChannel.Reject(gossh.Prohibited, "open failed")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		open.Add(1)
		live := s.live.Add(1)
		for {
			prev := s.maxLive.Load()
			if live <= prev || s.maxLive.CompareAndSwap(prev, live) {
				break
			}
		}
		go func() {
			defer open.Add(-1)
			defer s.live.Add(-1)
			s.session(channel, channelRequests)
		}()
	}
}

func (s *limitServer) session(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := gossh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		switch {
		case payload.Command == "hold":
			<-s.gate
		case strings.HasPrefix(payload.Command, "slow"):
			time.Sleep(120 * time.Millisecond)
		}
		_, _ = channel.Write([]byte("done\n"))
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
		return
	}
	// The request stream ended before the command finished: the connection died.
	s.interrupted.Add(1)
}

func (s *limitServer) killConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, conn := range s.conns {
		_ = conn.Close()
	}
	s.conns = nil
}

func limitTestRun(conn config.Connection, vault *config.Vault, command string) RunResult {
	return Run(conn, vault, RunOptions{Command: command, Capture: true, RequestedAlias: conn.Name, Mode: "argv"})
}

func setupLimitTest(t *testing.T, limit int) (config.Connection, *config.Vault, *limitServer) {
	t.Helper()
	ClosePool()
	t.Cleanup(ClosePool)
	conn, vault, srv := startLimitServer(t, limit)
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, conn)
	srv.connections.Store(0)
	return conn, vault, srv
}

func TestSessionLimitParallelRunsShareOneConnectionAndAllSucceed(t *testing.T) {
	conn, vault, srv := setupLimitTest(t, 2)

	var wg sync.WaitGroup
	results := make([]RunResult, 6)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = limitTestRun(conn, vault, "slow")
		}()
	}
	wg.Wait()

	for i, res := range results {
		if !res.OK {
			t.Errorf("job %d failed: error=%q message=%q", i, res.Error, res.Message)
		}
	}
	if got := srv.connections.Load(); got != 1 {
		t.Fatalf("SSH connections = %d, want the one shared connection", got)
	}
	if got := srv.maxLive.Load(); got > 2 {
		t.Fatalf("live sessions peaked at %d, above the server limit", got)
	}
	if got := srv.interrupted.Load(); got != 0 {
		t.Fatalf("%d in-flight sessions were interrupted", got)
	}
}

func TestSessionLimitWaitDoesNotHoldPoolEntryLock(t *testing.T) {
	conn, vault, srv := setupLimitTest(t, 1)

	held := make(chan RunResult, 1)
	go func() { held <- limitTestRun(conn, vault, "hold") }()
	waitFor(t, func() bool { return srv.live.Load() == 1 })

	waiter := make(chan RunResult, 1)
	go func() { waiter <- limitTestRun(conn, vault, "slow") }()
	// The waiter must have been refused at least once and be backing off.
	waitFor(t, func() bool { return srv.refusals.Load() >= 1 })

	locked := make(chan struct{})
	go func() {
		entry := lockPoolEntry(poolKey(conn))
		entry.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("pool entry lock stayed held while a run waited for a free session slot")
	}
	pooled := make(chan error, 1)
	go func() {
		_, err := getPooledClient(conn, vault)
		pooled <- err
	}()
	select {
	case err := <-pooled:
		if err != nil {
			t.Fatalf("getPooledClient during slot wait: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("getPooledClient blocked behind a slot wait")
	}

	close(srv.gate)
	for name, ch := range map[string]chan RunResult{"held": held, "waiter": waiter} {
		select {
		case res := <-ch:
			if !res.OK {
				t.Fatalf("%s run failed: %q %q", name, res.Error, res.Message)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s run did not finish", name)
		}
	}
	if got := srv.connections.Load(); got != 1 {
		t.Fatalf("SSH connections = %d, want 1", got)
	}
}

func TestSessionLimitThatNeverFreesReportsSessionLimit(t *testing.T) {
	conn, vault, srv := setupLimitTest(t, 1)
	t.Setenv("SSM_TIMEOUT", "400ms")

	held := make(chan RunResult, 1)
	go func() { held <- limitTestRun(conn, vault, "hold") }()
	waitFor(t, func() bool { return srv.live.Load() == 1 })

	start := time.Now()
	res := limitTestRun(conn, vault, "slow")
	elapsed := time.Since(start)
	if res.OK || res.Error != "session_limit" || res.Stage != "session" || res.Exit != 255 {
		t.Fatalf("result = ok=%v error=%q stage=%q exit=%d, want session_limit at stage session exit 255", res.OK, res.Error, res.Stage, res.Exit)
	}
	if !strings.Contains(res.Hint, "MaxSessions") || !strings.Contains(res.Hint, "-j") {
		t.Fatalf("hint = %q, want -j / MaxSessions advice", res.Hint)
	}
	if elapsed < 200*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("slot wait took %s, want it bounded near SSM_TIMEOUT", elapsed)
	}

	close(srv.gate)
	if first := <-held; !first.OK {
		t.Fatalf("in-flight run was killed by the refused one: %q %q", first.Error, first.Message)
	}
	if got := srv.interrupted.Load(); got != 0 {
		t.Fatalf("%d in-flight sessions were interrupted", got)
	}
}

func TestSessionLimitWaitStopsWhenCancelled(t *testing.T) {
	conn, vault, srv := setupLimitTest(t, 1)
	held := make(chan RunResult, 1)
	go func() { held <- limitTestRun(conn, vault, "hold") }()
	waitFor(t, func() bool { return srv.live.Load() == 1 })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, _, err := acquireSSHSessionContext(ctx, conn, vault, false)
		done <- err
	}()
	waitFor(t, func() bool { return srv.refusals.Load() >= 1 })
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slot wait ignored cancellation")
	}
	close(srv.gate)
	<-held
}

func TestTransportBreakStillEvictsAndRedials(t *testing.T) {
	conn, vault, srv := setupLimitTest(t, 2)

	if res := limitTestRun(conn, vault, "slow"); !res.OK {
		t.Fatalf("first run failed: %q %q", res.Error, res.Message)
	}
	srv.killConnections()
	// The client notices the closed transport asynchronously.
	time.Sleep(100 * time.Millisecond)
	if res := limitTestRun(conn, vault, "slow"); !res.OK {
		t.Fatalf("run after transport break failed: %q %q", res.Error, res.Message)
	}
	if got := srv.connections.Load(); got != 2 {
		t.Fatalf("SSH connections = %d, want a redial after the break", got)
	}
}

func TestIsSessionLimitErrorUsesTypedReason(t *testing.T) {
	prohibited := &gossh.OpenChannelError{Reason: gossh.Prohibited, Message: "open failed"}
	if !machinecontract.IsSessionLimit(prohibited) {
		t.Fatal("administratively prohibited must be a session limit")
	}
	if !machinecontract.IsSessionLimit(errors.Join(errors.New("wrapped"), prohibited)) {
		t.Fatal("wrapped administratively prohibited must be a session limit")
	}
	for _, err := range []error{
		nil,
		errors.New("ssh: rejected: administratively prohibited (open failed)"),
		errors.New("ssh: connection reset by peer"),
		&gossh.OpenChannelError{Reason: gossh.ConnectionFailed, Message: "open failed"},
		&gossh.OpenChannelError{Reason: gossh.ResourceShortage, Message: "open failed"},
	} {
		if machinecontract.IsSessionLimit(err) {
			t.Errorf("IsSessionLimit(%v) = true", err)
		}
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPooledClientProbeGivesUpOnSilentServerAndRedials(t *testing.T) {
	conn, vault, srv := setupLimitTest(t, 2)
	if _, err := getPooledClient(conn, vault); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSM_TIMEOUT", "300ms")
	srv.silentRequests.Store(true)

	done := make(chan error, 1)
	go func() {
		_, err := getPooledClient(conn, vault)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("getPooledClient with a silent server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("liveness probe blocked on a server that never answers global requests")
	}
	if got := srv.connections.Load(); got != 2 {
		t.Fatalf("SSH connections = %d, want the silent one evicted and a fresh dial", got)
	}
}

func TestSessionAcquisitionUsesOneBudgetForDialAndSlotWait(t *testing.T) {
	// A server whose limit is always full and whose handshake takes 1s: the
	// dial time must come out of the 2s budget, not add to it.
	conn, vault, srv := setupLimitTest(t, 0)
	t.Setenv("SSM_TIMEOUT", "2s")
	srv.handshakeDelay.Store(int64(time.Second))

	start := time.Now()
	res := limitTestRun(conn, vault, "slow")
	elapsed := time.Since(start)
	if res.Error != "session_limit" {
		t.Fatalf("result error=%q, want session_limit", res.Error)
	}
	// Separate budgets would take about 1s + 2s = 3s.
	if elapsed < 1800*time.Millisecond || elapsed >= 2700*time.Millisecond {
		t.Fatalf("acquisition took %s, want about one 2s budget", elapsed)
	}
	if got := srv.connections.Load(); got != 1 {
		t.Fatalf("SSH connections = %d, want exactly 1", got)
	}
}
