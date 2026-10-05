package ssh

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

const (
	sessionSlotBackoffMin = 25 * time.Millisecond
	sessionSlotBackoffMax = 250 * time.Millisecond
)

// sessionSlotBackoff is the jittered, bounded delay before the attempt-th
// retry (0-based) of a full session limit.
func sessionSlotBackoff(attempt int) time.Duration {
	delay := sessionSlotBackoffMax
	if attempt < 4 {
		delay = sessionSlotBackoffMin << attempt
	}
	half := delay / 2
	return half + rand.N(half+1) //nolint:gosec // retry jitter, not security-sensitive
}

// waitSessionSlot sleeps the jittered backoff for the attempt-th retry,
// bounded by the budget's deadline and interruptible through ctx. It reports
// false when the budget is spent (the caller gives up with the refusal) and
// ctx.Err() when cancelled.
func waitSessionSlot(ctx context.Context, attempt int, deadline time.Time) (bool, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false, nil
	}
	timer := time.NewTimer(min(sessionSlotBackoff(attempt), remaining))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return true, nil
	}
}

// newSessionRetry opens a session on a client the caller already holds (file
// transfers and other non-run paths). A full session limit is waited out with
// jittered backoff for up to DialTimeout() without closing the shared
// connection; every other error returns immediately. No pool lock is held.
// There is no production cancel source before a session exists (a local
// SIGINT/SIGTERM before that point terminates the process by default), so
// callers pass context.Background(); the context exists for tests and future
// callers.
func newSessionRetry(client *gossh.Client) (*gossh.Session, error) {
	return newSessionRetryContext(context.Background(), client, time.Now().Add(DialTimeout()))
}

func newSessionRetryContext(ctx context.Context, client *gossh.Client, deadline time.Time) (*gossh.Session, error) {
	for attempt := 0; ; attempt++ {
		session, err := client.NewSession()
		if err == nil || !machinecontract.IsSessionLimit(err) {
			return session, err
		}
		again, waitErr := waitSessionSlot(ctx, attempt, deadline)
		if waitErr != nil {
			return nil, waitErr
		}
		if !again {
			return nil, err
		}
	}
}

// Session reuse: keep *ssh.Client open and open a new channel per command.
// Disable with SSM_REUSE=0/off/false or RunOptions.NoReuse.

var (
	poolLifecycle sync.RWMutex
	poolMu        sync.Mutex
	pool          = map[string]*pooledClient{}
)

type pooledClient struct {
	mu       sync.Mutex
	client   *gossh.Client
	lastUsed time.Time
	key      string
}

func reuseEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SSM_REUSE")))
	switch v {
	case "0", "off", "false", "no", "disable", "disabled":
		return false
	default:
		return true
	}
}

// ReuseEnabled reports the process-local connection-pool setting used by the
// CLI status contract. It accepts the same false spellings as the pool.
func ReuseEnabled() bool { return reuseEnabled() }

func poolKey(c config.Connection) string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%s@%s:%d|key=%s|password=%t", c.User, c.Host, port, c.KeyName, c.Password != "")
}

// lockPoolEntry acquires the process pool and selected entry as one ordered
// operation. The lifecycle read lock prevents an acquisition from retaining a
// detached entry across whole-pool revocation without serializing unrelated
// destinations against each other.
func lockPoolEntry(key string) *pooledClient {
	poolLifecycle.RLock()
	poolMu.Lock()
	entry, ok := pool[key]
	if !ok {
		entry = &pooledClient{key: key}
		pool[key] = entry
	}
	poolMu.Unlock()
	entry.mu.Lock()
	poolLifecycle.RUnlock()
	return entry
}

// dialSSH obtains an SSH client, optionally from the reuse pool.
func dialSSH(c config.Connection, v *config.Vault) (*gossh.Client, error) {
	return dialSSHOpts(c, v, false)
}

func dialSSHOpts(c config.Connection, v *config.Vault, noReuse bool) (*gossh.Client, error) {
	if !noReuse && reuseEnabled() {
		return getPooledClient(c, v)
	}
	return dialSSHFresh(c, v)
}

func dialSSHFresh(c config.Connection, v *config.Vault) (*gossh.Client, error) {
	if strings.TrimSpace(c.ProxyJump) != "" {
		chain, err := config.ResolveJumpChain(v, c)
		if err != nil {
			return nil, invalidJumpChainError(c, err)
		}
		return dialChain(chain, v)
	}
	var reached atomic.Bool
	client, err := dialDirectHop(c, v, &reached, nil)
	if err != nil {
		return nil, classifyHop(err, c, c, false, &reached, false)
	}
	startKeepalive(client)
	return client, nil
}

// dialDirectHop dials c over TCP: host-key verification, authentication and
// the handshake deadline apply. Errors are returned unclassified.
// reached is set once the hop's host key arrived (credentials may then have
// been sent), so callers can refuse to retry the failure.
func dialDirectHop(c config.Connection, v *config.Vault, reached *atomic.Bool, abort *dialAbort) (*gossh.Client, error) {
	auth, err := buildAuth(c, v)
	if err != nil {
		return nil, err
	}
	address := hostPortOf(c)
	knownHostsPath, err := KnownHostsPath()
	if err != nil {
		return nil, knownHostsPathError()
	}
	return dialSSHClient(address, &gossh.ClientConfig{
		User:              c.User,
		Auth:              auth,
		HostKeyCallback:   trackedHostKeyCallback(reached, abort),
		HostKeyAlgorithms: hostKeyAlgorithmsFor(knownHostsPath, address),
	}, abort)
}

// dialConnectDeadline opens the TCP connection and arms one deadline covering
// TCP connect plus the SSH handshake. gossh.ClientConfig.Timeout only limits
// the TCP connect, so a server that accepts the connection and never speaks
// SSH would otherwise hang the caller forever. The caller clears the deadline
// with conn.SetDeadline(time.Time{}) once the handshake succeeded.
func dialConnectDeadline(address string) (net.Conn, error) {
	deadline := time.Now().Add(DialTimeout())
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialSSHClient connects and completes the SSH handshake under the connect
// deadline, then removes the deadline so the established session is bounded
// only by exec timeouts and keepalive.
func dialSSHClient(address string, config *gossh.ClientConfig, abort *dialAbort) (*gossh.Client, error) {
	conn, err := dialConnectDeadline(address)
	if err != nil {
		return nil, err
	}
	if !abort.register(conn) {
		return nil, errDialAbandoned
	}
	sshConn, channels, requests, err := gossh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = sshConn.Close()
		return nil, err
	}
	return gossh.NewClient(sshConn, channels, requests), nil
}

func getPooledClient(c config.Connection, v *config.Vault) (*gossh.Client, error) {
	key := poolKeyChain(c, v)
	entry := lockPoolEntry(key)
	defer entry.mu.Unlock()

	if entry.client != nil {
		// A global request answers whether the transport is alive without
		// taking a session slot, so a full MaxSessions cannot look like a
		// dead connection. Any reply, even a refusal, proves liveness.
		if clientAlive(entry.client, livenessBound()) {
			entry.lastUsed = time.Now()
			return entry.client, nil
		}
		_ = entry.client.Close()
		entry.client = nil
	}

	client, err := dialSSHFresh(c, v)
	if err != nil {
		return nil, err
	}
	entry.client = client
	entry.lastUsed = time.Now()
	return client, nil
}

// livenessBound is how long the pooled-connection liveness probe may wait for
// a reply. It runs under the per-host entry lock, so it must be short.
func livenessBound() time.Duration { return min(DialTimeout(), 5*time.Second) }

// clientAlive sends one keepalive global request now and reports whether any
// reply arrived within bound. It complements the background keepalive
// (startKeepalive), which only notices a dead peer after several intervals;
// this check is what stops a reused connection from serving a caller that is
// about to use it. A silent or half-open server is reported dead; the
// caller then closes the client, which also unblocks the probe goroutine.
func clientAlive(client *gossh.Client, bound time.Duration) bool {
	replied := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest(keepaliveRequest, true, nil)
		replied <- err
	}()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case err := <-replied:
		return err == nil
	case <-timer.C:
		return false
	}
}

// acquireSSHSession opens the session that the caller will actually use. It
// avoids the old "probe channel, close it, open another channel" round trip on
// every pooled command. A stale pooled connection is evicted and redialed once.
// The per-destination lock serializes only one host's dial and one session
// open attempt; it is never held while waiting for a free session slot.
// On error the returned client and session are always nil.
func acquireSSHSession(c config.Connection, v *config.Vault, noReuse bool) (*gossh.Client, *gossh.Session, string, error) {
	return acquireSSHSessionContext(context.Background(), c, v, noReuse)
}

// acquireSSHSessionContext is acquireSSHSession with a cancellation path for
// the slot wait. Production passes context.Background() because nothing can
// cancel an acquisition before the session exists (a local signal then kills
// the process by default).
//
// When the host's session limit is full the pooled connection stays open (its
// running sessions must not be killed) and the acquisition backs off, without
// the entry lock, until a slot frees or DialTimeout() elapses. The
// wait-and-retry strategy is used rather than a client-side per-connection cap
// or a second connection because sshd's MaxSessions is unknown and per-host;
// polling adapts to whatever the server allows.
func acquireSSHSessionContext(ctx context.Context, c config.Connection, v *config.Vault, noReuse bool) (*gossh.Client, *gossh.Session, string, error) {
	if noReuse || !reuseEnabled() {
		client, err := dialSSHFresh(c, v)
		if err != nil {
			return nil, nil, "dial", err
		}
		session, err := client.NewSession()
		if err != nil {
			_ = client.Close()
			return nil, nil, "session", err
		}
		return client, session, "", nil
	}

	// One budget covers dialing and the slot wait, so the worst case is about
	// DialTimeout() in total rather than one timeout for each.
	deadline := time.Now().Add(DialTimeout())
	for attempt := 0; ; attempt++ {
		client, session, stage, err := tryPooledSession(c, v)
		if err == nil || !machinecontract.IsSessionLimit(err) {
			return client, session, stage, err
		}
		again, waitErr := waitSessionSlot(ctx, attempt, deadline)
		if waitErr != nil {
			return nil, nil, "session", waitErr
		}
		if !again {
			return nil, nil, "session", err
		}
	}
}

// tryPooledSession makes one attempt to open a session on the host's pooled
// connection under the entry lock. A session-limit refusal leaves the healthy
// connection in the pool and is returned as-is for the caller to back off.
func tryPooledSession(c config.Connection, v *config.Vault) (*gossh.Client, *gossh.Session, string, error) {
	entry := lockPoolEntry(poolKeyChain(c, v))
	defer entry.mu.Unlock()

	if entry.client != nil {
		session, err := entry.client.NewSession()
		if err == nil {
			entry.lastUsed = time.Now()
			return entry.client, session, "", nil
		}
		if machinecontract.IsSessionLimit(err) {
			return nil, nil, "session", err
		}
		_ = entry.client.Close()
		entry.client = nil
	}

	client, err := dialSSHFresh(c, v)
	if err != nil {
		return nil, nil, "dial", err
	}
	entry.client = client
	entry.lastUsed = time.Now()
	session, err := client.NewSession()
	if err != nil {
		if !machinecontract.IsSessionLimit(err) {
			_ = client.Close()
			entry.client = nil
		}
		return nil, nil, "session", err
	}
	return client, session, "", nil
}

// releaseClient closes the client only when reuse is disabled.
func releaseClient(client *gossh.Client, noReuse bool) {
	if client == nil {
		return
	}
	if !noReuse && reuseEnabled() {
		return
	}
	_ = client.Close()
}

// ClosePool closes every process-local SSH connection. Long-lived streaming
// callers use this when their inventory changes or the input stream ends.
func ClosePool() {
	poolLifecycle.Lock()
	defer poolLifecycle.Unlock()

	poolMu.Lock()
	entries := make([]*pooledClient, 0, len(pool))
	for _, entry := range pool {
		entries = append(entries, entry)
	}
	pool = map[string]*pooledClient{}
	poolMu.Unlock()

	for _, entry := range entries {
		entry.mu.Lock()
		if entry.client != nil {
			_ = entry.client.Close()
			entry.client = nil
		}
		entry.mu.Unlock()
	}
}
