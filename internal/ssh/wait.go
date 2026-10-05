package ssh

import (
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// MaxRetryDial is the largest accepted --retry-dial count.
const MaxRetryDial = 10

// MaxBackoff caps the exponential base delay of RetryDelay (before jitter).
const MaxBackoff = 30 * time.Second

// RetryDelay returns the pause before retry number attempt (1-based): base
// doubled per attempt up to MaxBackoff, plus up to 25% random jitter so
// parallel callers do not hit a host in lockstep. It never returns less than
// base, so a caller's minimum interval is a real floor. A base above
// MaxBackoff is used as-is (no growth): the caller asked for that pause.
func RetryDelay(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 250 * time.Millisecond
	}
	delay := base
	for i := 1; i < attempt && delay < MaxBackoff; i++ {
		delay *= 2
	}
	if delay > MaxBackoff && base <= MaxBackoff {
		delay = MaxBackoff
	}
	if jitter := int64(delay / 4); jitter > 0 {
		delay += time.Duration(rand.Int64N(jitter + 1)) //nolint:gosec // retry jitter, not a security value
	}
	return delay
}

// RetryableTransportFailure reports whether a classified failure means "the
// host is not reachable yet" and no credential can have been sent: dial_*
// failures, and handshake failures (EOF, reset, timeout) that happened before
// the server's host key arrived. Anything past key exchange (for example a
// drop or timeout during authentication, as MaxAuthTries or fail2ban rejects
// look), authentication, host-key, credential and session failures, and a
// deterministic algorithm mismatch never qualify.
func RetryableTransportFailure(failure machinecontract.Failure) bool {
	if failure.PastKeyExchange {
		return false
	}
	if strings.HasPrefix(failure.Error, "dial_") {
		return true
	}
	return failure.Error == machinecontract.CodeHandshakeFailed &&
		!strings.Contains(strings.ToLower(failure.Message), "no common algorithm")
}

func waitAddress(c config.Connection) (string, machinecontract.SSHContext) {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(port)), machinecontract.SSHContext{
		Alias: c.Name, Host: c.Host, Port: c.Port, Stage: "dial",
	}
}

// WaitPreflight reports, without touching the network, a failure that no
// amount of waiting can fix (no usable credentials).
func WaitPreflight(c config.Connection, v *config.Vault) (machinecontract.Failure, bool) {
	if _, err := buildAuth(c, v); err != nil {
		_, context := waitAddress(c)
		return machinecontract.ClassifySSH(ClassifyError(err, c), context), true
	}
	return machinecontract.Failure{}, false
}

// WaitTCP reports whether a TCP connection to the host opens within timeout.
func WaitTCP(c config.Connection, timeout time.Duration) (machinecontract.Failure, bool) {
	address, context := waitAddress(c)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return machinecontract.ClassifySSH(err, context), false
	}
	_ = conn.Close()
	return machinecontract.Failure{}, true
}

// WaitAuthProbe performs ONE real SSH connection per call (version exchange,
// host-key verification, authentication, session channel) bounded by timeout.
// There is deliberately no separate banner probe: a connection that closes
// before identifying itself is logged by sshd as a pre-auth failure that
// fail2ban's aggressive modes count. Host-key failures surface before any
// authentication is attempted.
func WaitAuthProbe(c config.Connection, v *config.Vault, timeout time.Duration) (machinecontract.Failure, bool) {
	if strings.TrimSpace(c.ProxyJump) != "" {
		return waitChainProbe(c, v, timeout)
	}
	address, context := waitAddress(c)
	auth, err := buildAuth(c, v)
	if err != nil {
		return machinecontract.ClassifySSH(ClassifyError(err, c), context), false
	}
	knownHostsPath, err := KnownHostsPath()
	if err != nil {
		failure, _ := machinecontract.FailureFromError(knownHostsPathError())
		return failure, false
	}
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return machinecontract.ClassifySSH(err, context), false
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var reachedKeyExchange atomic.Bool
	hostKeyCallback := trackedHostKeyCallback(&reachedKeyExchange, nil)
	sshConn, channels, requests, err := gossh.NewClientConn(conn, address, &gossh.ClientConfig{
		User:              c.User,
		Auth:              auth,
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithmsFor(knownHostsPath, address),
		Timeout:           timeout,
	})
	if err != nil {
		_ = conn.Close()
		failure := machinecontract.ClassifySSH(err, context)
		failure.PastKeyExchange = reachedKeyExchange.Load()
		return failure, false
	}
	client := gossh.NewClient(sshConn, channels, requests)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	if err != nil {
		sessionContext := context
		sessionContext.Stage = "session"
		sessionContext.SessionAcquisition = true
		failure := machinecontract.ClassifySSH(err, sessionContext)
		// Authentication already succeeded: never retry (another login).
		failure.PastKeyExchange = true
		return failure, false
	}
	_ = session.Close()
	return machinecontract.Failure{}, true
}

// waitChainProbe is WaitAuthProbe for a connection with proxy_jump: the probe
// goes through the whole chain (each hop verifies its own host key and
// authenticates once). A failure after the failing hop's own host key arrived
// is never retryable; a transport failure before it (for example the target
// behind the jump is down) is, since earlier hops only logged in successfully.
// The chain dial is bounded by timeout as a whole and, on expiry, is really
// torn down (connections closed, host keys refused) before this returns, so
// an abandoned dial can never send credentials while the next attempt dials.
func waitChainProbe(c config.Connection, v *config.Vault, timeout time.Duration) (machinecontract.Failure, bool) {
	_, context := waitAddress(c)
	chain, err := config.ResolveJumpChain(v, c)
	if err != nil {
		failure, _ := machinecontract.FailureFromError(invalidJumpChainError(c, err))
		return failure, false
	}
	type outcome struct {
		client *gossh.Client
		err    error
	}
	abort := &dialAbort{}
	done := make(chan outcome, 1)
	go func() {
		client, err := dialChainTracked(chain, v, abort)
		done <- outcome{client, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var result outcome
	select {
	case result = <-done:
	case <-timer.C:
		// Abort first, then read: a host-key callback that was not refused
		// stored its flag before abort() (see trackedHostKeyCallback).
		abort.abort()
		pastKey := abort.currentReached()
		select {
		case r := <-done:
			if r.client != nil {
				_ = r.client.Close()
			}
		case <-time.After(abortGrace):
			// Still inside a TCP connect: it will close itself on completion
			// and can no longer send credentials.
			go func() {
				if r := <-done; r.client != nil {
					_ = r.client.Close()
				}
			}()
		}
		failure := machinecontract.ClassifySSH(tunnelTimeout("ssh: handshake failed: i/o timeout through jump chain"), context)
		failure.PastKeyExchange = pastKey
		return failure, false
	}
	if result.err != nil {
		failure, ok := machinecontract.FailureFromError(result.err)
		if !ok {
			failure = machinecontract.ClassifySSH(result.err, context)
			failure.PastKeyExchange = abort.currentReached()
		}
		// classifyHop already set PastKeyExchange from the failing hop's flag.
		return failure, false
	}
	defer func() { _ = result.client.Close() }()
	session, err := result.client.NewSession()
	if err != nil {
		sessionContext := context
		sessionContext.Stage = "session"
		sessionContext.SessionAcquisition = true
		failure := machinecontract.ClassifySSH(err, sessionContext)
		failure.PastKeyExchange = true
		return failure, false
	}
	_ = session.Close()
	return machinecontract.Failure{}, true
}
