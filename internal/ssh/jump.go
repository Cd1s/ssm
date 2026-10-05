package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// ProxyJump support (issue #86). A connection with proxy_jump is reached hop by
// hop: the first hop uses the ordinary direct dial, and every following hop is
// an SSH handshake over a direct-tcpip channel opened on the previous hop's
// client. Each hop verifies its own host key against the local known_hosts and
// authenticates with its own credentials, so no credential or agent ever
// reaches a jump host.

func hostPortOf(c config.Connection) string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(port))
}

// classifyHop turns the error of one dial hop into a classified error. For a
// plain connection (chained == false) it is the historical classification.
// For a chained connection the failure additionally names the hop that failed
// in Via, so an agent knows which alias to fix or trust.
//
// reached reports whether any hop's host key arrived before the failure; such a
// failure carries PastKeyExchange and is never retried. tunneled marks a hop
// reached through an earlier hop, whose errors are not local connect errnos.
func classifyHop(err error, target, hop config.Connection, chained bool, reached *atomic.Bool, tunneled bool) *machinecontract.ClassifiedError {
	if !chained {
		classified := ClassifyError(err, target)
		if reached != nil && reached.Load() {
			classified.PastKeyExchange = true
		}
		return classified
	}
	port := hop.Port
	if port == 0 {
		port = 22 // never render the unset port as :0
	}
	failure := machinecontract.ClassifySSH(err, machinecontract.SSHContext{
		Alias: target.Name, Host: hop.Host, Port: port, Tunneled: tunneled,
	})
	if reached != nil && reached.Load() {
		failure.PastKeyExchange = true
	}
	via := machinecontract.RedactString(hop.Name)
	failure.Via = via
	if failure.Message != "" {
		failure.Message = fmt.Sprintf("via %s: %s", via, failure.Message)
	}
	if strings.Contains(failure.Hint, "<alias>") {
		// Host-key remediation applies to the hop that presented the key.
		failure.Hint = strings.ReplaceAll(failure.Hint, "<alias>", via)
	}
	return machinecontract.NewClassifiedError(failure)
}

// invalidJumpChainError classifies an unresolvable proxy_jump chain.
func invalidJumpChainError(target config.Connection, err error) *machinecontract.ClassifiedError {
	failure := machinecontract.Classify(machinecontract.InvalidProxyJump, machinecontract.Details{
		Cause: err, Message: err.Error(), Alias: target.Name,
	})
	var chainErr *config.JumpChainError
	if errors.As(err, &chainErr) {
		failure.Via = machinecontract.RedactString(chainErr.Alias)
	}
	return machinecontract.NewClassifiedError(failure)
}

// dialHops connects hops in order, each over the previous one, and returns
// every client opened. On failure it closes what it opened and returns the
// classified error naming the failing hop.
func dialHops(hops []config.Connection, target config.Connection, v *config.Vault, abort *dialAbort) ([]*gossh.Client, error) {
	clients := make([]*gossh.Client, 0, len(hops))
	for index, hop := range hops {
		var client *gossh.Client
		var err error
		// One flag per hop: it says whether THIS hop's host key arrived, i.e.
		// whether credentials may have been sent to it.
		reached := new(atomic.Bool)
		abort.setCurrent(reached)
		if index == 0 {
			client, err = dialDirectHop(hop, v, reached, abort)
		} else {
			client, err = dialHopThrough(clients[index-1], hop, v, reached, abort)
		}
		if err != nil {
			closeClients(clients)
			return nil, classifyHop(err, target, hop, true, reached, index > 0)
		}
		clients = append(clients, client)
	}
	return clients, nil
}

// dialChain connects to chain[len-1] through chain[:len-1]. The returned client
// owns the jump clients: when it closes, for whatever reason, they are closed
// too, so neither goroutines nor connections outlive the target connection.
func dialChain(chain []config.Connection, v *config.Vault) (*gossh.Client, error) {
	return dialChainTracked(chain, v, nil)
}

// dialChainTracked is dialChain with an optional dialAbort that can cancel the
// dial from another goroutine and reports whether the hop in progress already
// received its host key.
func dialChainTracked(chain []config.Connection, v *config.Vault, abort *dialAbort) (*gossh.Client, error) {
	clients, err := dialHops(chain, chain[len(chain)-1], v, abort)
	if err != nil {
		return nil, err
	}
	for _, client := range clients {
		startKeepalive(client)
	}
	target, jumps := clients[len(clients)-1], clients[:len(clients)-1]
	go func() {
		_ = target.Wait()
		closeClients(jumps)
	}()
	return target, nil
}

// closeClients closes clients last-opened first.
func closeClients(clients []*gossh.Client) {
	for i := len(clients) - 1; i >= 0; i-- {
		_ = clients[i].Close()
	}
}

// dialJumpPrefix connects every jump host of the chain in front of the target
// and returns the last one together with a function that closes them all. The
// chain must have at least two entries.
func dialJumpPrefix(chain []config.Connection, v *config.Vault) (*gossh.Client, func(), error) {
	clients, err := dialHops(chain[:len(chain)-1], chain[len(chain)-1], v, nil)
	if err != nil {
		return nil, nil, err
	}
	return clients[len(clients)-1], func() { closeClients(clients) }, nil
}

// dialHopThrough opens a direct-tcpip channel to hop over previous and runs the
// SSH handshake for hop over it, with hop's own host-key verification and
// credentials. The handshake shares the connect deadline of the direct path.
func dialHopThrough(previous *gossh.Client, hop config.Connection, v *config.Vault, reached *atomic.Bool, abort *dialAbort) (*gossh.Client, error) {
	auth, err := buildAuth(hop, v)
	if err != nil {
		return nil, err
	}
	address := hostPortOf(hop)
	deadline := time.Now().Add(DialTimeout())
	knownHostsPath, err := KnownHostsPath()
	if err != nil {
		return nil, knownHostsPathError()
	}
	conn, err := dialTunnel(previous, address, deadline)
	if err != nil {
		return nil, err
	}
	if !abort.register(conn) {
		return nil, errDialAbandoned
	}
	sshConn, channels, requests, err := handshakeOverTunnel(conn, address, deadline, &gossh.ClientConfig{
		User:              hop.User,
		Auth:              auth,
		HostKeyCallback:   trackedHostKeyCallback(reached, abort),
		HostKeyAlgorithms: hostKeyAlgorithmsFor(knownHostsPath, address),
	})
	if err != nil {
		return nil, err
	}
	return gossh.NewClient(sshConn, channels, requests), nil
}

// handshakeOverTunnel runs NewClientConn over an SSH channel. Channels have no
// read deadlines, so the deadline is enforced by closing the channel when it
// expires; the expiry is reported as a typed timeout so it classifies as
// handshake_failed like the direct path does.
func handshakeOverTunnel(conn net.Conn, address string, deadline time.Time, cfg *gossh.ClientConfig) (gossh.Conn, <-chan gossh.NewChannel, <-chan *gossh.Request, error) {
	var expired atomic.Bool
	timer := time.AfterFunc(time.Until(deadline), func() {
		expired.Store(true)
		_ = conn.Close()
	})
	sshConn, channels, requests, err := gossh.NewClientConn(conn, address, cfg)
	if !timer.Stop() {
		expired.Store(true)
	}
	if err != nil {
		_ = conn.Close()
		if expired.Load() {
			return nil, nil, nil, tunnelTimeout(fmt.Sprintf("ssh: handshake failed: i/o timeout through tunnel to %s", address))
		}
		return nil, nil, nil, err
	}
	if expired.Load() {
		_ = sshConn.Close()
		return nil, nil, nil, tunnelTimeout(fmt.Sprintf("ssh: handshake failed: i/o timeout through tunnel to %s", address))
	}
	return sshConn, channels, requests, nil
}

// dialTunnel opens a direct-tcpip channel to address on previous, bounded by
// deadline. previous.Dial has no timeout of its own, and a jump host that
// cannot reach the target may take the operating system's connect timeout.
func dialTunnel(previous *gossh.Client, address string, deadline time.Time) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := previous.Dial("tcp", address)
		done <- result{conn, err}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r := <-done:
		if r.err != nil {
			// "connect: " keeps refused/unreachable targets in the dial
			// classes; a jump host that forbids forwarding is a network-class
			// failure of this hop, not a session problem.
			return nil, fmt.Errorf("connect: %w", r.err)
		}
		return r.conn, nil
	case <-timer.C:
		go func() {
			if r := <-done; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, tunnelTimeout(fmt.Sprintf("dial tcp %s: i/o timeout (through jump host)", address))
	}
}

type tunnelTimeoutError struct{ message string }

func tunnelTimeout(message string) error { return tunnelTimeoutError{message: message} }

func (e tunnelTimeoutError) Error() string   { return e.message }
func (e tunnelTimeoutError) Timeout() bool   { return true }
func (e tunnelTimeoutError) Temporary() bool { return true }

// poolKeyChain is the pool identity of a connection: the whole jump chain when
// the connection has one, so the same target reached through different jump
// paths never shares a client.
func poolKeyChain(c config.Connection, v *config.Vault) string {
	if strings.TrimSpace(c.ProxyJump) == "" {
		return poolKey(c)
	}
	chain, err := config.ResolveJumpChain(v, c)
	if err != nil {
		return poolKey(c) + "|jump=unresolved:" + c.ProxyJump
	}
	parts := make([]string, len(chain))
	for i, hop := range chain {
		parts[i] = poolKey(hop)
	}
	return strings.Join(parts, " >> ")
}

// abortGrace is how long a cancelled chain dial gets to finish tearing down
// before the caller moves on.
const abortGrace = 2 * time.Second

var errDialAbandoned = errors.New("connect: dial abandoned")

// dialAbort lets another goroutine cancel a chain dial: it closes every
// connection the dial opened and makes host-key verification refuse, so no
// credential is sent after abandonment. All methods accept a nil receiver.
type dialAbort struct {
	mu      sync.Mutex
	done    bool
	conns   []io.Closer
	current *atomic.Bool
}

// register records a connection to close on abort; it reports false (and
// closes conn) when the dial was already abandoned.
func (a *dialAbort) register(conn io.Closer) bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done {
		_ = conn.Close()
		return false
	}
	a.conns = append(a.conns, conn)
	return true
}

func (a *dialAbort) abort() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.done = true
	conns := a.conns
	a.conns = nil
	a.mu.Unlock()
	for i := len(conns) - 1; i >= 0; i-- {
		_ = conns[i].Close()
	}
}

func (a *dialAbort) aborted() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.done
}

func (a *dialAbort) setCurrent(reached *atomic.Bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.current = reached
	a.mu.Unlock()
}

// currentReached reports whether the hop in progress already received its
// host key.
func (a *dialAbort) currentReached() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current != nil && a.current.Load()
}
