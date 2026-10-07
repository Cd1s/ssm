package ssh

// SSH local and dynamic forwarding. The forwarding transport deliberately
// goes through dialSSHOpts so host-key, authentication, keepalive, and jump
// host policy remain identical to every other sshctl operation.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

var tunnelMaxConnections = 256
var socksHandshakeTimeout = 10 * time.Second

// TunnelSpec describes one local or dynamic listener.
type TunnelSpec struct {
	Kind       string // local or dynamic
	Bind       string
	Port       int
	Host       string
	TargetPort int
}

// TunnelListener is the stable ready-file/ready-event representation.
type TunnelListener struct {
	Kind   string `json:"kind"`
	Bind   string `json:"bind"`
	Target string `json:"target,omitempty"`
}

// TunnelResult describes the listeners and why a tunnel stopped.
type TunnelResult struct {
	Listeners []TunnelListener
	Reason    string
}

// TunnelOptions controls lifecycle and output hooks. OnReady is called after
// every listener has successfully bound and before RunTunnel blocks.
type TunnelOptions struct {
	ConnectTimeout  time.Duration
	Duration        time.Duration
	ReadyFile       string
	AllowRemoteBind bool
	Yes             bool
	OnReady         func(TunnelResult) error
}

func parsePort(value string) (int, error) {
	p, err := strconv.Atoi(value)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return p, nil
}

func parseBindPort(value string) (string, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, errors.New("empty bind address")
	}
	if strings.HasPrefix(value, "[") {
		i := strings.Index(value, "]:")
		if i < 0 || strings.Contains(value[i+2:], ":") {
			return "", 0, fmt.Errorf("invalid bind %q", value)
		}
		port, err := parsePort(value[i+2:])
		return value[1:i], port, err
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" {
		return "", 0, fmt.Errorf("invalid bind %q", value)
	}
	port, err := parsePort(parts[1])
	return parts[0], port, err
}

func splitForwardParts(value string) []string {
	parts := make([]string, 0, 4)
	start := 0
	depth := 0
	for i, r := range value {
		switch r {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				parts = append(parts, value[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, value[start:])
}

// ParseLocalForward parses [bind:]port:host:hostport. IPv6 addresses must be
// bracketed, matching ssh's -L syntax; the target host is never resolved here.
func ParseLocalForward(value string) (TunnelSpec, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return TunnelSpec{}, errors.New("local forward is empty")
	}
	parts := splitForwardParts(value)
	var bind, portValue, host, targetPortValue string
	switch len(parts) {
	case 3:
		bind, portValue, host, targetPortValue = "127.0.0.1", parts[0], parts[1], parts[2]
	case 4:
		bind, portValue, host, targetPortValue = parts[0], parts[1], parts[2], parts[3]
	default:
		return TunnelSpec{}, fmt.Errorf("invalid local forward %q", value)
	}
	if strings.HasPrefix(bind, "[") && strings.HasSuffix(bind, "]") {
		bind = bind[1 : len(bind)-1]
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	port, err := parsePort(portValue)
	if err != nil {
		return TunnelSpec{}, err
	}
	if host == "" {
		return TunnelSpec{}, errors.New("local forward target host is empty")
	}
	targetPort, err := parsePort(targetPortValue)
	if err != nil {
		return TunnelSpec{}, err
	}
	if bind == "" {
		return TunnelSpec{}, errors.New("local forward bind is empty")
	}
	return TunnelSpec{Kind: "local", Bind: bind, Port: port, Host: host, TargetPort: targetPort}, nil
}

// ParseDynamicForward parses [bind:]port for a SOCKS5 listener.
func ParseDynamicForward(value string) (TunnelSpec, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return TunnelSpec{}, errors.New("dynamic forward is empty")
	}
	bind, port, err := func() (string, int, error) {
		if strings.HasPrefix(value, "[") {
			i := strings.Index(value, "]:")
			if i < 0 {
				return "", 0, fmt.Errorf("invalid dynamic forward %q", value)
			}
			p, e := parsePort(value[i+2:])
			return value[1:i], p, e
		}
		if !strings.Contains(value, ":") {
			p, e := parsePort(value)
			return "127.0.0.1", p, e
		}
		return parseBindPort(value)
	}()
	if err != nil {
		return TunnelSpec{}, err
	}
	return TunnelSpec{Kind: "dynamic", Bind: bind, Port: port}, nil
}

func tunnelBindAllowed(bind string, opts TunnelOptions) bool {
	if strings.EqualFold(bind, "localhost") {
		return true
	}
	ip := net.ParseIP(bind)
	return ip != nil && ip.IsLoopback() || opts.AllowRemoteBind && opts.Yes
}

func tunnelFailure(kind machinecontract.Kind, message string, cause error) error {
	return machinecontract.NewClassifiedError(machinecontract.Classify(kind, machinecontract.Details{Message: message, Cause: cause}))
}

// ValidateTunnelSpecs checks every listener before credentials are read or a
// network socket is opened.
func ValidateTunnelSpecs(specs []TunnelSpec, opts TunnelOptions) error {
	if len(specs) == 0 {
		return tunnelFailure(machinecontract.TunnelInvalidArguments, "tunnel requires at least one -L or -D", nil)
	}
	for _, spec := range specs {
		if spec.Kind != "local" && spec.Kind != "dynamic" {
			return tunnelFailure(machinecontract.TunnelInvalidArguments, "unknown tunnel listener kind", nil)
		}
		if spec.Port < 0 || spec.Port > 65535 || spec.Bind == "" || (spec.Kind == "local" && (spec.Host == "" || spec.TargetPort < 1 || spec.TargetPort > 65535)) {
			return tunnelFailure(machinecontract.TunnelInvalidArguments, "invalid tunnel listener specification", nil)
		}
		if !tunnelBindAllowed(spec.Bind, opts) {
			return tunnelFailure(machinecontract.TunnelRemoteBindRefused, "non-loopback bind requires --allow-remote-bind --yes", nil)
		}
	}
	return nil
}

// RunTunnel runs all listeners until ctx is cancelled, Duration expires, or
// the SSH transport disappears. It returns only after listeners and handlers
// have stopped, so callers can immediately reuse the ports.
func RunTunnel(ctx context.Context, c config.Connection, v *config.Vault, specs []TunnelSpec, opts TunnelOptions) (TunnelResult, error) {
	if err := ValidateTunnelSpecs(specs, opts); err != nil {
		return TunnelResult{}, err
	}
	listeners := make([]net.Listener, 0, len(specs))
	result := TunnelResult{Listeners: make([]TunnelListener, 0, len(specs))}
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}
	client, err := dialSSHOpts(c, v, true)
	if err != nil {
		return TunnelResult{}, ClassifyError(err, c)
	}
	defer func() { _ = client.Close() }()
	for _, spec := range specs {
		address := net.JoinHostPort(spec.Bind, strconv.Itoa(spec.Port))
		l, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			closeAll()
			_ = client.Close()
			return TunnelResult{}, tunnelFailure(machinecontract.TunnelBindFailed, "failed to listen on "+address, listenErr)
		}
		listeners = append(listeners, l)
		bound := l.Addr().String()
		target := ""
		if spec.Kind == "local" {
			target = net.JoinHostPort(spec.Host, strconv.Itoa(spec.TargetPort))
		}
		result.Listeners = append(result.Listeners, TunnelListener{Kind: spec.Kind, Bind: bound, Target: target})
	}
	if opts.ReadyFile != "" {
		data, _ := json.Marshal(struct {
			Listeners []TunnelListener `json:"listeners"`
		}{result.Listeners})
		payload := append([]byte(nil), data...)
		if err := os.WriteFile(opts.ReadyFile, payload, 0600); err != nil {
			closeAll()
			return TunnelResult{}, tunnelFailure(machinecontract.TunnelBindFailed, "failed to write ready file", err)
		}
		_ = os.Chmod(opts.ReadyFile, 0600)
		defer func() { _ = os.Remove(opts.ReadyFile) }()
	}
	if opts.OnReady != nil {
		if err := opts.OnReady(result); err != nil {
			closeAll()
			return TunnelResult{}, err
		}
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var handlers sync.WaitGroup
	var accepts sync.WaitGroup
	for i, l := range listeners {
		if i >= len(specs) {
			break
		}
		spec := specs[i] //nolint:gosec // listeners are created from the same validated specs slice
		accepts.Add(1)
		go func() {
			defer accepts.Done()
			sem := make(chan struct{}, tunnelMaxConnections)
			for {
				conn, acceptErr := l.Accept()
				if acceptErr != nil {
					return
				}
				select {
				case sem <- struct{}{}:
				case <-workCtx.Done():
					_ = conn.Close()
					return
				default:
					_ = conn.Close()
					continue
				}
				handlers.Add(1)
				go func(conn net.Conn) {
					defer handlers.Done()
					defer func() { <-sem }()
					if spec.Kind == "dynamic" {
						handleSOCKS(workCtx, conn, client)
					} else {
						handleLocal(workCtx, conn, client, net.JoinHostPort(spec.Host, strconv.Itoa(spec.TargetPort)))
					}
				}(conn)
			}
		}()
	}

	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Wait() }()
	var timer *time.Timer
	var duration <-chan time.Time
	if opts.Duration > 0 {
		timer = time.NewTimer(opts.Duration)
		defer timer.Stop()
		duration = timer.C
	}
	select {
	case <-ctx.Done():
		result.Reason = "signal"
	case <-duration:
		result.Reason = "duration"
	case err := <-clientDone:
		cancel()
		closeAll()
		accepts.Wait()
		handlers.Wait()
		if err == nil {
			err = io.EOF
		}
		return result, tunnelFailure(machinecontract.ConnectionLost, "SSH connection lost while tunnel was running", err)
	}
	cancel()
	closeAll()
	_ = client.Close()
	<-clientDone
	accepts.Wait()
	handlers.Wait()
	return result, nil
}

func handleLocal(ctx context.Context, local net.Conn, client *gossh.Client, target string) {
	defer func() { _ = local.Close() }()
	remote, err := client.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = remote.Close() }()
	copyBoth(ctx, local, remote)
}

// closeWriter signals "no more data from me" on one direction of a connection
// while leaving the other direction readable. net.TCPConn and the channel
// returned by ssh.Client.Dial both support it; anything else falls back to a
// full close, which is the old behaviour.
type closeWriter interface{ CloseWrite() error }

// copyBoth relays data in both directions until both have finished. A peer
// that half-closes (sends everything, then shuts its write side, and keeps
// reading) must still receive the complete reply, so the end of one direction
// only half-closes the other side. Cancelling ctx tears both down at once.
func copyBoth(ctx context.Context, a, b net.Conn) {
	var wg sync.WaitGroup
	relay := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
			return
		}
		_ = dst.Close()
		_ = src.Close()
	}
	wg.Add(2)
	go relay(a, b)
	go relay(b, a)

	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
	}
	_ = a.Close()
	_ = b.Close()
	<-finished
}

func socksReply(conn net.Conn, code byte) {
	_, _ = conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func handleSOCKS(ctx context.Context, conn net.Conn, client *gossh.Client) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
	header := []byte{0, 0}
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 5 {
		socksReply(conn, 1)
		return
	}
	if header[1] == 0 {
		_, _ = conn.Write([]byte{5, 0xff})
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	found := false
	for _, method := range methods {
		if method == 0 {
			found = true
		}
	}
	if !found {
		_, _ = conn.Write([]byte{5, 0xff})
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 5 {
		if err == nil {
			socksReply(conn, 1)
		}
		return
	}
	if req[1] != 1 {
		socksReply(conn, 7)
		return
	}
	var host string
	switch req[3] {
	case 1:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil || n[0] == 0 {
			return
		}
		name := make([]byte, int(n[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		host = string(name)
	case 4:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		socksReply(conn, 8)
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	if port == 0 {
		socksReply(conn, 8)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	remote, err := client.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		socksReply(conn, 5)
		return
	}
	defer func() { _ = remote.Close() }()
	socksReply(conn, 0)
	copyBoth(ctx, conn, remote)
}
