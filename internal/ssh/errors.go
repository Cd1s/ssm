package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
)

// Agent-oriented failure classes. Printed as ssm: error=<code> so agents can
// triage without re-reading raw dial strings.
const (
	ErrCodeAliasNotFound = "alias_not_found"
	ErrCodeDialTimeout   = "dial_timeout"
	ErrCodeDialRefused   = "dial_refused"
	ErrCodeDialNetwork   = "dial_network"
	ErrCodeHostKey       = "host_key_mismatch"
	ErrCodeAuth          = "auth_failed"
	ErrCodeNoAuth        = "no_auth_configured"
	ErrCodeSession       = "session_failed"
	ErrCodeRemote        = "remote_failed"
	ErrCodeInternal      = "internal"
)

// Exit code used for connection-layer failures (distinct from remote exit status).
// Matches common OpenSSH client convention for ssh itself failing.
const ExitConnectionFailed = 255

// ClassifiedError is an SSH failure with a stable machine-readable code.
type ClassifiedError struct {
	Code    string
	Message string
	Hint    string
	Cause   error
	// Address is host:port when known.
	Address string
	Alias   string
}

func (e *ClassifiedError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return e.Code
}

func (e *ClassifiedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ClassifyError maps dial/auth/session errors into stable codes for agents.
func ClassifyError(err error, c config.Connection) *ClassifiedError {
	if err == nil {
		return nil
	}
	if ce, ok := err.(*ClassifiedError); ok {
		return ce
	}

	port := c.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", port))
	msg := err.Error()
	low := strings.ToLower(msg)

	out := &ClassifiedError{
		Code:    ErrCodeInternal,
		Message: msg,
		Cause:   err,
		Address: addr,
		Alias:   c.Name,
	}

	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) || strings.Contains(low, "host key") || strings.Contains(low, "knownhosts") {
		out.Code = ErrCodeHostKey
		out.Message = "remote host key does not match known_hosts (host reinstalled or MITM)"
		hostArg := c.Host
		if port != 22 {
			hostArg = fmt.Sprintf("[%s]:%d", c.Host, port)
		}
		out.Hint = fmt.Sprintf(
			"after user confirms host rebuild is expected: ssh-keygen -R %q && ssh-keyscan -p %d -t ed25519,rsa,ecdsa %s >> ~/.ssh/known_hosts",
			hostArg, port, c.Host,
		)
		return out
	}

	if strings.Contains(low, "no authentication configured") {
		out.Code = ErrCodeNoAuth
		out.Message = "connection has no password or private key configured"
		out.Hint = "update host auth with sshctl host update <alias> --key-file <path> or --password-file <path>"
		return out
	}

	if strings.Contains(low, "unable to authenticate") ||
		strings.Contains(low, "no supported methods remain") ||
		strings.Contains(low, "permission denied") ||
		strings.Contains(low, "authentication failed") {
		out.Code = ErrCodeAuth
		out.Message = "SSH authentication failed"
		out.Hint = "check password/key in vault; not a quote or SSM client bug"
		return out
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		out.Code = ErrCodeDialTimeout
		out.Message = fmt.Sprintf("dial tcp %s: i/o timeout", addr)
		out.Hint = "network/host unreachable or filtered; verify host online/firewall/IPv6. Not an ssm quote bug."
		return out
	}
	if strings.Contains(low, "i/o timeout") || strings.Contains(low, "timeout") {
		out.Code = ErrCodeDialTimeout
		out.Message = fmt.Sprintf("connection timed out to %s", addr)
		out.Hint = "network/host unreachable or filtered; verify host online/firewall/IPv6. Not an ssm quote bug."
		return out
	}
	if strings.Contains(low, "connection refused") {
		out.Code = ErrCodeDialRefused
		out.Message = fmt.Sprintf("connection refused by %s", addr)
		out.Hint = "sshd not listening or wrong port; not an ssm quote bug"
		return out
	}
	if strings.Contains(low, "no route to host") ||
		strings.Contains(low, "network is unreachable") ||
		strings.Contains(low, "connect: ") {
		out.Code = ErrCodeDialNetwork
		out.Message = fmt.Sprintf("network error dialing %s: %s", addr, msg)
		out.Hint = "routing/DNS/firewall issue; not an ssm quote bug"
		return out
	}

	if strings.Contains(low, "session") {
		out.Code = ErrCodeSession
		out.Hint = "SSH connected but session failed; remote sshd or resources may be unhealthy"
		return out
	}

	return out
}

// PrintAgentError writes structured stderr lines for agents plus a human Error line.
func PrintAgentError(err error, c config.Connection) {
	ce := ClassifyError(err, c)
	if ce == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "ssm: error=%s", ce.Code)
	if ce.Alias != "" {
		fmt.Fprintf(os.Stderr, " alias=%s", shellMetaSafe(ce.Alias))
	}
	if ce.Address != "" {
		fmt.Fprintf(os.Stderr, " address=%s", shellMetaSafe(ce.Address))
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Error: %s\n", ce.Error())
	if ce.Hint != "" {
		fmt.Fprintf(os.Stderr, "ssm: hint=%s\n", ce.Hint)
	}
}

func shellMetaSafe(s string) string {
	// Keep one-token fields agent-parseable; replace spaces.
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "_")
}

// DialTimeout returns the SSH dial timeout from SSM_TIMEOUT / SSM_DIAL_TIMEOUT
// or the default 15s. Values are Go durations ("10s", "1m") or integer seconds.
func DialTimeout() time.Duration {
	for _, key := range []string{"SSM_TIMEOUT", "SSM_DIAL_TIMEOUT"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			if d, err := parseTimeout(v); err == nil && d > 0 {
				return d
			}
		}
	}
	return dialTimeout
}

func parseTimeout(v string) (time.Duration, error) {
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	// bare integer = seconds
	var sec int
	if _, err := fmt.Sscanf(v, "%d", &sec); err == nil && sec > 0 {
		return time.Duration(sec) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid timeout %q", v)
}

// ExitCodeFor returns process exit code for a classified connection error.
func ExitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*gossh.ExitError); ok {
		return exitErr.ExitStatus()
	}
	ce := ClassifyError(err, config.Connection{})
	switch ce.Code {
	case ErrCodeInternal:
		// unclassified: still treat as connection-ish if message looks like dial
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "dial") || strings.Contains(low, "connect") {
			return ExitConnectionFailed
		}
		return 1
	default:
		return ExitConnectionFailed
	}
}
