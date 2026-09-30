package machinecontract

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
)

// opaqueErrnoError wraps an errno behind text no message fallback matches, so
// only the typed errno (via Unwrap) can classify it.
type opaqueErrnoError struct{ errno syscall.Errno }

func (opaqueErrnoError) Error() string   { return "opaque transport failure" }
func (e opaqueErrnoError) Unwrap() error { return e.errno }

func TestClassifySSHRecognizesTypedDialErrnos(t *testing.T) {
	t.Parallel()
	tests := []struct {
		errno syscall.Errno
		want  string
	}{
		{syscall.ECONNREFUSED, CodeDialRefused},
		{syscall.ETIMEDOUT, CodeDialTimeout},
		{syscall.EHOSTUNREACH, CodeDialNetwork},
		{syscall.ENETUNREACH, CodeDialNetwork},
	}
	for _, test := range tests {
		// The text contains none of "refused", "timeout", "route", "connect:",
		// so this passes only through the typed errno path.
		err := &net.OpError{Op: "dial", Net: "tcp", Err: opaqueErrnoError{test.errno}}
		got := ClassifySSH(err, SSHContext{Alias: "prod", Host: "127.0.0.1", Port: 22, Stage: "dial"})
		if got.Error != test.want || got.Stage != "dial" || got.Exit != ExitConnectionFailed {
			t.Fatalf("ClassifySSH(%v) = %+v, want %s", test.errno, got, test.want)
		}
	}
}

func TestClassifySSHTypedDialErrnosStayInsideTheDialStage(t *testing.T) {
	t.Parallel()
	// ETIMEDOUT is excluded on purpose: syscall.Errno reports it as a
	// net.Error timeout, which the pre-existing generic timeout case maps to
	// dial_timeout at any stage (unchanged by the typed dial mapping).
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH} {
		for _, context := range []SSHContext{
			{Alias: "prod", Host: "127.0.0.1", Port: 22, Stage: "session", ExecPhase: true},
			{Alias: "prod", Host: "127.0.0.1", Port: 22, Stage: "session", SessionAcquisition: true},
		} {
			got := ClassifySSH(opaqueErrnoError{errno}, context)
			if strings.HasPrefix(got.Error, "dial_") {
				t.Fatalf("errno %v at %+v classified as %+v", errno, context, got)
			}
		}
	}
}

func TestClassifySSHHandshakeFailuresKeepTheirCode(t *testing.T) {
	t.Parallel()
	context := SSHContext{Alias: "prod", Host: "127.0.0.1", Port: 22, Stage: "dial"}
	for name, err := range map[string]error{
		"reset during handshake":      fmt.Errorf("ssh: handshake failed: %w", &net.OpError{Op: "read", Net: "tcp", Err: opaqueErrnoError{syscall.ECONNRESET}}),
		"timeout during handshake":    fmt.Errorf("ssh: handshake failed: %w", &net.OpError{Op: "read", Net: "tcp", Err: opaqueErrnoError{syscall.ETIMEDOUT}}),
		"refused text in a handshake": fmt.Errorf("ssh: handshake failed: %w", &net.OpError{Op: "read", Net: "tcp", Err: opaqueErrnoError{syscall.ECONNREFUSED}}),
	} {
		if got := ClassifySSH(err, context); got.Error != CodeHandshakeFailed {
			t.Errorf("%s = %+v, want handshake_failed", name, got)
		}
	}
}
