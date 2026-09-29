//go:build unix

package ssh

import (
	"os"
	"syscall"

	gossh "golang.org/x/crypto/ssh"
)

var runInterruptSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}

// remoteInterrupt maps a local interrupt to the SSH signal forwarded to the
// remote command and the conventional 128+signo local exit status.
func remoteInterrupt(signal os.Signal) (gossh.Signal, int) {
	switch signal {
	case syscall.SIGTERM:
		return gossh.SIGTERM, 128 + int(syscall.SIGTERM)
	case syscall.SIGHUP:
		return gossh.SIGHUP, 128 + int(syscall.SIGHUP)
	default:
		return gossh.SIGINT, 128 + int(syscall.SIGINT)
	}
}
