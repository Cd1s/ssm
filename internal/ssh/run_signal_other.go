//go:build !unix

package ssh

import (
	"os"

	gossh "golang.org/x/crypto/ssh"
)

var runInterruptSignals = []os.Signal{os.Interrupt}

// remoteInterrupt maps a local interrupt to the SSH signal forwarded to the
// remote command and the conventional 128+SIGINT local exit status.
func remoteInterrupt(os.Signal) (gossh.Signal, int) {
	return gossh.SIGINT, 130
}
