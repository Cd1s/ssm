//go:build windows

package machinecontract

import (
	"os"
	"syscall"
	"testing"
)

func TestClassifySSHRecognizesWinsockErrnos(t *testing.T) {
	t.Parallel()
	for _, errno := range []syscall.Errno{10053, 10054} {
		err := os.NewSyscallError("wsarecv", errno)
		got := ClassifySSH(err, SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22})
		if got.Error != CodeConnectionLost {
			t.Fatalf("ClassifySSH(errno %d) = %+v, want connection_lost", errno, got)
		}
	}
}
