//go:build unix

package ssh

import (
	"os"

	"golang.org/x/sys/unix"
)

func stdinHasReadableData() bool {
	pollFds := []unix.PollFd{{
		Fd:     int32(os.Stdin.Fd()),
		Events: unix.POLLIN | unix.POLLHUP,
	}}
	n, err := unix.Poll(pollFds, 100)
	return err == nil && n > 0 && pollFds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0
}
