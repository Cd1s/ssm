//go:build unix

package inventorytransaction

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func tryPublicationFileLock(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) //nolint:gosec // flock accepts the OS descriptor owned by os.File
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
		return false, nil
	default:
		return false, err
	}
}

func unlockPublicationFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN) //nolint:gosec // flock accepts the OS descriptor owned by os.File
}
