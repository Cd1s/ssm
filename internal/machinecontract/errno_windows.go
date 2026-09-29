//go:build windows

package machinecontract

import (
	"errors"
	"syscall"
)

// Winsock reports resets and aborts with its own error numbers, which do not
// match syscall.ECONNRESET and syscall.ECONNABORTED on Windows.
const (
	wsaECONNABORTED syscall.Errno = 10053
	wsaECONNRESET   syscall.Errno = 10054
)

func isPlatformConnectionBreak(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == wsaECONNABORTED || errno == wsaECONNRESET)
}
