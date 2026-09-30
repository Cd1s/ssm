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

// Winsock connect failures. errors.Is(err, syscall.ECONNREFUSED) does not
// match them on Windows.
const (
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
	wsaETIMEDOUT    syscall.Errno = 10060
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

func platformDialErrnoKind(err error) Kind {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return ""
	}
	switch errno {
	case wsaECONNREFUSED:
		return DialRefused
	case wsaETIMEDOUT:
		return DialTimeout
	case wsaENETDOWN, wsaENETUNREACH, wsaEHOSTDOWN, wsaEHOSTUNREACH:
		return DialNetwork
	}
	return ""
}
