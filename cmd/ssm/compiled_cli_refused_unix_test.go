//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"fmt"
	"syscall"
)

func reserveCompiledRefusedTCPPort() (string, int, func() error, error) {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return "", 0, nil, err
	}
	closeSocket := func() error { return syscall.Close(socket) }
	address := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(socket, address); err != nil {
		_ = closeSocket()
		return "", 0, nil, err
	}
	bound, err := syscall.Getsockname(socket)
	if err != nil {
		_ = closeSocket()
		return "", 0, nil, err
	}
	inet, ok := bound.(*syscall.SockaddrInet4)
	if !ok {
		_ = closeSocket()
		return "", 0, nil, fmt.Errorf("reserved socket has address type %T", bound)
	}
	return "127.0.0.1", inet.Port, closeSocket, nil
}
