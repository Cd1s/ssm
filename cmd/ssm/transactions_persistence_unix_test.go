//go:build linux || darwin

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func pushPersistenceFailureSupported() bool {
	return true
}

func injectPushPersistenceFailureFromEnvironment() {
	if os.Getenv("SSM_TEST_PUSH_PERSISTENCE_FAILURE") != "1" {
		return
	}
	signal.Ignore(syscall.SIGXFSZ)
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		panic(err)
	}
	limit.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		panic(err)
	}
}
