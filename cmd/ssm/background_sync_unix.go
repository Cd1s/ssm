//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startDetachedBackgroundSync starts `sshctl sync --background` in its own
// session so it survives the parent and the terminal. All standard streams are
// the null device, the environment is inherited, and the parent releases the
// child without waiting.
func startDetachedBackgroundSync(executable string) error {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open null device: %w", err)
	}
	defer func() { _ = null.Close() }()
	command := &exec.Cmd{
		Path:        executable,
		Args:        []string{"sshctl", "sync", backgroundSyncFlag},
		Env:         os.Environ(),
		Stdin:       null,
		Stdout:      null,
		Stderr:      null,
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
