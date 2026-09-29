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
// the null device, the environment is inherited, and the working directory is
// the filesystem root so the child never pins the caller's directory. The
// parent never blocks on the child: a goroutine reaps it, so a long-running
// parent (for example run --stream) does not accumulate zombies.
func startDetachedBackgroundSync(executable string) error {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open null device: %w", err)
	}
	defer func() { _ = null.Close() }()
	command := &exec.Cmd{
		Path:        executable,
		Args:        []string{"sshctl", "sync", backgroundSyncFlag},
		Dir:         string(os.PathSeparator),
		Env:         backgroundEnvironment(),
		Stdin:       null,
		Stdout:      null,
		Stderr:      null,
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}
