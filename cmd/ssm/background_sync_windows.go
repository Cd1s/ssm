//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const (
	windowsDetachedProcess       = 0x00000008
	windowsCreateNewProcessGroup = 0x00000200
)

// startDetachedBackgroundSync starts `sshctl sync --background` detached from
// the parent's console and process group, with every standard stream on the
// null device, then releases it without waiting.
func startDetachedBackgroundSync(executable, claimToken string) error {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open null device: %w", err)
	}
	defer func() { _ = null.Close() }()
	command := &exec.Cmd{
		Path:   executable,
		Dir:    os.TempDir(),
		Args:   []string{"sshctl", "sync", backgroundSyncFlag},
		Env:    backgroundEnvironment(claimToken),
		Stdin:  null,
		Stdout: null,
		Stderr: null,
		SysProcAttr: &syscall.SysProcAttr{
			CreationFlags: windowsDetachedProcess | windowsCreateNewProcessGroup,
			HideWindow:    true,
		},
	}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
