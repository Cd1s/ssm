//go:build unix

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

type ownedProcessTree struct {
	processGroupID int
}

func newOwnedProcessTree(command *exec.Cmd) (*ownedProcessTree, error) {
	if command.SysProcAttr != nil {
		return nil, errors.New("verifier command already has platform process attributes")
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &ownedProcessTree{}, nil
}

func (tree *ownedProcessTree) attach(command *exec.Cmd) error {
	tree.processGroupID = command.Process.Pid
	return nil
}

func (tree *ownedProcessTree) terminate() error {
	if tree.processGroupID <= 0 {
		return nil
	}
	err := syscall.Kill(-tree.processGroupID, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("terminate verifier process group: %w", err)
	}
	return nil
}

func (tree *ownedProcessTree) wait() error {
	if tree.processGroupID <= 0 {
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := syscall.Kill(-tree.processGroupID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect verifier process group termination: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for verifier process group %d", tree.processGroupID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (tree *ownedProcessTree) terminateAndWait() error {
	return errors.Join(tree.terminate(), tree.wait())
}

func (*ownedProcessTree) close() error {
	return nil
}
