//go:build !unix && !windows

package main

import (
	"fmt"
	"os/exec"
)

type ownedProcessTree struct{}

func newOwnedProcessTree(*exec.Cmd) (*ownedProcessTree, error) {
	return nil, fmt.Errorf("verifier process-tree ownership is unsupported on this platform")
}

func (*ownedProcessTree) attach(*exec.Cmd) error {
	return nil
}

func (*ownedProcessTree) terminate() error {
	return nil
}

func (*ownedProcessTree) wait() error {
	return nil
}

func (*ownedProcessTree) terminateAndWait() error {
	return nil
}

func (*ownedProcessTree) close() error {
	return nil
}
