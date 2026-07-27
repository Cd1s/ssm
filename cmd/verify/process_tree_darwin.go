//go:build darwin

package main

import (
	"errors"
	"os/exec"
)

type ownedProcessTree struct{}

func newOwnedProcessTree(*exec.Cmd) (*ownedProcessTree, error) {
	return nil, errors.New("verifier cannot guarantee stable command-tree ownership on Darwin")
}

func (*ownedProcessTree) attach(*exec.Cmd) error  { return nil }
func (*ownedProcessTree) terminate() error        { return nil }
func (*ownedProcessTree) wait() error             { return nil }
func (*ownedProcessTree) terminateAndWait() error { return nil }
func (*ownedProcessTree) close() error            { return nil }
