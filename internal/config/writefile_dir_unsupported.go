//go:build !unix && !windows

package config

import (
	"fmt"

	"ssm/internal/privatepath"
)

func restrictPrivateDirectory(path string) error {
	return privatepath.RestrictDirectory(path)
}

func syncPrivateDirectory(string) error {
	return fmt.Errorf("private directory synchronization is unsupported on this platform")
}
