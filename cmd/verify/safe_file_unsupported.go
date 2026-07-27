//go:build !unix && !windows

package main

import (
	"fmt"
	"os"
)

func openRegularFileNoFollow(_, slashPath string) (*os.File, error) {
	return nil, fmt.Errorf("safe no-follow regular-file open is unsupported for %q on this platform", slashPath)
}

func workspaceFileMode(os.FileMode) os.FileMode {
	return 0o600
}
