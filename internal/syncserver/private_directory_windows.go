//go:build windows

package syncserver

import "ssm/internal/privatepath"

func restrictPrivateDirectory(path string) error {
	return privatepath.RestrictDirectory(path)
}
