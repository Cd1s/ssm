//go:build windows

package config

import "ssm/internal/privatepath"

func restrictPrivateDirectory(path string) error {
	return privatepath.RestrictDirectory(path)
}
