package main

import (
	"os"

	"ssm/internal/config"
)

type vaultFileIdentity struct {
	size      int64
	modTimeNS int64
	device    uint64
	inode     uint64
}

func currentVaultFileIdentity() (vaultFileIdentity, error) {
	info, err := os.Stat(config.Path())
	if err != nil {
		return vaultFileIdentity{}, err
	}
	return vaultFileIdentityFromFileInfo(info), nil
}
