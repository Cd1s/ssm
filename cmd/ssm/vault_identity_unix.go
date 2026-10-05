//go:build unix

package main

import (
	"os"
	"syscall"
)

func vaultFileIdentityFromFileInfo(info os.FileInfo) vaultFileIdentity {
	identity := vaultFileIdentity{size: info.Size(), modTimeNS: info.ModTime().UnixNano()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		identity.device = uint64(stat.Dev)
		identity.inode = uint64(stat.Ino)
	}
	return identity
}
