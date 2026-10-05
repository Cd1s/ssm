//go:build unix

package main

import (
	"os"
	"syscall"
)

func vaultFileIdentityFromFileInfo(info os.FileInfo) vaultFileIdentity {
	identity := vaultFileIdentity{size: info.Size(), modTimeNS: info.ModTime().UnixNano()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// Dev is int32 on darwin and uint64 on linux; the conversion is required to build on both.
		identity.device = uint64(stat.Dev) //nolint:unconvert,gosec // Dev is int32 on darwin; it is only compared for equality
		identity.inode = uint64(stat.Ino)  //nolint:unconvert // keep both fields uniform across platforms
	}
	return identity
}
