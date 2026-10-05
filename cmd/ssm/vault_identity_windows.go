//go:build windows

package main

import "os"

func vaultFileIdentityFromFileInfo(info os.FileInfo) vaultFileIdentity {
	return vaultFileIdentity{size: info.Size(), modTimeNS: info.ModTime().UnixNano()}
}
