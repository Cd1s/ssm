//go:build windows

package main

import "os"

func vaultFileIdentityFromFileInfo(info os.FileInfo) vaultFileIdentity {
	// No stable file ID without reopening the file here; size and mtime still change on an atomic replace.
	return vaultFileIdentity{size: info.Size(), modTimeNS: info.ModTime().UnixNano(), device: 0, inode: 0}
}
