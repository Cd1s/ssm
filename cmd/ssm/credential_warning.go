package main

import (
	"fmt"
	"os"
	"sync"

	"ssm/internal/privatepath"
)

var warnedCredentialFiles struct {
	sync.Mutex
	files []os.FileInfo
}

func warnCredentialFile(option, path string) {
	if os.Getenv("SSM_NO_PERMISSION_WARNING") == "1" || !privatepath.WarnIfBroad(path) {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	warnedCredentialFiles.Lock()
	defer warnedCredentialFiles.Unlock()
	for _, warned := range warnedCredentialFiles.files {
		if os.SameFile(info, warned) {
			return
		}
	}
	warnedCredentialFiles.files = append(warnedCredentialFiles.files, info)
	fmt.Fprintf(os.Stderr, "warning: %s is readable by other users; run chmod 600 on it\n", option)
}
