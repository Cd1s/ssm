package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var debugEnabled bool

func EnableDebug() {
	debugEnabled = true
	_ = WritePrivateFile(debugPath(), []byte{})
}

func debugPath() string {
	return filepath.Join(Dir(), "debug.log")
}

func Debug(format string, args ...any) {
	if !debugEnabled {
		return
	}
	f, err := os.OpenFile(debugPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	ts := time.Now().Format("15:04:05.000")
	fmt.Fprintf(f, "%s  %s\n", ts, fmt.Sprintf(format, args...))
}
