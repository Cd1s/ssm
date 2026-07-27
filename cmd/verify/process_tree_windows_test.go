//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOwnedCommandCancellationReleasesWindowsJobHandles(t *testing.T) {
	if os.Getenv("SSM_VERIFY_WINDOWS_JOB_HELPER") == "1" {
		time.Sleep(30 * time.Second)
		return
	}
	runtime.GC()
	before := currentProcessHandleCount(t)
	for range 5 {
		ctx, cancel := context.WithCancel(context.Background())
		command := exec.Command(os.Args[0], "-test.run=^TestOwnedCommandCancellationReleasesWindowsJobHandles$")
		command.Env = append(os.Environ(), "SSM_VERIFY_WINDOWS_JOB_HELPER=1")
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		err := runOwnedCommand(ctx, command)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("owned command error = %v, want context.Canceled", err)
		}
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := currentProcessHandleCount(t)
	if after > before+2 {
		t.Fatalf("process handle count grew from %d to %d; verifier Job handles were not released", before, after)
	}
}

func currentProcessHandleCount(t *testing.T) uint32 {
	t.Helper()
	procedure := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	var count uint32
	result, _, callErr := procedure.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&count)),
	)
	if result == 0 {
		t.Fatalf("GetProcessHandleCount: %v", callErr)
	}
	return count
}
