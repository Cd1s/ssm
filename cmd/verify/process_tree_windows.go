//go:build windows

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ownedProcessTree struct {
	job         windows.Handle
	rootProcess windows.Handle
	rootDone    chan error

	terminateOnce sync.Once
	terminateErr  error
}

type jobBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

func newOwnedProcessTree(command *exec.Cmd) (*ownedProcessTree, error) {
	if command.SysProcAttr != nil {
		return nil, errors.New("verifier command already has platform process attributes")
	}
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	command.WaitDelay = 5 * time.Second
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create verifier Job Object: %w", err)
	}
	information := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	information.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&information)),
		uint32(unsafe.Sizeof(information)),
	); err != nil {
		return nil, errors.Join(
			fmt.Errorf("configure verifier Job Object: %w", err),
			windows.CloseHandle(job),
		)
	}
	return &ownedProcessTree{job: job}, nil
}

func (tree *ownedProcessTree) attach(command *exec.Cmd) error {
	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|
			windows.PROCESS_TERMINATE|
			windows.PROCESS_QUERY_LIMITED_INFORMATION|
			windows.SYNCHRONIZE,
		false,
		uint32(command.Process.Pid),
	)
	if err != nil {
		return fmt.Errorf("open verifier process for Job Object: %w", err)
	}
	assignErr := windows.AssignProcessToJobObject(tree.job, process)
	if assignErr != nil {
		return errors.Join(
			wrapProcessTreeError("assign verifier process to Job Object", assignErr),
			wrapProcessTreeError("close verifier process handle", windows.CloseHandle(process)),
		)
	}
	tree.rootProcess = process
	if err := resumeOwnedWindowsProcess(uint32(command.Process.Pid)); err != nil {
		return err
	}
	tree.rootDone = make(chan error, 1)
	go tree.monitorRootCompletion()
	return nil
}

func (tree *ownedProcessTree) terminate() error {
	tree.terminateOnce.Do(func() {
		tree.terminateErr = tree.terminateJob()
	})
	return tree.terminateErr
}

func (tree *ownedProcessTree) terminateJob() error {
	if tree.job == 0 {
		return nil
	}
	if err := windows.TerminateJobObject(tree.job, 1); err != nil {
		return fmt.Errorf("terminate verifier Job Object: %w", err)
	}
	return nil
}

func (tree *ownedProcessTree) wait() error {
	if tree.rootDone != nil {
		return <-tree.rootDone
	}
	return tree.waitJob()
}

func (tree *ownedProcessTree) waitJob() error {
	if tree.job == 0 {
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var information jobBasicAccountingInformation
		if err := windows.QueryInformationJobObject(
			tree.job,
			windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&information)),
			uint32(unsafe.Sizeof(information)),
			nil,
		); err != nil {
			return fmt.Errorf("inspect verifier Job Object termination: %w", err)
		}
		if information.ActiveProcesses == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for verifier Job Object processes")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (tree *ownedProcessTree) terminateAndWait() error {
	return errors.Join(tree.terminate(), tree.wait())
}

func (tree *ownedProcessTree) close() error {
	if tree.job == 0 {
		return nil
	}
	var rootErr error
	if tree.rootProcess != 0 {
		rootErr = windows.CloseHandle(tree.rootProcess)
		tree.rootProcess = 0
	}
	jobErr := windows.CloseHandle(tree.job)
	tree.job = 0
	return errors.Join(
		wrapProcessTreeError("close verifier root process handle", rootErr),
		wrapProcessTreeError("close verifier Job Object", jobErr),
	)
}

func (tree *ownedProcessTree) monitorRootCompletion() {
	event, waitErr := windows.WaitForSingleObject(tree.rootProcess, windows.INFINITE)
	if waitErr == nil && event != windows.WAIT_OBJECT_0 {
		waitErr = fmt.Errorf("unexpected root process wait result %#x", event)
	}
	tree.rootDone <- errors.Join(
		wrapProcessTreeError("wait for verifier root process", waitErr),
		tree.terminate(),
		tree.waitJob(),
	)
}

func resumeOwnedWindowsProcess(processID uint32) (returnErr error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("enumerate suspended verifier process threads: %w", err)
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			wrapProcessTreeError("close verifier thread snapshot", windows.CloseHandle(snapshot)),
		)
	}()

	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	err = windows.Thread32First(snapshot, &entry)
	resumed := 0
	for err == nil {
		if entry.OwnerProcessID == processID {
			thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if openErr != nil {
				return fmt.Errorf("open suspended verifier process thread: %w", openErr)
			}
			_, resumeErr := windows.ResumeThread(thread)
			closeErr := windows.CloseHandle(thread)
			if resumeErr != nil || closeErr != nil {
				return errors.Join(
					wrapProcessTreeError("resume verifier process thread", resumeErr),
					wrapProcessTreeError("close verifier process thread", closeErr),
				)
			}
			resumed++
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		err = windows.Thread32Next(snapshot, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("enumerate suspended verifier process threads: %w", err)
	}
	if resumed == 0 {
		return fmt.Errorf("suspended verifier process has no resumable thread")
	}
	return nil
}

func wrapProcessTreeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
