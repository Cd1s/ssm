//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	linuxSupervisorArgument = "--ssm-internal-command-supervisor"
	linuxSupervisorSpecFD   = 3
	linuxSupervisorStatusFD = 4
	linuxSupervisorCancelFD = 5
	processTreeWaitTimeout  = 5 * time.Second
)

type linuxCommandSpecification struct {
	Path string
	Args []string
	Env  []string
	Dir  string
}

type linuxSupervisorStatus struct {
	Ready bool
	Error string
}

type ownedProcessTree struct {
	specFile    *os.File
	statusRead  *os.File
	statusWrite *os.File
	cancelRead  *os.File
	cancelWrite *os.File

	terminateOnce sync.Once
	terminateErr  error
}

func init() {
	if len(os.Args) != 2 || os.Args[1] != linuxSupervisorArgument {
		return
	}
	os.Exit(runLinuxCommandSupervisor())
}

func newOwnedProcessTree(command *exec.Cmd) (*ownedProcessTree, error) {
	if command.SysProcAttr != nil {
		return nil, errors.New("verifier command already has platform process attributes")
	}
	if len(command.ExtraFiles) != 0 {
		return nil, errors.New("verifier command already has extra files")
	}

	specification := linuxCommandSpecification{
		Path: command.Path,
		Args: cloneProcessTreeStrings(command.Args),
		Env:  effectiveProcessTreeEnvironment(command.Env),
		Dir:  command.Dir,
	}
	specFD, err := unix.MemfdCreate("ssm-verifier-command", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create verifier command specification: %w", err)
	}
	specFile := os.NewFile(uintptr(specFD), "ssm-verifier-command") //nolint:gosec // MemfdCreate returned a successful non-negative file descriptor
	if specFile == nil {
		_ = unix.Close(specFD)
		return nil, errors.New("open verifier command specification")
	}
	if err := json.NewEncoder(specFile).Encode(specification); err != nil {
		return nil, errors.Join(
			fmt.Errorf("encode verifier command specification: %w", err),
			specFile.Close(),
		)
	}
	if _, err := specFile.Seek(0, 0); err != nil {
		return nil, errors.Join(
			fmt.Errorf("rewind verifier command specification: %w", err),
			specFile.Close(),
		)
	}

	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("create verifier supervisor status pipe: %w", err),
			specFile.Close(),
		)
	}
	cancelRead, cancelWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("create verifier supervisor cancellation pipe: %w", err),
			statusRead.Close(),
			statusWrite.Close(),
			specFile.Close(),
		)
	}
	tree := &ownedProcessTree{
		specFile:    specFile,
		statusRead:  statusRead,
		statusWrite: statusWrite,
		cancelRead:  cancelRead,
		cancelWrite: cancelWrite,
	}

	executable, err := os.Executable()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("locate verifier command supervisor: %w", err),
			tree.close(),
		)
	}
	helper := exec.Command(executable, linuxSupervisorArgument) //nolint:gosec // executable is the current verifier binary
	helper.Env = linuxSupervisorEnvironment()
	helper.Stdin = command.Stdin
	helper.Stdout = command.Stdout
	helper.Stderr = command.Stderr
	helper.ExtraFiles = []*os.File{specFile, statusWrite, cancelRead}
	helper.WaitDelay = processTreeWaitTimeout
	*command = *helper
	return tree, nil
}

func (tree *ownedProcessTree) attach(*exec.Cmd) error {
	closeErr := errors.Join(
		closeProcessTreeFile(&tree.specFile),
		closeProcessTreeFile(&tree.statusWrite),
		closeProcessTreeFile(&tree.cancelRead),
	)
	if closeErr != nil {
		return closeErr
	}

	type statusResult struct {
		status linuxSupervisorStatus
		err    error
	}
	statusRead := tree.statusRead
	received := make(chan statusResult, 1)
	go func() {
		var status linuxSupervisorStatus
		err := json.NewDecoder(statusRead).Decode(&status)
		received <- statusResult{status: status, err: err}
	}()

	var result statusResult
	select {
	case result = <-received:
	case <-time.After(processTreeWaitTimeout):
		_ = statusRead.Close()
		tree.statusRead = nil
		return errors.New("timed out waiting for verifier command supervisor startup")
	}
	closeErr = closeProcessTreeFile(&tree.statusRead)
	if result.err != nil {
		return errors.Join(
			fmt.Errorf("read verifier command supervisor startup: %w", result.err),
			closeErr,
		)
	}
	if !result.status.Ready {
		return errors.Join(
			fmt.Errorf("prepare verifier command supervisor: %s", result.status.Error),
			closeErr,
		)
	}
	_, startErr := tree.cancelWrite.Write([]byte{1})
	return errors.Join(
		wrapProcessTreeError("release verifier command after ownership handshake", startErr),
		closeErr,
	)
}

func cloneProcessTreeStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func effectiveProcessTreeEnvironment(environment []string) []string {
	if environment == nil {
		return os.Environ()
	}
	return cloneProcessTreeStrings(environment)
}

func linuxSupervisorEnvironment() []string {
	environment := os.Environ()
	const prefix = "GORACE="
	for index, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			environment[index] = entry + " atexit_sleep_ms=0"
			return environment
		}
	}
	return append(environment, prefix+"atexit_sleep_ms=0")
}

func (tree *ownedProcessTree) terminate() error {
	tree.terminateOnce.Do(func() {
		tree.terminateErr = closeProcessTreeFile(&tree.cancelWrite)
	})
	return tree.terminateErr
}

func (*ownedProcessTree) wait() error {
	return nil
}

func (tree *ownedProcessTree) terminateAndWait() error {
	return errors.Join(tree.terminate(), tree.wait())
}

func (tree *ownedProcessTree) close() error {
	return errors.Join(
		tree.terminate(),
		closeProcessTreeFile(&tree.specFile),
		closeProcessTreeFile(&tree.statusRead),
		closeProcessTreeFile(&tree.statusWrite),
		closeProcessTreeFile(&tree.cancelRead),
	)
}

func closeProcessTreeFile(file **os.File) error {
	if *file == nil {
		return nil
	}
	err := (*file).Close()
	*file = nil
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func runLinuxCommandSupervisor() int {
	specFile := os.NewFile(linuxSupervisorSpecFD, "ssm-verifier-command")
	statusFile := os.NewFile(linuxSupervisorStatusFD, "ssm-verifier-status")
	cancelFile := os.NewFile(linuxSupervisorCancelFD, "ssm-verifier-cancel")
	if specFile == nil || statusFile == nil || cancelFile == nil {
		return 125
	}
	defer func() { _ = specFile.Close() }()
	defer func() { _ = statusFile.Close() }()
	defer func() { _ = cancelFile.Close() }()

	var specification linuxCommandSpecification
	if err := json.NewDecoder(specFile).Decode(&specification); err != nil {
		sendLinuxSupervisorStatus(statusFile, fmt.Errorf("decode command specification: %w", err))
		return 125
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		sendLinuxSupervisorStatus(statusFile, fmt.Errorf("establish command subreaper: %w", err))
		return 125
	}
	selfPidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		sendLinuxSupervisorStatus(statusFile, fmt.Errorf("verify pidfd support: %w", err))
		return 125
	}
	if err := unix.PidfdSendSignal(selfPidfd, 0, nil, 0); err != nil {
		_ = unix.Close(selfPidfd)
		sendLinuxSupervisorStatus(statusFile, fmt.Errorf("verify pidfd signaling: %w", err))
		return 125
	}
	if err := unix.Close(selfPidfd); err != nil {
		sendLinuxSupervisorStatus(statusFile, fmt.Errorf("close pidfd capability probe: %w", err))
		return 125
	}
	if err := json.NewEncoder(statusFile).Encode(linuxSupervisorStatus{Ready: true}); err != nil {
		return 125
	}
	_ = statusFile.Close()
	statusFile = nil
	var start [1]byte
	if _, err := cancelFile.Read(start[:]); err != nil {
		return 125
	}

	rootPidfd := -1
	target := &exec.Cmd{
		Path:   specification.Path,
		Args:   specification.Args,
		Env:    specification.Env,
		Dir:    specification.Dir,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		SysProcAttr: &syscall.SysProcAttr{
			PidFD: &rootPidfd,
		},
	}
	if err := target.Start(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "verifier command supervisor: start verifier command: %v\n", err)
		return 125
	}
	if rootPidfd < 0 {
		_ = target.Process.Kill()
		_ = target.Wait()
		_, _ = fmt.Fprintln(os.Stderr, "verifier command supervisor: kernel did not return a stable root process handle")
		return 125
	}

	cancelled := make(chan struct{})
	go func() {
		var buffer [1]byte
		_, _ = cancelFile.Read(buffer[:])
		close(cancelled)
	}()
	waited := make(chan error, 1)
	go func() {
		waited <- target.Wait()
	}()

	var waitErr error
	var supervisorErr error
	select {
	case waitErr = <-waited:
	case <-cancelled:
		supervisorErr = terminateLinuxSupervisorRoot(rootPidfd)
		select {
		case waitErr = <-waited:
		case <-time.After(processTreeWaitTimeout):
			supervisorErr = errors.Join(supervisorErr, errors.New("timed out waiting for verifier command root"))
		}
	}
	supervisorErr = errors.Join(
		supervisorErr,
		wrapProcessTreeError("close verifier command root pidfd", unix.Close(rootPidfd)),
		cleanupLinuxSupervisorDescendants(time.Now().Add(processTreeWaitTimeout)),
	)
	if supervisorErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "verifier command supervisor: %v\n", supervisorErr)
		return 125
	}
	return linuxSupervisorExitCode(waitErr)
}

func sendLinuxSupervisorStatus(statusFile *os.File, err error) {
	_ = json.NewEncoder(statusFile).Encode(linuxSupervisorStatus{Error: err.Error()})
}

func terminateLinuxSupervisorRoot(rootPidfd int) error {
	pidfdErr := unix.PidfdSendSignal(rootPidfd, unix.SIGKILL, nil, 0)
	if errors.Is(pidfdErr, unix.ESRCH) {
		pidfdErr = nil
	}
	return wrapProcessTreeError("terminate verifier command root", pidfdErr)
}

func cleanupLinuxSupervisorDescendants(deadline time.Time) error {
	for {
		if time.Now().After(deadline) {
			return errors.New("timed out cleaning verifier command descendants")
		}
		if err := reapLinuxSupervisorChildren(); err != nil {
			return err
		}
		children, err := linuxSupervisorChildren()
		if err != nil {
			return err
		}
		if len(children) == 0 {
			var status syscall.WaitStatus
			pid, waitErr := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
			switch {
			case errors.Is(waitErr, syscall.ECHILD):
				return nil
			case waitErr != nil:
				return fmt.Errorf("inspect verifier command descendants: %w", waitErr)
			case pid > 0:
				continue
			default:
				continue
			}
		}

		pollDescriptors := make([]unix.PollFd, 0, len(children))
		childDisappeared := false
		for _, pid := range children {
			pidfd, err := unix.PidfdOpen(pid, 0)
			if errors.Is(err, unix.ESRCH) {
				childDisappeared = true
				continue
			}
			if err != nil {
				return fmt.Errorf("open verifier descendant %d pidfd: %w", pid, err)
			}
			if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				_ = unix.Close(pidfd)
				return fmt.Errorf("terminate verifier descendant %d: %w", pid, err)
			}
			const maximumPollFileDescriptor = int64(1<<31 - 1)
			if int64(pidfd) > maximumPollFileDescriptor {
				_ = unix.Close(pidfd)
				return fmt.Errorf("verifier descendant %d pidfd exceeds poll descriptor range", pid)
			}
			pollDescriptors = append(pollDescriptors, unix.PollFd{
				Fd:     int32(pidfd), //nolint:gosec // guarded against overflow immediately above
				Events: unix.POLLIN,
			})
		}
		if childDisappeared && len(pollDescriptors) == 0 {
			continue
		}
		timeout := int(time.Until(deadline).Milliseconds())
		if timeout < 1 {
			timeout = 1
		}
		_, pollErr := unix.Poll(pollDescriptors, timeout)
		var closeErr error
		for _, descriptor := range pollDescriptors {
			closeErr = errors.Join(closeErr, unix.Close(int(descriptor.Fd)))
		}
		if pollErr != nil && !errors.Is(pollErr, unix.EINTR) {
			return errors.Join(
				fmt.Errorf("wait for verifier descendants: %w", pollErr),
				closeErr,
			)
		}
		if closeErr != nil {
			return fmt.Errorf("close verifier descendant pidfds: %w", closeErr)
		}
	}
}

func linuxSupervisorChildren() ([]int, error) {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, fmt.Errorf("enumerate verifier supervisor threads: %w", err)
	}
	children := make(map[int]struct{})
	for _, task := range tasks {
		if _, err := strconv.Atoi(task.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "children"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read verifier supervisor children: %w", err)
		}
		for _, field := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 0 {
				return nil, fmt.Errorf("parse verifier supervisor child %q", field)
			}
			children[pid] = struct{}{}
		}
	}
	result := make([]int, 0, len(children))
	for pid := range children {
		result = append(result, pid)
	}
	return result, nil
}

func reapLinuxSupervisorChildren() error {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		switch {
		case errors.Is(err, syscall.ECHILD):
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case err != nil:
			return fmt.Errorf("reap verifier command descendant: %w", err)
		case pid == 0:
			return nil
		}
	}
}

func linuxSupervisorExitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		return 125
	}
	if code := exitErr.ExitCode(); code >= 0 {
		return code
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return 125
	}
	return 128 + int(status.Signal())
}

func wrapProcessTreeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
