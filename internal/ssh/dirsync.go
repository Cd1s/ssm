package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func UploadPathWithOptions(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	if c.UsesSFTP() {
		return uploadPathSFTP(c, v, localPath, remotePath, opts)
	}
	info, err := os.Stat(localPath)
	if err != nil {
		return TransferResult{Direction: "put", Kind: "unknown", Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"}, transferError(machinecontract.TransferLocalRead, 0, err)
	}
	if info.Mode().IsRegular() {
		result, err := UploadFileWithOptions(c, v, localPath, remotePath, opts)
		result.Direction, result.Kind = "put", "file"
		return result, err
	}
	if !info.IsDir() {
		return TransferResult{Direction: "put", Kind: "unknown", Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"}, transferError(machinecontract.TransferDirectorySourceUnsupported, 0, fmt.Errorf("%s is not a regular file or directory", localPath))
	}
	if opts.VerifySHA256 || opts.Timeout > 0 || opts.ResumeVersion != "" {
		return TransferResult{Direction: "put", Kind: "directory", Stage: "validate", Integrity: "not_available", Resume: "unsupported"}, transferError(machinecontract.TransferDirectoryOptionsUnsupported, 0, errors.New("directory transfer does not support requested reliability options"))
	}
	err = uploadDirTar(c, v, localPath, remotePath, opts.DirMode)
	if err != nil {
		stage := "remote_write"
		var transferErr *TransferError
		if errors.As(err, &transferErr) && transferErr.failure.Stage != "" {
			stage = transferErr.failure.Stage
		}
		return TransferResult{Direction: "put", Kind: "directory", Stage: stage, Integrity: "not_available", Resume: "unsupported"}, err
	}
	return TransferResult{OK: true, Direction: "put", Kind: "directory", Stage: "complete", Integrity: "not_available", Atomic: false, Resume: "unsupported"}, nil
}

// DownloadOptions controls get. Directory downloads support Timeout only.
type DownloadOptions struct {
	VerifySHA256 bool
	Timeout      time.Duration
}

// DownloadPath downloads a remote file or directory tree.
// Directories use tar-over-ssh; remotePath should be a directory.
func DownloadPath(c config.Connection, v *config.Vault, remotePath, localPath string) (TransferResult, error) {
	return DownloadPathWithOptions(c, v, remotePath, localPath, DownloadOptions{})
}

// DownloadPathWithOptions is DownloadPath with optional timeout and SHA-256
// verification (regular files only).
func DownloadPathWithOptions(c config.Connection, v *config.Vault, remotePath, localPath string, opts DownloadOptions) (TransferResult, error) {
	if c.UsesSFTP() {
		return downloadFileSFTP(c, v, remotePath, localPath, opts)
	}
	// Probe: if remote is a directory, tar it; else single file.
	isDir, err := remoteIsDir(c, v, remotePath)
	if err != nil {
		return TransferResult{Direction: "get", Kind: "unknown", Stage: "discovery"}, err
	}
	if !isDir {
		return downloadFileWithOptions(c, v, remotePath, localPath, opts)
	}
	if opts.VerifySHA256 {
		return TransferResult{Direction: "get", Kind: "directory", Stage: "validate", Integrity: "not_available", Resume: "unsupported"}, transferError(machinecontract.TransferDirectoryOptionsUnsupported, 0, errors.New("directory transfer does not support --sha256"))
	}
	result := TransferResult{Direction: "get", Kind: "directory", Stage: "remote_read", Integrity: "not_available", Atomic: false, Resume: "unsupported"}
	err = downloadDirTar(c, v, remotePath, localPath, opts.Timeout)
	if err != nil {
		var transferErr *TransferError
		if errors.As(err, &transferErr) && transferErr.failure.Stage == "timeout" {
			result.Stage = "timeout"
		}
		return result, err
	}
	result.OK = true
	result.Stage = "complete"
	return result, nil
}

func remoteIsDir(c config.Connection, v *config.Vault, remotePath string) (bool, error) {
	client, err := dialSSH(c, v)
	if err != nil {
		return false, err
	}
	defer releaseClient(client, false)
	return remoteIsDirOn(client, remotePath)
}

// remoteIsDirOn is remoteIsDir over an already connected client.
func remoteIsDirOn(client *gossh.Client, remotePath string) (bool, error) {
	session, err := newSessionRetry(client)
	if err != nil {
		return false, err
	}
	defer func() { _ = session.Close() }()

	cmd := fmt.Sprintf("if [ -d %s ]; then echo DIR; elif [ -f %s ]; then echo FILE; else echo MISSING; fi",
		ShellQuote(remotePath), ShellQuote(remotePath))
	out, err := session.CombinedOutput(cmd)
	if err != nil {
		var exit *gossh.ExitError
		if errors.As(err, &exit) || isExecRefused(err) {
			// A POSIX shell answers this probe with exit 0. A non-zero exit or
			// a refused exec request means the target has no such shell.
			return false, remoteShellUnsupportedError(string(out), err)
		}
		return false, err
	}
	switch strings.TrimSpace(string(out)) {
	case "DIR":
		return true, nil
	case "FILE":
		return false, nil
	case "MISSING":
		return false, transferError(machinecontract.TransferDownloadRemoteRead, 0, fmt.Errorf("remote path %s not found", remotePath))
	default:
		return false, remoteShellUnsupportedError(string(out), nil)
	}
}

// isExecRefused reports the client-side error x/crypto/ssh returns when the
// server rejects an exec request (for example an SFTP-only account).
// It relies on the exact text "ssh: command <cmd> failed" that
// golang.org/x/crypto/ssh (session.go, Session.start, v0.56.0) produces; the
// library exposes no typed error for it. TestCompiledExecRefusedIsAnUnsupportedRemoteShell
// pins this, so a changed message fails that test instead of silently
// degrading to a generic error.
func isExecRefused(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, "ssh: command ") && strings.HasSuffix(message, " failed")
}

const remoteShellProbeDetailLimit = 120

// remoteShellUnsupportedError reports a target whose shell did not answer the
// POSIX path probe, instead of misreporting the path as missing (issue #87).
func remoteShellUnsupportedError(output string, cause error) error {
	detail := strings.Join(strings.Fields(output), " ")
	if len(detail) > remoteShellProbeDetailLimit {
		detail = detail[:remoteShellProbeDetailLimit] + "..."
	}
	message := "the remote host does not run a POSIX shell for commands"
	switch {
	case detail != "":
		message += fmt.Sprintf(" (received %q)", detail)
	case cause != nil:
		message += ": " + cause.Error()
	}
	return transferKindError(machinecontract.RemoteShellUnsupported, 0, errors.New(message))
}

// errLocalTarUnavailable means the local tar binary is missing or cannot be
// executed. It is the only condition that selects the per-file fallback.
var errLocalTarUnavailable = errors.New("local tar is unavailable")

const remoteDiagnosticLimit = 4096

// boundedBuffer keeps the first remoteDiagnosticLimit bytes written to it.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := remoteDiagnosticLimit - b.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		b.buf.Write(p[:room])
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(b.buf.String())
}

func uploadDirTar(c config.Connection, v *config.Vault, localDir, remoteDir string, dirMode os.FileMode) error {
	tarPath, lookErr := exec.LookPath("tar")
	if lookErr == nil {
		err := uploadDirTarStream(c, v, tarPath, localDir, remoteDir, dirMode)
		if !errors.Is(err, errLocalTarUnavailable) {
			return err
		}
	}
	// Only a missing or non-executable local tar reaches this point.
	return uploadDirFallback(c, v, localDir, remoteDir, dirMode)
}

// remoteDirCreateCommand creates the destination directory. A zero dirMode
// selects DefaultUploadDirMode, so the result never depends on the remote
// login umask.
func remoteDirCreateCommand(remoteDir string, dirMode os.FileMode) string {
	if dirMode == 0 {
		dirMode = DefaultUploadDirMode
	}
	return remoteMkdirParents(remoteDir, dirMode)
}

func uploadDirTarStream(c config.Connection, v *config.Vault, tarPath, localDir, remoteDir string, dirMode os.FileMode) (resultErr error) {
	client, err := dialSSH(c, v)
	if err != nil {
		return err
	}
	defer releaseClient(client, false)

	session, err := newSessionRetry(client)
	if err != nil {
		return ClassifyError(err, c)
	}
	defer func() { _ = session.Close() }()

	// Ensure remote dir exists, then extract tar into it.
	remoteCmd := fmt.Sprintf("%s && tar -C %s -xf -", remoteDirCreateCommand(remoteDir, dirMode), ShellQuote(remoteDir))
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdoutSpool, err := machinecontract.NewDiagnosticSpool(os.Stdout)
	if err != nil {
		return err
	}
	defer func() { _ = stdoutSpool.Close() }()
	stderrSpool, err := machinecontract.NewDiagnosticSpool(os.Stderr)
	if err != nil {
		return errors.Join(err, stdoutSpool.Close())
	}
	defer func() { _ = stderrSpool.Close() }()
	diagnostics := []*machinecontract.DiagnosticSpool{stdoutSpool, stderrSpool}
	diagnosticsSucceeded := false
	defer func() {
		if replayErr := replayDiagnosticSpools(diagnosticsSucceeded, diagnostics...); resultErr == nil {
			resultErr = replayErr
		}
	}()
	session.Stdout = stdoutSpool
	// The remote message is also kept (bounded) so a remote extraction
	// failure can be reported as the first-hand error.
	var remoteStderr boundedBuffer
	session.Stderr = io.MultiWriter(stderrSpool, &remoteStderr)
	if err := session.Start(remoteCmd); err != nil {
		return err
	}

	// Keep local tar diagnostics separate from remote extractor diagnostics.
	var tarDiagnostics bytes.Buffer
	tarCmd := exec.Command(tarPath, "-C", localDir, "-cf", "-", ".") //nolint:gosec // tarPath comes from exec.LookPath("tar"); remaining argv is fixed
	tarCmd.Stderr = &tarDiagnostics
	tarOut, err := tarCmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := tarCmd.Start(); err != nil {
		// The local tar could not be executed: the only fallback trigger. Drain
		// the idle remote extractor and discard its diagnostics.
		_ = stdin.Close()
		_ = waitSessionBounded(session, remoteExitGrace)
		resultErr = errors.Join(stdoutSpool.Close(), stderrSpool.Close())
		if resultErr != nil {
			return resultErr
		}
		return errLocalTarUnavailable
	}
	// Copy the archive ourselves so the tar process's own failure (an
	// *exec.ExitError) stays distinct from a failure to write into the SSH
	// channel. The remote extractor may legitimately stop reading at the
	// archive end marker and exit 0 while tar is still writing record padding.
	_, copyErr := io.Copy(stdin, tarOut)
	if copyErr != nil {
		// Let tar finish writing bounded trailing bytes; beyond that the
		// reader is closed so tar cannot block on a full pipe.
		_, _ = io.Copy(io.Discard, io.LimitReader(tarOut, 1<<20))
		_ = tarOut.Close()
	}
	tarErr := tarCmd.Wait()
	_ = stdin.Close()
	remoteWaited := false
	var remoteErr error
	if tarErr != nil || copyErr != nil {
		remoteErr = waitSessionBounded(session, remoteExitGrace)
		remoteWaited = true
		var exitErr *gossh.ExitError
		localMessage := strings.TrimSpace(tarDiagnostics.String())
		switch {
		case errors.As(remoteErr, &exitErr):
			// The remote session's own non-zero exit is the deciding fact; the
			// local tar's wording (locale, bsdtar, tar.exe) is not. Local
			// diagnostics that do not look like a pipe failure are appended
			// for context only.
			_ = stderrSpool.Close()
			note := ""
			if tarErr != nil && localMessage != "" && !looksLikeBrokenPipe(localMessage) {
				note = fmt.Sprintf("; local tar also reported: %v: %s", tarErr, localMessage)
			}
			return remoteExtractError(remoteStderr.String(), remoteErr, note)
		case remoteErr != nil:
			return remoteErr
		case tarErr != nil:
			message := fmt.Sprintf("local tar failed: %v", tarErr)
			if localMessage != "" {
				message += ": " + localMessage
			}
			message += "; the remote destination may contain partially extracted files"
			return transferKindError(machinecontract.TransferLocalRead, 0, errors.New(message))
		}
		// tar exited 0 and the remote extractor exited 0: the write error was
		// only trailing padding sent after the extractor finished.
	}
	if _, err := stderrSpool.Write(tarDiagnostics.Bytes()); err != nil {
		return err
	}
	if !remoteWaited {
		remoteErr = session.Wait()
	}
	if remoteErr != nil {
		var exitErr *gossh.ExitError
		if errors.As(remoteErr, &exitErr) {
			_ = stderrSpool.Close()
			return remoteExtractError(remoteStderr.String(), remoteErr, "")
		}
		return remoteErr
	}
	diagnosticsSucceeded = true
	return nil
}

// remoteExitGrace bounds how long we wait for the remote extractor's exit
// status after the local tar has already ended.
const remoteExitGrace = 15 * time.Second

// sessionWaiter is the part of *gossh.Session the bounded wait needs; it is a
// seam so the remote-exited-first logic can be tested without a live server.
type sessionWaiter interface {
	Wait() error
	Close() error
}

func waitSessionBounded(session sessionWaiter, grace time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = session.Close()
		return <-done
	}
}

// looksLikeBrokenPipe is an auxiliary hint only: message wording varies by tar
// implementation and locale, so it never decides which end failed.
func looksLikeBrokenPipe(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "broken pipe") || strings.Contains(lower, "write error") ||
		strings.Contains(lower, "cannot write") || strings.Contains(lower, "not recoverable")
}

func remoteExtractError(stderr string, remoteErr error, note string) error {
	message := stderr
	if message == "" {
		message = remoteErr.Error()
	}
	// A plain error (not *gossh.ExitError) keeps the process exit code at the
	// contract's value instead of the remote's status.
	return transferKindError(machinecontract.TransferRemoteExtractFailed, 0, fmt.Errorf("remote tar extraction failed: %s%s", message, note))
}

// uploadDirFallback uploads a tree file by file. It is used only when the
// local tar is unavailable, and fails closed for entries it cannot represent.
func uploadDirFallback(c config.Connection, v *config.Vault, localDir, remoteDir string, dirMode os.FileMode) error {
	if err := validateUploadDirWalk(localDir); err != nil {
		return err
	}
	if err := remoteMkdir(c, v, remoteDir, dirMode); err != nil {
		return err
	}
	return uploadDirWalk(c, v, localDir, remoteDir, dirMode)
}

func remoteMkdir(c config.Connection, v *config.Vault, remoteDir string, dirMode os.FileMode) error {
	client, err := dialSSH(c, v)
	if err != nil {
		return err
	}
	defer releaseClient(client, false)
	session, err := newSessionRetry(client)
	if err != nil {
		return ClassifyError(err, c)
	}
	defer func() { _ = session.Close() }()
	var stderr boundedBuffer
	session.Stderr = &stderr
	if err := session.Run(remoteDirCreateCommand(remoteDir, dirMode)); err != nil {
		var exitErr *gossh.ExitError
		if !errors.As(err, &exitErr) {
			return err
		}
		message := stderr.String()
		if message == "" {
			message = err.Error()
		}
		return transferKindError(machinecontract.TransferRemotePermissionsFailed, 0, errors.New(message))
	}
	return nil
}

// downloadEnd names the end of a directory download that failed first.
type downloadEnd int

const (
	downloadEndNone downloadEnd = iota
	downloadEndRemote
	downloadEndLocal
)

// downloadRemoteGrace is how long a failed local extractor waits for the
// remote tar to report its own exit status before the remote is closed.
const downloadRemoteGrace = 2 * time.Second

// superviseDirectoryDownload waits for both ends of a directory download
// concurrently and returns in bounded time. When one end fails, the other is
// closed or killed. It reports which end is the root cause:
//   - a remote session that exits non-zero (an *ssh.ExitError) always wins,
//     because the local tar then only sees a truncated stream (unexpected EOF);
//     a failed local end therefore waits up to grace for the remote's exit
//     status before closing the remote;
//   - otherwise whichever end failed first.
func superviseDirectoryDownload(waitRemote, waitLocal func() error, closeRemote, killLocal func(), grace time.Duration) (first downloadEnd, remoteErr, localErr error) {
	remoteCh := make(chan error, 1)
	localCh := make(chan error, 1)
	go func() { remoteCh <- waitRemote() }()
	go func() { localCh <- waitLocal() }()
	select {
	case remoteErr = <-remoteCh:
		if remoteErr != nil {
			first = downloadEndRemote
			killLocal()
		}
		localErr = <-localCh
		if first == downloadEndNone && localErr != nil {
			first = downloadEndLocal
		}
	case localErr = <-localCh:
		if localErr == nil {
			remoteErr = <-remoteCh
			if remoteErr != nil {
				first = downloadEndRemote
			}
			break
		}
		timer := time.NewTimer(grace)
		select {
		case remoteErr = <-remoteCh:
			timer.Stop()
		case <-timer.C:
			closeRemote()
			remoteErr = <-remoteCh
		}
		var exitErr *gossh.ExitError
		if errors.As(remoteErr, &exitErr) {
			first = downloadEndRemote
		} else {
			first = downloadEndLocal
		}
	}
	return first, remoteErr, localErr
}

func rejectSpecialEntries(root string) error {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = rootFS.Close() }()
	return fs.WalkDir(rootFS.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := rootFS.Lstat(path)
		if err != nil {
			return err
		}
		mode := info.Mode()
		switch {
		case mode.IsRegular():
			if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
				if err := rootFS.Chmod(path, mode.Perm()); err != nil {
					return err
				}
			}
		case mode.IsDir(), mode&os.ModeSymlink != 0:
		default:
			return fmt.Errorf("download contains unsupported special file %s", filepath.Join(root, filepath.FromSlash(path)))
		}
		return nil
	})
}

func downloadDirTar(c config.Connection, v *config.Vault, remoteDir, localDir string, timeout time.Duration) (resultErr error) {
	staging, err := newDirectoryDownloadStaging(localDir)
	if err != nil {
		return err
	}
	defer staging.cleanup()
	client, err := dialSSH(c, v)
	if err != nil {
		return err
	}
	defer releaseClient(client, false)

	session, err := newSessionRetry(client)
	if err != nil {
		return ClassifyError(err, c)
	}
	defer func() { _ = session.Close() }()

	tarArgs := []string{"-C", staging.path}
	if runtime.GOOS == "linux" {
		tarArgs = append(tarArgs, "--no-same-owner", "--no-same-permissions")
	}
	tarArgs = append(tarArgs, "-xf", "-")
	tarLocal := exec.Command("tar", tarArgs...) //nolint:gosec // fixed binary/argv; staging is created internally with os.MkdirTemp
	// If the local tar exits early nobody drains the pipe copy; bound the
	// post-exit I/O wait so Wait cannot block on an idle remote.
	tarLocal.WaitDelay = time.Second
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderrSpool, err := machinecontract.NewDiagnosticSpool(os.Stderr)
	if err != nil {
		return err
	}
	defer func() { _ = stderrSpool.Close() }()
	session.Stderr = stderrSpool
	tarLocal.Stdin = stdout
	stdoutSpool, err := machinecontract.NewDiagnosticSpool(os.Stdout)
	if err != nil {
		return errors.Join(err, stderrSpool.Close())
	}
	defer func() { _ = stdoutSpool.Close() }()
	diagnostics := []*machinecontract.DiagnosticSpool{stdoutSpool, stderrSpool}
	diagnosticsSucceeded := false
	defer func() {
		if replayErr := replayDiagnosticSpools(diagnosticsSucceeded, diagnostics...); resultErr == nil {
			resultErr = replayErr
		}
	}()
	tarLocal.Stdout = stdoutSpool
	tarLocal.Stderr = stderrSpool

	remoteCmd := fmt.Sprintf("tar -C %s -cf - .", ShellQuote(remoteDir))
	if err := session.Start(remoteCmd); err != nil {
		return err
	}
	interrupt := watchRunInterrupt(session)
	if err := tarLocal.Start(); err != nil {
		interrupt.stop()
		_ = session.Close()
		return transferError(machinecontract.TransferDownloadLocalWrite, 0, fmt.Errorf("local tar: %w", err))
	}
	var timedOut atomic.Bool
	if timeout > 0 {
		timer := time.AfterFunc(timeout, func() {
			timedOut.Store(true)
			_ = session.Close()
			_ = tarLocal.Process.Kill()
		})
		defer timer.Stop()
	}
	first, remoteErr, localErr := superviseDirectoryDownload(
		session.Wait,
		func() error {
			err := tarLocal.Wait()
			// tar may exit 0 at the archive end marker while the stdin copy
			// still holds unread trailing padding from the remote; that is
			// not a failure.
			if errors.Is(err, exec.ErrWaitDelay) && tarLocal.ProcessState != nil && tarLocal.ProcessState.Success() {
				return nil
			}
			return err
		},
		func() { _ = session.Close() },
		func() { _ = tarLocal.Process.Kill() },
		downloadRemoteGrace,
	)
	interrupt.stop()
	if signalExit, interrupted := interrupt.result(); interrupted {
		failure := machinecontract.Classify(machinecontract.RunInterrupted, machinecontract.Details{
			Message: fmt.Sprintf("interrupted by local signal; exit %d", signalExit),
			Exit:    signalExit,
		})
		return transferClassifiedError(failure, 0, machinecontract.NewClassifiedError(failure))
	}
	switch {
	case first != downloadEndNone && timedOut.Load():
		// A deadline that fires after both ends already finished cleanly is
		// ignored: only a failure that coincides with it is a timeout.
		return transferError(machinecontract.TransferTimedOut, 0, fmt.Errorf("directory download exceeded %s", timeout))
	case first == downloadEndLocal:
		return transferError(machinecontract.TransferDownloadLocalWrite, 0, localErr)
	case first == downloadEndRemote:
		return transferError(machinecontract.TransferDownloadRemoteRead, 0, remoteErr)
	}
	if err := rejectSpecialEntries(staging.path); err != nil {
		return transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
	}
	if staging.destinationExists {
		if err := restoreDirectoryModes(staging.destinationPath, staging.path); err != nil {
			return transferError(machinecontract.TransferDownloadLocalWrite, 0, fmt.Errorf("preserve local directory modes: %w", err))
		}
	}
	if err := staging.publish(localDir, systemDirectoryDownloadPublishOperations()); err != nil {
		return err
	}
	diagnosticsSucceeded = true
	return nil
}

func uploadDirWalk(c config.Connection, v *config.Vault, localDir, remoteDir string, dirMode os.FileMode) error {
	return filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		// remote always uses forward slashes
		rel = filepath.ToSlash(rel)
		remote := strings.TrimRight(remoteDir, "/") + "/" + rel
		_, err = UploadFileWithOptions(c, v, path, remote, UploadOptions{DirMode: dirMode})
		return err
	})
}

// validateUploadDirWalk ensures the pure-Go fallback can represent every
// entry in the source tree. It only uploads regular files and cannot create
// empty directories or preserve non-regular entries, so those cases fail
// closed instead of being reported as a successful partial transfer.
func validateUploadDirWalk(localDir string) error {
	dirsWithEntries := map[string]bool{}
	if err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			dirsWithEntries[path] = false
			if path != localDir {
				dirsWithEntries[filepath.Dir(path)] = true
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("directory fallback cannot preserve non-regular entry %s", path)
		}
		dirsWithEntries[filepath.Dir(path)] = true
		return nil
	}); err != nil {
		return err
	}
	for path, hasEntries := range dirsWithEntries {
		// The caller creates remoteDir before invoking the fallback, so an
		// otherwise empty source root is already representable.
		if path != localDir && !hasEntries {
			return fmt.Errorf("directory fallback cannot preserve empty directory %s", path)
		}
	}
	return nil
}

// LocalTreeFiles lists relative slash-paths of regular files under dir (tests).
func LocalTreeFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}

func replayDiagnosticSpools(success bool, spools ...*machinecontract.DiagnosticSpool) error {
	var result error
	for _, spool := range spools {
		result = errors.Join(result, spool.Replay(success))
	}
	return result
}

// Ensure no unused import if tar path always works — io used? remove if unused
var _ = io.Discard
