package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func UploadPathWithOptions(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
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

	session, err := client.NewSession()
	if err != nil {
		return false, err
	}
	defer func() { _ = session.Close() }()

	cmd := fmt.Sprintf("if [ -d %s ]; then echo DIR; elif [ -f %s ]; then echo FILE; else echo MISSING; fi",
		ShellQuote(remotePath), ShellQuote(remotePath))
	out, err := session.CombinedOutput(cmd)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(out)) {
	case "DIR":
		return true, nil
	case "FILE":
		return false, nil
	default:
		return false, fmt.Errorf("remote path %s not found", remotePath)
	}
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

func remoteDirCreateCommand(remoteDir string, dirMode os.FileMode) string {
	if dirMode == 0 {
		return "mkdir -p " + ShellQuote(remoteDir)
	}
	return remoteMkdirParents(remoteDir, dirMode)
}

func uploadDirTarStream(c config.Connection, v *config.Vault, tarPath, localDir, remoteDir string, dirMode os.FileMode) (resultErr error) {
	client, err := dialSSH(c, v)
	if err != nil {
		return err
	}
	defer releaseClient(client, false)

	session, err := client.NewSession()
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
	tarCmd.Stdout = stdin
	tarCmd.Stderr = &tarDiagnostics
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
	tarErr := tarCmd.Wait()
	_ = stdin.Close()
	if tarErr != nil {
		// A remote failure (permissions, disk full, target not a directory)
		// makes the local tar die with EPIPE. Report the remote first-hand
		// error instead of masking it with a fallback.
		remoteErr := waitSessionBounded(session, remoteExitGrace)
		var exitErr *gossh.ExitError
		localMessage := strings.TrimSpace(tarDiagnostics.String())
		switch {
		case errors.As(remoteErr, &exitErr) && (localMessage == "" || looksLikeBrokenPipe(localMessage)):
			_ = stderrSpool.Close()
			return remoteExtractError(remoteStderr.String(), remoteErr)
		case remoteErr != nil && !errors.As(remoteErr, &exitErr):
			return remoteErr
		default:
			message := fmt.Sprintf("local tar failed: %v", tarErr)
			if localMessage != "" {
				message += ": " + localMessage
			}
			message += "; the remote destination may contain partially extracted files"
			return transferKindError(machinecontract.TransferLocalRead, 0, errors.New(message))
		}
	}
	if _, err := stderrSpool.Write(tarDiagnostics.Bytes()); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	if remoteErr := session.Wait(); remoteErr != nil {
		var exitErr *gossh.ExitError
		if errors.As(remoteErr, &exitErr) {
			_ = stderrSpool.Close()
			return remoteExtractError(remoteStderr.String(), remoteErr)
		}
		return remoteErr
	}
	diagnosticsSucceeded = true
	return nil
}

// remoteExitGrace bounds how long we wait for the remote extractor's exit
// status after the local tar has already ended.
const remoteExitGrace = 15 * time.Second

func waitSessionBounded(session *gossh.Session, grace time.Duration) error {
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

func looksLikeBrokenPipe(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "broken pipe") || strings.Contains(lower, "write error") ||
		strings.Contains(lower, "cannot write") || strings.Contains(lower, "not recoverable")
}

func remoteExtractError(stderr string, remoteErr error) error {
	message := stderr
	if message == "" {
		message = remoteErr.Error()
	}
	// A plain error (not *gossh.ExitError) keeps the process exit code at the
	// contract's value instead of the remote's status.
	return transferKindError(machinecontract.TransferRemoteExtractFailed, 0, fmt.Errorf("remote tar extraction failed: %s", message))
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
	session, err := client.NewSession()
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

// superviseDirectoryDownload waits for both ends of a directory download
// concurrently. As soon as one end fails, the other is closed or killed so the
// call returns in bounded time instead of hanging on a peer that no longer
// reads or writes. It reports which end failed first, because the other end's
// error is then only a consequence.
func superviseDirectoryDownload(waitRemote, waitLocal func() error, closeRemote, killLocal func()) (first downloadEnd, remoteErr, localErr error) {
	type outcome struct {
		end downloadEnd
		err error
	}
	results := make(chan outcome, 2)
	go func() { results <- outcome{end: downloadEndRemote, err: waitRemote()} }()
	go func() { results <- outcome{end: downloadEndLocal, err: waitLocal()} }()
	for received := 0; received < 2; received++ {
		res := <-results
		if res.err != nil && first == downloadEndNone {
			first = res.end
			if res.end == downloadEndRemote {
				killLocal()
			} else {
				closeRemote()
			}
		}
		if res.end == downloadEndRemote {
			remoteErr = res.err
		} else {
			localErr = res.err
		}
	}
	return first, remoteErr, localErr
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

	session, err := client.NewSession()
	if err != nil {
		return ClassifyError(err, c)
	}
	defer func() { _ = session.Close() }()

	tarLocal := exec.Command("tar", "-C", staging.path, "-xf", "-") //nolint:gosec // fixed binary/argv; staging is created internally with os.MkdirTemp
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
	if err := tarLocal.Start(); err != nil {
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
		tarLocal.Wait,
		func() { _ = session.Close() },
		func() { _ = tarLocal.Process.Kill() },
	)
	switch {
	case timedOut.Load():
		return transferError(machinecontract.TransferTimedOut, 0, fmt.Errorf("directory download exceeded %s", timeout))
	case first == downloadEndLocal:
		return transferError(machinecontract.TransferDownloadLocalWrite, 0, localErr)
	case first == downloadEndRemote:
		return transferError(machinecontract.TransferDownloadRemoteRead, 0, remoteErr)
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
