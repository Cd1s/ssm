package ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

type UploadOptions struct {
	VerifySHA256  bool
	Timeout       time.Duration
	ResumeVersion string
	// DirMode is the permission for parent directories created by a put.
	// Zero selects DefaultUploadDirMode.
	DirMode os.FileMode
}

// DefaultUploadDirMode is the permission of parent directories that put
// creates automatically. Uploaded files keep their private temp-file + rename
// flow and their own mode.
const DefaultUploadDirMode os.FileMode = 0o755

func (o UploadOptions) dirMode() os.FileMode {
	if o.DirMode == 0 {
		return DefaultUploadDirMode
	}
	return o.DirMode.Perm()
}

type TransferResult struct {
	OK            bool   `json:"ok"`
	Direction     string `json:"direction,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Stage         string `json:"stage"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received,omitempty"`
	Integrity     string `json:"integrity"`
	LocalSHA256   string `json:"local_sha256,omitempty"`
	RemoteSHA256  string `json:"remote_sha256,omitempty"`
	Atomic        bool   `json:"atomic"`
	Resume        string `json:"resume"`
	BytesReused   int64  `json:"bytes_reused,omitempty"`
}

type TransferError struct {
	failure   machinecontract.Failure
	BytesSent int64
	Cause     error
}

func (e *TransferError) Error() string { return e.Cause.Error() }
func (e *TransferError) Unwrap() error { return e.Cause }
func (e *TransferError) ContractFailure() machinecontract.Failure {
	return e.failure
}

func UploadFile(c config.Connection, v *config.Vault, localPath, remotePath string) error {
	_, err := UploadFileWithOptions(c, v, localPath, remotePath, UploadOptions{})
	return err
}

func UploadFileWithOptions(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	if opts.ResumeVersion != "" {
		return uploadFileResumable(c, v, localPath, remotePath, opts)
	}
	result := TransferResult{Stage: "local_read", Integrity: "not_checked", Atomic: true, Resume: "unsupported"}
	f, err := os.Open(localPath)
	if err != nil {
		return result, transferError(machinecontract.TransferLocalRead, 0, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return result, transferError(machinecontract.TransferLocalFileStat, 0, err)
	}
	if !info.Mode().IsRegular() {
		return result, transferError(machinecontract.TransferRegularFileRequired, 0, fmt.Errorf("%s is not a regular file", localPath))
	}

	localDigest := ""
	if opts.VerifySHA256 {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return result, transferError(machinecontract.TransferIntegritySourceRead, 0, err)
		}
		localDigest = hex.EncodeToString(h.Sum(nil))
		result.LocalSHA256 = localDigest
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return result, transferError(machinecontract.TransferSeekableSourceRequired, 0, err)
		}
	}

	result.Stage = "dial"
	client, err := dialSSH(c, v)
	if err != nil {
		classified := ClassifyError(err, c)
		return result, transferClassifiedError(classified.Failure, 0, classified)
	}
	defer releaseClient(client, false)

	session, err := newSessionRetry(client)
	if err != nil {
		return result, transferError(machinecontract.TransferSessionOpenFailed, 0, err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return result, transferError(machinecontract.TransferStdinOpenFailed, 0, err)
	}
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	cmd := uploadCommandWithIntegrity(remotePath, info.Mode(), info.Size(), localDigest, opts.dirMode())
	if err := session.Start(cmd); err != nil {
		if isExecRefused(err) {
			// No exec at all (for example an SFTP-only account).
			return result, remoteShellUnsupportedError("", err)
		}
		return result, transferError(machinecontract.TransferStartFailed, 0, err)
	}
	var timedOut atomic.Bool
	var timer *time.Timer
	if opts.Timeout > 0 {
		timer = time.AfterFunc(opts.Timeout, func() {
			timedOut.Store(true)
			_ = session.Close()
		})
		defer timer.Stop()
	}
	result.Stage = "remote_write"
	written, copyErr := io.Copy(stdin, f)
	result.BytesSent = written
	if copyErr != nil {
		_ = stdin.Close()
		return result, collectRemoteFirst(session, remoteExitGrace, &result, written, &timedOut, &stdout, copyErr, machinecontract.TransferRemoteWriteFailed)
	}
	if err := stdin.Close(); err != nil {
		// The remote may already have exited (for example because it has no
		// SHA-256 tool), so Close can fail after every byte was written.
		return result, collectRemoteFirst(session, remoteExitGrace, &result, written, &timedOut, &stdout, err, machinecontract.TransferRemoteCloseFailed)
	}
	if err := session.Wait(); err != nil {
		if timedOut.Load() {
			return result, transferError(machinecontract.TransferTimedOut, written, err)
		}
		if strings.Contains(stdout.String(), integrityToolMissingMarker) {
			result.Stage = "capability"
			return result, transferKindError(machinecontract.IntegrityToolUnavailable, written, errors.New(remoteSHA256UnavailableMessage))
		}
		if strings.Contains(stdout.String(), "SSM_INTEGRITY_MISMATCH") {
			result.Stage = "integrity"
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferIntegrityMismatch, written, errors.New("remote integrity verification failed"))
		}
		message := strings.TrimSpace(stderr.String())
		var remoteExit *gossh.ExitError
		if message == "" && !errors.As(err, &remoteExit) {
			// No exit status and no remote diagnostic: the session ended
			// without the remote command reporting anything, which is a
			// transport failure, not a remote permissions problem.
			return result, transferError(machinecontract.TransferRemoteWriteFailed, written, err)
		}
		if message == "" {
			message = err.Error()
		}
		if strings.Contains(message, "remote destination") && strings.Contains(message, "is a directory") {
			return result, transferError(machinecontract.TransferRemoteWriteFailed, written, errors.New(message))
		}
		return result, transferError(machinecontract.TransferRemotePermissionsFailed, written, errors.New(message))
	}
	remoteSize, remoteDigest, err := parseUploadReceipt(stdout.String())
	if err != nil || remoteSize != info.Size() || (opts.VerifySHA256 && remoteDigest != localDigest) {
		result.Stage = "integrity"
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferReceiptInvalid, written, errors.New("invalid remote integrity receipt"))
	}
	result.OK = true
	result.Stage = "complete"
	result.RemoteSHA256 = remoteDigest
	if opts.VerifySHA256 {
		result.Integrity = "sha256_verified"
	} else {
		result.Integrity = "size_verified"
	}
	return result, nil
}

// collectRemoteFirst is used when writing to or closing the upload stdin
// failed. A remote that exits before reading its input closes the channel
// under the writer, so its exit status and marker output are the first-hand
// reason and win over the local write or close error. Only when the remote
// reported nothing does the generic fallback kind apply.
func collectRemoteFirst(session sessionWaiter, grace time.Duration, result *TransferResult, written int64, timedOut *atomic.Bool, stdout *bytes.Buffer, cause error, fallback machinecontract.Kind) *TransferError {
	waitErr := waitSessionBounded(session, grace)
	_ = session.Close()
	// Read after the wait: the --timeout timer may fire during the grace.
	if timedOut.Load() {
		return transferError(machinecontract.TransferTimedOut, written, cause)
	}
	if waitErr != nil {
		output := stdout.String()
		if strings.Contains(output, integrityToolMissingMarker) {
			result.Stage = "capability"
			return transferKindError(machinecontract.IntegrityToolUnavailable, written, errors.New(remoteSHA256UnavailableMessage))
		}
		if strings.Contains(output, "SSM_INTEGRITY_MISMATCH") {
			result.Stage = "integrity"
			result.Integrity = "mismatch"
			return transferError(machinecontract.TransferIntegrityMismatch, written, errors.New("remote integrity verification failed"))
		}
	}
	return transferError(fallback, written, cause)
}

func transferError(kind machinecontract.Kind, bytesSent int64, cause error) *TransferError {
	return transferClassifiedError(machinecontract.Classify(kind, machinecontract.Details{Cause: cause}), bytesSent, cause)
}

// transferKindError is transferError for failures whose free-form message must
// not influence the process exit code: the exit comes from the contract, not
// from keywords (such as "permission denied") in remote text.
func transferKindError(kind machinecontract.Kind, bytesSent int64, cause error) *TransferError {
	failure := machinecontract.Classify(kind, machinecontract.Details{Cause: cause})
	return transferClassifiedError(failure, bytesSent, machinecontract.NewClassifiedError(failure))
}

func transferClassifiedError(failure machinecontract.Failure, bytesSent int64, cause error) *TransferError {
	return &TransferError{failure: failure, BytesSent: bytesSent, Cause: cause}
}

// DownloadFile copies remotePath from the server to localPath.
// Parent directories of localPath are created as needed.
func DownloadFile(c config.Connection, v *config.Vault, remotePath, localPath string) (TransferResult, error) {
	return downloadFileWithOptions(c, v, remotePath, localPath, DownloadOptions{})
}

func downloadFileWithOptions(c config.Connection, v *config.Vault, remotePath, localPath string, opts DownloadOptions) (result TransferResult, resultErr error) {
	result = TransferResult{Direction: "get", Kind: "file", Stage: "local_write", Integrity: "not_checked", Atomic: true, Resume: "unsupported"}
	staging, err := newFileDownloadStaging(localPath)
	if err != nil {
		return result, err
	}
	defer staging.cleanup()

	client, err := dialSSH(c, v)
	if err != nil {
		result.Stage = "dial"
		return result, err
	}
	defer releaseClient(client, false)

	var timedOut atomic.Bool
	var active sessionSet
	if opts.Timeout > 0 {
		// One deadline covers the digest probe and the download.
		deadline := time.AfterFunc(opts.Timeout, func() {
			timedOut.Store(true)
			active.closeAll()
		})
		defer deadline.Stop()
	}
	remoteDigest := ""
	if opts.VerifySHA256 {
		result.Stage = "integrity"
		remoteDigest, err = remoteFileSHA256(client, remotePath, &active)
		if err != nil {
			if timedOut.Load() {
				return result, transferError(machinecontract.TransferTimedOut, 0, err)
			}
			return result, err
		}
		result.RemoteSHA256 = remoteDigest
	}

	session, err := newSessionRetry(client)
	if err != nil {
		result.Stage = "session"
		return result, ClassifyError(err, c)
	}
	defer func() { _ = session.Close() }()
	active.add(session)

	session.Stdout = staging.file
	sessionStderr, err := machinecontract.NewDiagnosticSpool(os.Stderr)
	if err != nil {
		return result, err
	}
	defer func() { _ = sessionStderr.Close() }()
	diagnosticsSucceeded := false
	defer func() {
		if replayErr := sessionStderr.Replay(diagnosticsSucceeded); resultErr == nil {
			resultErr = replayErr
		}
	}()
	session.Stderr = sessionStderr

	cmd := downloadCommand(remotePath)
	result.Stage = "remote_read"
	if err := session.Run(cmd); err != nil {
		if timedOut.Load() {
			result.Stage = "timeout"
			return result, transferError(machinecontract.TransferTimedOut, 0, err)
		}
		return result, transferError(machinecontract.TransferDownloadRemoteRead, 0, err)
	}
	if opts.VerifySHA256 {
		localDigest, err := fileSHA256(staging.path)
		if err != nil {
			return result, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
		}
		result.LocalSHA256 = localDigest
		if localDigest != remoteDigest {
			result.Stage = "integrity"
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferDownloadIntegrityMismatch, 0, errors.New("downloaded file SHA-256 does not match the remote digest"))
		}
	}
	result.BytesReceived, err = staging.publish(localPath, systemFileDownloadPublishOperations())
	if err != nil {
		if failure, ok := machinecontract.FailureFromError(err); ok {
			result.Stage = failure.Stage
		}
		return result, err
	}
	diagnosticsSucceeded = true
	result.OK = true
	result.Stage = "complete"
	if opts.VerifySHA256 {
		result.Integrity = "sha256_verified"
	}
	return result, nil
}

// sessionSet lets one timer close every SSH session of a multi-step transfer.
type sessionSet struct {
	mu       sync.Mutex
	sessions []*gossh.Session
	closed   bool
}

func (s *sessionSet) add(session *gossh.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = session.Close()
		return
	}
	s.sessions = append(s.sessions, session)
}

func (s *sessionSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, session := range s.sessions {
		_ = session.Close()
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is the internally created download staging file
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// remoteFileSHA256 asks the remote host for the SHA-256 of a regular file using
// the shared sha256sum -> shasum -> openssl probe.
func remoteFileSHA256(client *gossh.Client, remotePath string, active *sessionSet) (string, error) {
	session, err := newSessionRetry(client)
	if err != nil {
		return "", transferError(machinecontract.TransferSessionOpenFailed, 0, err)
	}
	active.add(session)
	defer func() { _ = session.Close() }()
	var stdout, stderr bytes.Buffer
	session.Stdout, session.Stderr = &stdout, &stderr
	command := remoteSHA256Helpers + "ssm_sha256_tool >/dev/null || { echo " + integrityToolMissingMarker + "; exit 69; }; " +
		"[ -f " + ShellQuote(remotePath) + " ] || { echo 'not a regular file' >&2; exit 66; }; ssm_sha256 " + ShellQuote(remotePath)
	if err := session.Run(command); err != nil {
		if strings.Contains(stdout.String(), integrityToolMissingMarker) {
			return "", transferKindError(machinecontract.IntegrityToolUnavailable, 0, errors.New(remoteSHA256UnavailableMessage))
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", transferError(machinecontract.TransferDownloadRemoteRead, 0, errors.New(message))
	}
	digest := strings.ToLower(strings.TrimSpace(stdout.String()))
	if len(digest) != 64 {
		return "", transferError(machinecontract.TransferDownloadRemoteRead, 0, errors.New("remote returned an invalid SHA-256 digest"))
	}
	return digest, nil
}

func uploadCommand(remotePath string, mode os.FileMode) string {
	return uploadCommandWithIntegrity(remotePath, mode, -1, "", DefaultUploadDirMode)
}

// integrityToolMissingMarker is printed on stdout when the remote host has no
// SHA-256 tool, before any payload is consumed.
const integrityToolMissingMarker = "SSM_INTEGRITY_TOOL_MISSING"

const remoteSHA256UnavailableMessage = "remote host has none of sha256sum, shasum, or openssl"

// remoteSHA256Helpers defines POSIX sh functions shared by put --sha256 and
// resume. The probe order is sha256sum, shasum -a 256, openssl dgst -sha256.
// Input is read from stdin so file names never reach the tool's option parser.
const remoteSHA256Helpers = "ssm_sha256_tool() { if command -v sha256sum >/dev/null 2>&1; then echo sha256sum; " +
	"elif command -v shasum >/dev/null 2>&1; then echo shasum; " +
	"elif command -v openssl >/dev/null 2>&1; then echo openssl; else return 1; fi; }; " +
	"ssm_sha256() { case \"$(ssm_sha256_tool)\" in " +
	"sha256sum) sha256sum < \"$1\" | awk '{print $1}';; " +
	"shasum) shasum -a 256 < \"$1\" | awk '{print $1}';; " +
	"openssl) openssl dgst -sha256 < \"$1\" | awk '{print $NF}';; " +
	"*) return 127;; esac; }; "

// remoteMkdirParents creates dir (and missing ancestors) with permission mode
// regardless of the remote login umask. Existing directories are untouched.
func remoteMkdirParents(dir string, mode os.FileMode) string {
	return fmt.Sprintf("(umask %03o; mkdir -p -- %s)", uint32(0o777&^mode.Perm()), ShellQuote(dir))
}

func uploadCommandWithIntegrity(remotePath string, mode os.FileMode, size int64, digest string, dirMode os.FileMode) string {
	if strings.HasPrefix(remotePath, "-") {
		// A relative path beginning with '-' must not be parsed as an option
		// by mkdir, chmod, or mv.
		remotePath = "./" + remotePath
	}
	quotedPath := ShellQuote(remotePath)
	parent := RemoteParentDir(remotePath)
	prefix := "umask 077; "
	if digest != "" {
		prefix += remoteSHA256Helpers + "ssm_sha256_tool >/dev/null || { echo " + integrityToolMissingMarker + "; exit 69; }; "
	}
	if parent != "" {
		prefix += remoteMkdirParents(parent, dirMode) + " && "
	}
	// Stream into a sibling temporary file and rename only after the complete
	// payload and mode have been written. A failed transfer leaves the previous
	// destination intact and the trap removes the partial upload.
	checks := "actual_size=$(wc -c < \"$tmp\" | tr -d ' ') || exit 74; "
	if size >= 0 {
		checks += fmt.Sprintf("[ \"$actual_size\" = %d ] || { echo SSM_INTEGRITY_MISMATCH; exit 65; }; ", size)
	}
	if digest != "" {
		checks += fmt.Sprintf("actual_sha=$(ssm_sha256 \"$tmp\") || exit 74; [ \"$actual_sha\" = %s ] || { echo SSM_INTEGRITY_MISMATCH; exit 65; }; ", ShellQuote(digest))
	} else {
		checks += "actual_sha=-; "
	}
	return fmt.Sprintf("%stmp=%s.ssm-upload.$$; trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; cat > \"$tmp\" && chmod %04o \"$tmp\" || exit $?; %s[ -d %s ] && { rm -f -- \"$tmp\"; echo \"remote destination %s is a directory\" >&2; exit 73; }; mv -f -- \"$tmp\" %s && trap - EXIT HUP INT TERM && printf 'SSM_TRANSFER %%s %%s\\n' \"$actual_size\" \"$actual_sha\"", prefix, quotedPath, uint32(mode.Perm()), checks, quotedPath, quotedPath, quotedPath)
}

func parseUploadReceipt(output string) (int64, string, error) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) != 3 || fields[0] != "SSM_TRANSFER" {
		return 0, "", fmt.Errorf("missing upload receipt")
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, "", err
	}
	digest := fields[2]
	if digest == "-" {
		digest = ""
	}
	return size, digest, nil
}

func downloadCommand(remotePath string) string {
	// cat is enough for regular files; fail clearly on missing paths.
	return "cat -- " + ShellQuote(remotePath)
}
