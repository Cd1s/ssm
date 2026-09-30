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
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// CopyOptions controls a host-to-host copy.
type CopyOptions struct {
	// Timeout, when positive, bounds the transfer (digest probe and stream)
	// after both hosts are connected; connecting is bounded by the connect
	// timeout.
	Timeout time.Duration
}

// CopyResult is the outcome of CopyFile. The digests are the source host's
// digest of the file before streaming, the digest of the bytes relayed
// through the local machine, and the digest the destination host computed
// over its temporary file before publishing it.
type CopyResult struct {
	OK                bool
	Stage             string
	Bytes             int64
	Integrity         string
	SourceSHA256      string
	LocalSHA256       string
	DestinationSHA256 string
	Atomic            bool
}

// CopyFile streams one regular file from srcPath on src to dstPath on dst
// through this machine (issue #86). Bytes are read with the get path (cat over
// an SSH session) and written with the put path's temporary-file-plus-rename
// script, so the destination never holds a partial file. Nothing is written to
// the local disk: the relay is an in-memory pipe that is hashed on the way.
//
// The destination script refuses to publish unless the digest of its temporary
// file equals the source host's digest, and success is reported only when the
// source digest, the locally computed digest and the destination digest all
// agree. Both hosts need a POSIX shell and a SHA-256 tool.
func CopyFile(src config.Connection, srcPath string, dst config.Connection, dstPath string, v *config.Vault, opts CopyOptions) (CopyResult, error) {
	result := CopyResult{Stage: "validate", Integrity: "not_checked", Atomic: true}
	if src.UsesSFTP() || dst.UsesSFTP() {
		return result, transferKindError(machinecontract.TransferSFTPUnsupported, 0,
			errors.New("cp needs a POSIX shell on both hosts; hosts with transfer: sftp are not supported (use get and put)"))
	}

	result.Stage = "discovery"
	isDir, err := remoteIsDir(src, v, srcPath)
	if err != nil {
		return result, copySourceError(err)
	}
	if isDir {
		return result, transferKindError(machinecontract.CopyDirectoryUnsupported, 0,
			fmt.Errorf("%s is a directory; cp copies single regular files only", srcPath))
	}

	result.Stage = "dial"
	clientSrc, err := dialSSH(src, v)
	if err != nil {
		return result, copySourceError(err)
	}
	defer releaseClient(clientSrc, false)
	clientDst, err := dialSSH(dst, v)
	if err != nil {
		return result, copyDestinationError(err)
	}
	defer releaseClient(clientDst, false)

	var timedOut atomic.Bool
	var active sessionSet
	if opts.Timeout > 0 {
		deadline := time.AfterFunc(opts.Timeout, func() {
			timedOut.Store(true)
			active.closeAll()
		})
		defer deadline.Stop()
	}
	timeoutOr := func(err error) error {
		if timedOut.Load() {
			result.Stage = "timeout"
			return transferError(machinecontract.TransferTimedOut, result.Bytes, err)
		}
		return err
	}

	result.Stage = "integrity"
	sourceDigest, err := remoteFileSHA256(clientSrc, srcPath, &active)
	if err != nil {
		return result, timeoutOr(err)
	}
	result.SourceSHA256 = sourceDigest
	mode := remoteFileMode(clientSrc, srcPath, &active)

	sessionSrc, err := newSessionRetry(clientSrc)
	if err != nil {
		result.Stage = "session"
		return result, ClassifyError(err, src)
	}
	defer func() { _ = sessionSrc.Close() }()
	active.add(sessionSrc)
	sessionDst, err := newSessionRetry(clientDst)
	if err != nil {
		result.Stage = "session"
		return result, ClassifyError(err, dst)
	}
	defer func() { _ = sessionDst.Close() }()
	active.add(sessionDst)

	sourceOut, err := sessionSrc.StdoutPipe()
	if err != nil {
		return result, transferError(machinecontract.TransferDownloadRemoteRead, 0, err)
	}
	var sourceErr boundedBuffer
	sessionSrc.Stderr = &sourceErr
	destIn, err := sessionDst.StdinPipe()
	if err != nil {
		return result, transferError(machinecontract.TransferStdinOpenFailed, 0, err)
	}
	var destOut bytes.Buffer
	var destErr boundedBuffer
	sessionDst.Stdout = &destOut
	sessionDst.Stderr = &destErr

	// The destination verifies the digest of its temporary file before the
	// rename; a size is not known yet, the local byte count is checked below.
	result.Stage = "remote_write"
	if err := sessionDst.Start(uploadCommandWithIntegrity(dstPath, mode, -1, sourceDigest, DefaultUploadDirMode)); err != nil {
		if isExecRefused(err) {
			return result, remoteShellUnsupportedError("", err)
		}
		return result, timeoutOr(transferError(machinecontract.TransferStartFailed, 0, err))
	}
	if err := sessionSrc.Start(downloadCommand(srcPath)); err != nil {
		_ = sessionDst.Close()
		if isExecRefused(err) {
			return result, remoteShellUnsupportedError("", err)
		}
		return result, timeoutOr(transferError(machinecontract.TransferDownloadRemoteRead, 0, err))
	}

	hasher := sha256.New()
	relay := &copyRelay{destination: destIn, hasher: hasher}
	_, copyErr := io.Copy(relay, sourceOut)
	if copyErr != nil {
		// Unblock the source command, which may be stuck writing to a pipe
		// nobody reads any more.
		_ = sessionSrc.Close()
	}
	result.Bytes = relay.written
	sourceWaitErr := sessionSrc.Wait()
	if copyErr == nil && sourceWaitErr == nil {
		// The relayed digest only means something for a completed stream.
		result.LocalSHA256 = hex.EncodeToString(hasher.Sum(nil))
	}

	if copyErr != nil || sourceWaitErr != nil {
		// Never let the destination see a clean EOF for a stream that did not
		// end cleanly; the digest check would refuse it anyway, but closing the
		// session makes the remote trap remove the temporary file at once.
		_ = sessionDst.Close()
		if relay.err != nil {
			// The destination stopped accepting bytes: its own exit status and
			// diagnostics are the first-hand reason.
			return result, timeoutOr(collectRemoteFirst(sessionDst, remoteExitGrace, &TransferResult{}, relay.written, &timedOut, &destOut, relay.err, machinecontract.TransferRemoteWriteFailed))
		}
		cause := copyErr
		if cause == nil {
			cause = sourceWaitErr
		}
		message := sourceErr.String()
		if message == "" {
			message = cause.Error()
		}
		result.Stage = "remote_read"
		return result, timeoutOr(transferError(machinecontract.TransferDownloadRemoteRead, result.Bytes, errors.New(message)))
	}
	if err := destIn.Close(); err != nil {
		return result, timeoutOr(collectRemoteFirst(sessionDst, remoteExitGrace, &TransferResult{}, relay.written, &timedOut, &destOut, err, machinecontract.TransferRemoteCloseFailed))
	}
	if err := sessionDst.Wait(); err != nil {
		if timedOut.Load() {
			return result, timeoutOr(err)
		}
		output := destOut.String()
		switch {
		case strings.Contains(output, integrityToolMissingMarker):
			result.Stage = "capability"
			return result, transferKindError(machinecontract.IntegrityToolUnavailable, result.Bytes, errors.New(remoteSHA256UnavailableMessage))
		case strings.Contains(output, "SSM_INTEGRITY_MISMATCH"):
			result.Stage = "integrity"
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferIntegrityMismatch, result.Bytes,
				errors.New("destination digest does not match the source digest; nothing was published"))
		}
		message := destErr.String()
		var exit *gossh.ExitError
		if message == "" && !errors.As(err, &exit) {
			return result, transferError(machinecontract.TransferRemoteWriteFailed, result.Bytes, err)
		}
		if message == "" {
			message = err.Error()
		}
		return result, transferError(machinecontract.TransferRemotePermissionsFailed, result.Bytes, errors.New(message))
	}

	size, destinationDigest, err := parseUploadReceipt(destOut.String())
	result.Stage = "integrity"
	result.DestinationSHA256 = destinationDigest
	if err != nil {
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferReceiptInvalid, result.Bytes, errors.New("invalid destination integrity receipt"))
	}
	if size != result.Bytes || destinationDigest != result.LocalSHA256 || result.LocalSHA256 != result.SourceSHA256 {
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferIntegrityMismatch, result.Bytes,
			errors.New("source, relayed and destination digests or sizes do not agree"))
	}
	result.OK = true
	result.Stage = "complete"
	result.Integrity = "sha256_verified"
	return result, nil
}

// copyRelay hashes and counts the bytes it forwards and remembers a write
// failure toward the destination so it can be told apart from a read failure.
type copyRelay struct {
	destination io.Writer
	hasher      io.Writer
	written     int64
	err         error
}

func (r *copyRelay) Write(p []byte) (int, error) {
	n, err := r.destination.Write(p)
	if n > 0 {
		_, _ = r.hasher.Write(p[:n])
		r.written += int64(n)
	}
	if err != nil {
		r.err = err
	}
	return n, err
}

// copySourceError keeps classified errors (dial, host key, shell unsupported,
// transfer errors) as they are and reports anything else, such as a missing
// path, as a source read failure.
func copySourceError(err error) error {
	var transferErr *TransferError
	if errors.As(err, &transferErr) {
		return err
	}
	if failure, ok := machinecontract.FailureFromError(err); ok {
		return transferClassifiedError(failure, 0, err)
	}
	return transferError(machinecontract.TransferDownloadRemoteRead, 0, err)
}

// copyDestinationError is copySourceError for the destination host: an
// unclassified failure there is a write failure, never a source read failure.
func copyDestinationError(err error) error {
	var transferErr *TransferError
	if errors.As(err, &transferErr) {
		return err
	}
	if failure, ok := machinecontract.FailureFromError(err); ok {
		return transferClassifiedError(failure, 0, err)
	}
	return transferError(machinecontract.TransferRemoteWriteFailed, 0, err)
}

// remoteFileMode reads the permission bits of a remote regular file with GNU
// or BSD stat. It is best effort: when stat is unavailable the copy keeps the
// private default 0600 that put uses for unknown modes.
func remoteFileMode(client *gossh.Client, remotePath string, active *sessionSet) os.FileMode {
	const fallback os.FileMode = 0o600
	session, err := newSessionRetry(client)
	if err != nil {
		return fallback
	}
	active.add(session)
	defer func() { _ = session.Close() }()
	quoted := ShellQuote(remotePath)
	out, err := session.Output("stat -c %a -- " + quoted + " 2>/dev/null || stat -f %Lp -- " + quoted + " 2>/dev/null")
	if err != nil {
		return fallback
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(out)), 8, 32)
	if err != nil || value > 0o7777 {
		return fallback
	}
	return os.FileMode(value).Perm()
}
