package ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

const resumeProtocolV1 = "v1"

type resumeState struct {
	Offset int64
	Digest string
}

func uploadFileResumable(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	result := TransferResult{Stage: "local_read", Integrity: "not_checked", Atomic: true, Resume: "v1"}
	if opts.ResumeVersion != resumeProtocolV1 {
		return result, transferError("unsupported_resume_version", "validate", "use --resume=v1", 0, fmt.Errorf("unsupported resume version %q", opts.ResumeVersion))
	}
	f, err := os.Open(localPath)
	if err != nil {
		return result, transferError("local_read_failed", "local_read", "verify the local path and read permissions", 0, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		if err == nil {
			err = errors.New("resumable put supports regular files only")
		}
		return result, transferError("local_read_failed", "local_read", "resume v1 supports regular files only", 0, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return result, transferError("local_read_failed", "local_read", "read the complete source before retrying", 0, err)
	}
	fullDigest := hex.EncodeToString(h.Sum(nil))
	result.LocalSHA256 = fullDigest
	partial, metadata, cleanupPattern := resumePaths(remotePath, fullDigest)

	result.Stage = "resume_probe"
	client, err := dialSSH(c, v)
	if err != nil {
		classified := ClassifyError(err, c)
		return result, transferError(classified.Code, "dial", classified.Hint, 0, classified)
	}
	defer releaseClient(client, false)
	state, err := probeResumeState(client, c, partial, metadata, cleanupPattern, info.Size(), fullDigest)
	if err != nil {
		return result, err
	}
	result.BytesReused = state.Offset
	result.Resume = "started"
	if state.Offset > 0 {
		result.Resume = "resumed"
	}
	prefixDigest, err := localPrefixDigest(f, state.Offset)
	if err != nil {
		return result, transferError("local_read_failed", "local_read", "source changed or could not be re-read", 0, err)
	}
	if prefixDigest != state.Digest {
		result.Stage = "resume_validate"
		result.Integrity = "mismatch"
		return result, transferError("partial_state_mismatch", "resume_validate", "remote partial prefix does not match the local source; remove stale state only after review or retry with non-resume put", 0, errors.New("remote partial digest does not match local prefix"))
	}
	if _, err := f.Seek(state.Offset, io.SeekStart); err != nil {
		return result, transferError("local_read_failed", "local_read", "source must remain seekable and unchanged", 0, err)
	}

	session, err := client.NewSession()
	if err != nil {
		return result, transferError("session_failed", "dial", "retry after checking SSH session limits", 0, err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return result, transferError("remote_write_failed", "remote_write", "retry resume; existing verified prefix remains available", 0, err)
	}
	var stdout, stderr bytes.Buffer
	session.Stdout, session.Stderr = &stdout, &stderr
	cmd := resumeAppendCommand(remotePath, partial, metadata, info.Mode(), info.Size(), fullDigest, state.Offset, state.Digest)
	if err := session.Start(cmd); err != nil {
		return result, transferError("remote_write_failed", "remote_write", "retry resume; final destination was not replaced", 0, err)
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
		_ = session.Close()
		if timedOut.Load() {
			return result, transferError("transfer_timeout", "timeout", "retry with --resume=v1 to validate and reuse the remote prefix", written, copyErr)
		}
		return result, transferError("remote_write_failed", "remote_write", "retry with --resume=v1; the destination was not replaced", written, copyErr)
	}
	if err := stdin.Close(); err != nil {
		_ = session.Close()
		return result, transferError("remote_write_failed", "remote_write", "retry with --resume=v1", written, err)
	}
	if err := session.Wait(); err != nil {
		if timedOut.Load() {
			return result, transferError("transfer_timeout", "timeout", "retry with --resume=v1 to validate and reuse the remote prefix", written, err)
		}
		marker := stdout.String()
		switch {
		case strings.Contains(marker, "SSM_RESUME_ERROR tool_missing"):
			return result, transferError("verification_tool_missing", "capability", "install sha256sum on the remote host or use non-resume put", written, errors.New("remote sha256sum is unavailable"))
		case strings.Contains(marker, "SSM_RESUME_ERROR state_changed"):
			return result, transferError("partial_state_changed", "resume_validate", "remote partial changed during retry; do not append until investigated", written, errors.New("remote partial state changed"))
		case strings.Contains(marker, "SSM_RESUME_ERROR digest_mismatch"):
			result.Integrity = "mismatch"
			return result, transferError("integrity_failed", "integrity", "completed partial failed SHA-256 verification and was not published", written, errors.New("remote final digest mismatch"))
		case strings.Contains(marker, "SSM_RESUME_ERROR publish_failed"):
			return result, transferError("publish_failed", "publish", "verified partial remains; fix destination permissions and retry resume", written, errors.New("atomic publish failed"))
		default:
			message := strings.TrimSpace(stderr.String())
			if message == "" {
				message = err.Error()
			}
			return result, transferError("remote_write_failed", "remote_write", "retry with --resume=v1", written, errors.New(message))
		}
	}
	remoteSize, remoteDigest, err := parseUploadReceipt(stdout.String())
	if err != nil || remoteSize != info.Size() || remoteDigest != fullDigest {
		result.Integrity = "mismatch"
		return result, transferError("integrity_failed", "integrity", "remote completion receipt is invalid", written, errors.New("invalid resume completion receipt"))
	}
	result.OK = true
	result.Stage = "complete"
	result.Integrity = "sha256_verified"
	result.RemoteSHA256 = remoteDigest
	return result, nil
}

func resumePaths(remotePath, digest string) (partial, metadata, cleanupPattern string) {
	pathSum := sha256.Sum256([]byte(remotePath))
	prefix := ".ssm-resume-v1-" + hex.EncodeToString(pathSum[:8]) + "-"
	partial = filepath.ToSlash(filepath.Join(RemoteParentDir(remotePath), prefix+digest))
	if RemoteParentDir(remotePath) == "" {
		partial = prefix + digest
	}
	return partial, partial + ".meta", prefix + "*"
}

func probeResumeState(client *gossh.Client, c config.Connection, partial, metadata, cleanupPattern string, size int64, digest string) (resumeState, error) {
	session, err := client.NewSession()
	if err != nil {
		return resumeState{}, transferError("session_failed", "resume_probe", "retry after checking SSH session limits", 0, err)
	}
	defer session.Close()
	parent := RemoteParentDir(partial)
	if parent == "" {
		parent = "."
	}
	metaTemp := metadata + ".new.$$"
	command := fmt.Sprintf(
		"command -v sha256sum >/dev/null 2>&1 || { echo 'SSM_RESUME_ERROR tool_missing'; exit 69; }; "+
			"umask 077; mkdir -p %s || exit 73; find %s -maxdepth 1 -type f -name %s -mtime +7 -delete 2>/dev/null || true; "+
			"if [ -e %s ] || [ -e %s ]; then "+
			"[ -f %s ] && [ -f %s ] || { echo 'SSM_RESUME_ERROR incompatible'; exit 65; }; "+
			"set -- $(cat -- %s); [ \"$#\" = 3 ] && [ \"$1\" = v1 ] && [ \"$2\" = %d ] && [ \"$3\" = %s ] || { echo 'SSM_RESUME_ERROR incompatible'; exit 65; }; "+
			"offset=$(wc -c < %s | tr -d ' ') || exit 74; [ \"$offset\" -le %d ] || { echo 'SSM_RESUME_ERROR incompatible'; exit 65; }; prefix_sha=$(sha256sum -- %s | awk '{print $1}') || exit 74; "+
			"else : > %s && chmod 0600 %s || exit 73; printf 'v1 %%s %%s\\n' %d %s > %s && chmod 0600 %s && mv -f -- %s %s || exit 73; offset=0; prefix_sha=$(sha256sum -- %s | awk '{print $1}') || exit 74; fi; "+
			"printf 'SSM_RESUME %%s %%s\\n' \"$offset\" \"$prefix_sha\"",
		ShellQuote(parent), ShellQuote(parent), ShellQuote(cleanupPattern),
		ShellQuote(partial), ShellQuote(metadata), ShellQuote(partial), ShellQuote(metadata), ShellQuote(metadata), size, ShellQuote(digest),
		ShellQuote(partial), size, ShellQuote(partial),
		ShellQuote(partial), ShellQuote(partial), size, ShellQuote(digest), ShellQuote(metaTemp), ShellQuote(metaTemp), ShellQuote(metaTemp), ShellQuote(metadata), ShellQuote(partial),
	)
	var stdout, stderr bytes.Buffer
	session.Stdout, session.Stderr = &stdout, &stderr
	if err := session.Run(command); err != nil {
		marker := stdout.String()
		switch {
		case strings.Contains(marker, "SSM_RESUME_ERROR tool_missing"):
			return resumeState{}, transferError("verification_tool_missing", "capability", "install sha256sum on the remote host or use non-resume put", 0, errors.New("remote sha256sum is unavailable"))
		case strings.Contains(marker, "SSM_RESUME_ERROR incompatible"):
			return resumeState{}, transferError("partial_state_incompatible", "resume_validate", "remote partial metadata is missing or incompatible; review and remove only the deterministic v1 partial state", 0, errors.New("incompatible remote partial state"))
		default:
			message := strings.TrimSpace(stderr.String())
			if message == "" {
				message = err.Error()
			}
			return resumeState{}, transferError("resume_probe_failed", "resume_probe", "check remote path permissions and resume capability", 0, errors.New(message))
		}
	}
	fields := strings.Fields(strings.TrimSpace(stdout.String()))
	if len(fields) != 3 || fields[0] != "SSM_RESUME" {
		return resumeState{}, transferError("resume_probe_failed", "resume_probe", "remote resume response was invalid", 0, errors.New("invalid remote resume state"))
	}
	offset, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || offset < 0 || offset > size || len(fields[2]) != 64 {
		return resumeState{}, transferError("resume_probe_failed", "resume_probe", "remote resume response was invalid", 0, errors.New("invalid remote resume offset or digest"))
	}
	return resumeState{Offset: offset, Digest: fields[2]}, nil
}

func localPrefixDigest(f *os.File, size int64) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.CopyN(h, f, size); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func resumeAppendCommand(remotePath, partial, metadata string, mode os.FileMode, size int64, digest string, offset int64, prefixDigest string) string {
	return fmt.Sprintf(
		"command -v sha256sum >/dev/null 2>&1 || { echo 'SSM_RESUME_ERROR tool_missing'; exit 69; }; "+
			"[ -f %s ] && [ -f %s ] || { echo 'SSM_RESUME_ERROR state_changed'; exit 65; }; "+
			"set -- $(cat -- %s); [ \"$#\" = 3 ] && [ \"$1\" = v1 ] && [ \"$2\" = %d ] && [ \"$3\" = %s ] || { echo 'SSM_RESUME_ERROR state_changed'; exit 65; }; "+
			"actual_size=$(wc -c < %s | tr -d ' ') || exit 74; [ \"$actual_size\" = %d ] || { echo 'SSM_RESUME_ERROR state_changed'; exit 65; }; "+
			"prefix_sha=$(sha256sum -- %s | awk '{print $1}') || exit 74; [ \"$prefix_sha\" = %s ] || { echo 'SSM_RESUME_ERROR state_changed'; exit 65; }; "+
			"cat >> %s || exit 74; chmod %04o %s || exit 73; actual_size=$(wc -c < %s | tr -d ' ') || exit 74; actual_sha=$(sha256sum -- %s | awk '{print $1}') || exit 74; "+
			"[ \"$actual_size\" = %d ] && [ \"$actual_sha\" = %s ] || { echo 'SSM_RESUME_ERROR digest_mismatch'; exit 65; }; "+
			"mv -f -- %s %s || { echo 'SSM_RESUME_ERROR publish_failed'; exit 73; }; rm -f -- %s; printf 'SSM_TRANSFER %%s %%s\\n' \"$actual_size\" \"$actual_sha\"",
		ShellQuote(partial), ShellQuote(metadata), ShellQuote(metadata), size, ShellQuote(digest),
		ShellQuote(partial), offset, ShellQuote(partial), ShellQuote(prefixDigest),
		ShellQuote(partial), uint32(mode.Perm()), ShellQuote(partial), ShellQuote(partial), ShellQuote(partial), size, ShellQuote(digest),
		ShellQuote(partial), ShellQuote(remotePath), ShellQuote(metadata),
	)
}
