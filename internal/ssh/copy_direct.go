package ssh

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// Issue #115: sshctl cp --direct. Host A runs ssh towards host B and pushes
// the file with the same temporary-file, digest-check and rename script that
// put uses. A authenticates to B through an SSH agent forwarded for this one
// session; that agent lives in this process and holds only B's key. B's
// password, this machine's own agent and every other vault key never reach A.
// A connects with strict host-key checking against a private known_hosts file
// that holds only the key this machine already trusts for B.

const directSSHProbeMarker = "SSM_SSH_OK"

func directUnsupported(format string, args ...any) error {
	return transferKindError(machinecontract.CopyDirectUnsupported, 0, fmt.Errorf(format, args...))
}

// directAgent is the scoped agent forwarded to A: a keyring that holds exactly
// the destination's private key from the vault.
func directAgent(dst config.Connection, v *config.Vault) (agent.Agent, gossh.PublicKey, error) {
	if dst.KeyName == "" {
		return nil, nil, directUnsupported("%s authenticates with a password only; cp --direct needs a key from the vault for the destination and never sends a password to the source host", dst.Name)
	}
	key := v.GetKey(dst.KeyName)
	if key == nil {
		return nil, nil, directUnsupported("key %q of destination %s was not found in the vault", dst.KeyName, dst.Name)
	}
	raw, err := gossh.ParseRawPrivateKey([]byte(key.PrivateKey))
	if err != nil {
		return nil, nil, directUnsupported("the key of destination %s cannot be loaded into the scoped agent (encrypted or unsupported key)", dst.Name)
	}
	if pointer, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *pointer
	}
	signer, err := gossh.NewSignerFromKey(raw)
	if err != nil {
		return nil, nil, directUnsupported("the key of destination %s cannot be loaded into the scoped agent (unsupported key)", dst.Name)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: raw, Comment: "sshctl cp --direct"}); err != nil {
		return nil, nil, directUnsupported("the key of destination %s cannot be loaded into the scoped agent (%v)", dst.Name, err)
	}
	return keyring, signer.PublicKey(), nil
}

// directKnownHostsLines returns the known_hosts entries, written for the exact
// host[:port] that A will connect to, of the host keys this machine already
// trusts for the destination. The destination must have an explicit entry for
// that endpoint (plain or hashed); wildcard patterns are not copied. Entries
// that the local verification would refuse (revoked) are dropped.
func directKnownHostsLines(path string, dst config.Connection) ([]string, error) {
	unknown := func(cause error) error {
		classified := ClassifyError(&knownhosts.KeyError{}, dst)
		if cause != nil {
			classified.Message = fmt.Sprintf("%s (%v)", classified.Message, cause)
		}
		return transferClassifiedError(classified.Failure, 0, classified)
	}
	data, err := os.ReadFile(path) //nolint:gosec // configured known_hosts path
	if err != nil {
		return nil, unknown(nil)
	}
	address := hostPortOf(dst)
	token := knownHostToken(dst)
	verify := buildHostKeyCallbackForPath(path)
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	var lines []string
	seen := map[string]bool{}
	for _, text := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		marker, hosts, key, _, _, err := gossh.ParseKnownHosts([]byte(trimmed))
		if err != nil || marker != "" {
			continue
		}
		matched := false
		for _, host := range hosts {
			if knownHostPatternIs(host, token) {
				matched = true
				break
			}
		}
		if !matched || verify(address, remote, key) != nil {
			continue
		}
		line := knownhosts.Line([]string{address}, key)
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, unknown(nil)
	}
	return lines, nil
}

// directSafeToken reports whether a user or host name can be placed in the
// user@host argument of ssh without being read as an option or splitting it.
func directSafeToken(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	return !strings.ContainsAny(value, " \t\r\n'\"\\$`;&|<>(){}*?!#~")
}

// directSSHCommand is the command line run on A. It writes the destination's
// trusted host keys to a private (0600) temporary known_hosts file that a trap
// removes on every exit, then pushes srcPath over ssh into putScript. Every
// operand is quoted with ShellQuote; ssh never prompts (BatchMode), only
// trusts the temporary file (strict checking, no global file), and does not
// forward an agent any further.
func directSSHCommand(srcPath string, dst config.Connection, knownHostsLines []string, connectSeconds int, putScript string) string {
	port := dst.Port
	if port == 0 {
		port = 22
	}
	quoted := make([]string, len(knownHostsLines))
	for i, line := range knownHostsLines {
		quoted[i] = ShellQuote(line)
	}
	return "umask 077; kh=$(mktemp \"${TMPDIR:-/tmp}/ssm-kh.XXXXXXXX\") || exit 70; " +
		"trap 'rm -f -- \"$kh\"' EXIT HUP INT TERM; " +
		"printf '%s\\n' " + strings.Join(quoted, " ") + " > \"$kh\" || exit 70; " +
		"ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o \"UserKnownHostsFile=$kh\" -o GlobalKnownHostsFile=/dev/null " +
		"-o VerifyHostKeyDNS=no -o ForwardAgent=no -o ConnectTimeout=" + strconv.Itoa(connectSeconds) + " -o IdentitiesOnly=no " +
		"-p " + strconv.Itoa(port) + " -- " + ShellQuote(dst.User+"@"+dst.Host) + " " + ShellQuote(putScript) +
		" < " + ShellQuote(srcPath)
}

func directConnectSeconds() int {
	seconds := int((DialTimeout() + time.Second - 1) / time.Second)
	return max(seconds, 1)
}

// copyFileDirect is CopyFile for --direct. All refusals that need no
// connection to A happen first, and B's host key must be trusted locally
// before A is contacted.
func copyFileDirect(src config.Connection, srcPath string, dst config.Connection, dstPath string, v *config.Vault, opts CopyOptions) (CopyResult, error) {
	result := CopyResult{Stage: "validate", Integrity: "not_checked", Atomic: true, Route: "direct"}
	if strings.TrimSpace(dst.ProxyJump) != "" {
		return result, directUnsupported("%s is reached through proxy_jump; cp --direct needs B to be directly reachable from A", dst.Name)
	}
	if !directSafeToken(dst.User) || !directSafeToken(dst.Host) {
		return result, directUnsupported("the user or host of %s cannot be passed safely to ssh on the source host", dst.Name)
	}
	keyring, _, err := directAgent(dst, v)
	if err != nil {
		return result, err
	}
	defer func() { _ = keyring.RemoveAll() }()
	knownHostsLines, err := directKnownHostsLines(KnownHostsPath(), dst)
	if err != nil {
		return result, err
	}

	// Check B with its key only, before A is involved: this proves the vault
	// key is accepted (password-only access never qualifies) and that the
	// trusted host key is the one B presents. The connection is kept for the
	// final digest read.
	result.Stage = "dial"
	keyOnly := dst
	keyOnly.Password = ""
	clientDst, err := dialSSHFresh(keyOnly, v)
	if err != nil {
		if failure, ok := machinecontract.FailureFromError(err); ok && failure.Error == machinecontract.CodeAuth {
			return result, directUnsupported("%s did not accept its vault key; cp --direct uses key authentication only and never sends a password to the source host", dst.Name)
		}
		return result, copyDestinationError(err)
	}
	defer func() { _ = clientDst.Close() }()

	// A gets its own connection: the forwarded agent is registered on it and
	// it is closed as soon as the copy ends, so nothing keeps the agent
	// reachable and no pooled connection is shared.
	clientSrc, err := dialSSHOpts(src, v, true)
	if err != nil {
		return result, copySourceError(err)
	}
	defer func() { _ = clientSrc.Close() }()

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

	result.Stage = "discovery"
	isDir, err := remoteIsDirOn(clientSrc, srcPath)
	if err != nil {
		return result, timeoutOr(copySourceError(err))
	}
	if isDir {
		return result, transferKindError(machinecontract.CopyDirectoryUnsupported, 0,
			fmt.Errorf("%s is a directory; cp copies single regular files only", srcPath))
	}

	result.Stage = "capability"
	if err := directRequireSSH(clientSrc, &active); err != nil {
		return result, timeoutOr(err)
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
	var sessionOut bytes.Buffer
	var sessionErr boundedBuffer
	sessionSrc.Stdout = &sessionOut
	sessionSrc.Stderr = &sessionErr

	// The agent is reachable from A only between this registration and the
	// RemoveAll below, and only over this one connection.
	if err := agent.ForwardToAgent(clientSrc, keyring); err != nil {
		return result, transferError(machinecontract.TransferStartFailed, 0, err)
	}
	if err := agent.RequestAgentForwarding(sessionSrc); err != nil {
		return result, directUnsupported("the SSH server of the source host refused agent forwarding; cp --direct needs it (AllowAgentForwarding)")
	}

	result.Stage = "remote_write"
	command := directSSHCommand(srcPath, dst, knownHostsLines, directConnectSeconds(),
		uploadCommandWithIntegrity(dstPath, mode, -1, sourceDigest, DefaultUploadDirMode))
	if err := sessionSrc.Start(command); err != nil {
		_ = keyring.RemoveAll()
		if isExecRefused(err) {
			return result, remoteShellUnsupportedError("", err)
		}
		return result, timeoutOr(transferError(machinecontract.TransferStartFailed, 0, err))
	}
	waitErr := sessionSrc.Wait()
	// The copy is over: nothing may use B's key any more.
	_ = keyring.RemoveAll()
	_ = sessionSrc.Close()
	_ = clientSrc.Close()

	if waitErr != nil {
		if timedOut.Load() {
			return result, timeoutOr(waitErr)
		}
		output := sessionOut.String()
		switch {
		case strings.Contains(output, integrityToolMissingMarker):
			result.Stage = "capability"
			return result, transferKindError(machinecontract.IntegrityToolUnavailable, 0, errors.New(remoteSHA256UnavailableMessage))
		case strings.Contains(output, "SSM_INTEGRITY_MISMATCH"):
			result.Stage = "integrity"
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferIntegrityMismatch, 0,
				errors.New("destination digest does not match the source digest; nothing was published"))
		}
		message := sessionErr.String()
		var exit *gossh.ExitError
		switch {
		case errors.As(waitErr, &exit) && exit.ExitStatus() == 255:
			if message == "" {
				message = waitErr.Error()
			}
			return result, transferError(machinecontract.TransferRemoteWriteFailed, 0, fmt.Errorf("ssh from %s to %s failed: %s", src.Name, dst.Name, message))
		case message == "" && !errors.As(waitErr, &exit):
			return result, transferError(machinecontract.TransferRemoteWriteFailed, 0, waitErr)
		}
		if message == "" {
			message = waitErr.Error()
		}
		return result, transferError(machinecontract.TransferRemotePermissionsFailed, 0, errors.New(message))
	}

	size, receiptDigest, err := parseUploadReceipt(sessionOut.String())
	result.Stage = "integrity"
	if err != nil {
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferReceiptInvalid, 0, errors.New("invalid destination integrity receipt"))
	}
	result.Bytes = size
	if receiptDigest != sourceDigest {
		result.DestinationSHA256 = receiptDigest
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferIntegrityMismatch, result.Bytes,
			errors.New("source and destination digests do not agree"))
	}
	destinationDigest, err := remoteFileSHA256(clientDst, dstPath, &active)
	if err != nil {
		return result, timeoutOr(copyDestinationError(err))
	}
	result.DestinationSHA256 = destinationDigest
	if destinationDigest != sourceDigest {
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferIntegrityMismatch, result.Bytes,
			errors.New("source and destination digests do not agree"))
	}
	result.OK = true
	result.Stage = "complete"
	result.Integrity = "sha256_verified"
	return result, nil
}

// directRequireSSH checks that host A has an ssh client.
func directRequireSSH(client *gossh.Client, active *sessionSet) error {
	session, err := newSessionRetry(client)
	if err != nil {
		return transferError(machinecontract.TransferSessionOpenFailed, 0, err)
	}
	active.add(session)
	defer func() { _ = session.Close() }()
	out, err := session.CombinedOutput("command -v ssh >/dev/null 2>&1 && echo " + directSSHProbeMarker)
	if err != nil {
		if isExecRefused(err) {
			return remoteShellUnsupportedError(string(out), err)
		}
		var exit *gossh.ExitError
		if !errors.As(err, &exit) {
			return transferError(machinecontract.TransferDownloadRemoteRead, 0, err)
		}
	}
	if !strings.Contains(string(out), directSSHProbeMarker) {
		return transferKindError(machinecontract.CopyDirectSSHUnavailable, 0, errors.New("the source host has no ssh client"))
	}
	return nil
}
