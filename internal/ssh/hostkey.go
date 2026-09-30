package ssh

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // required by the known_hosts hashed host name format
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	"ssm/internal/privatepath"
)

type HostKeyInspection struct {
	OK                  bool     `json:"ok"`
	Alias               string   `json:"alias"`
	ResolvedAlias       string   `json:"resolved_alias,omitempty"`
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	Address             string   `json:"address"`
	Status              string   `json:"status"` // trusted|new|mismatch|type_changed
	Classification      string   `json:"classification"`
	Algorithm           string   `json:"algorithm"`
	Fingerprint         string   `json:"fingerprint"`
	ObservedFingerprint string   `json:"observed_fingerprint"`
	KnownFingerprints   []string `json:"known_fingerprints,omitempty"`
	KnownHostsPath      string   `json:"known_hosts_path"`
	Accepted            bool     `json:"accepted,omitempty"`
	Message             string   `json:"message,omitempty"`
	Hint                string   `json:"hint,omitempty"`
}

func hostKeyError(kind machinecontract.Kind, message string, cause error) error {
	return machinecontract.NewClassifiedError(machinecontract.Classify(kind, machinecontract.Details{
		Message: message,
		Cause:   cause,
	}))
}

// InspectHostKey observes the key from a fresh unauthenticated SSH handshake.
// The callback aborts immediately after key exchange, so no credential is sent.
func InspectHostKey(c config.Connection) (HostKeyInspection, error) {
	return InspectHostKeyWithVault(c, nil)
}

// InspectHostKeyWithVault is InspectHostKey for connections that may use a
// proxy_jump chain. The key observed is always the target's; every jump host
// must already be trusted, because the tunnel is opened over fully verified
// and authenticated jump connections.
func InspectHostKeyWithVault(c config.Connection, v *config.Vault) (HostKeyInspection, error) {
	port := c.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(c.Host, strconv.Itoa(port))
	report := HostKeyInspection{
		Alias:          c.Name,
		ResolvedAlias:  c.Name,
		Host:           c.Host,
		Port:           port,
		Address:        address,
		KnownHostsPath: KnownHostsPath(),
	}

	conn, closeObservation, err := openObservationConn(c, v, address)
	if err != nil {
		return report, err
	}
	defer closeObservation()
	remote := conn.RemoteAddr()

	var observed gossh.PublicKey
	stop := errors.New("ssm host key captured")
	cfg := &gossh.ClientConfig{
		User: c.User,
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			observed = key
			return stop
		},
		HostKeyAlgorithms: hostKeyAlgorithmsFor(report.KnownHostsPath, address),
	}
	_, _, _, handshakeErr := gossh.NewClientConn(conn, address, cfg)
	if observed == nil {
		if handshakeErr == nil {
			handshakeErr = errors.New("SSH handshake ended before a host key was received")
		}
		return report, hostKeyError(machinecontract.HostKeyScanDirectFailed, handshakeErr.Error(), handshakeErr)
	}

	report.Algorithm = observed.Type()
	report.Fingerprint = gossh.FingerprintSHA256(observed)
	report.ObservedFingerprint = report.Fingerprint
	status, known, err := inspectKnownHost(report.KnownHostsPath, address, remote, observed)
	if err != nil {
		return report, err
	}
	report.Status = status
	report.Classification = status
	report.KnownFingerprints = known
	switch status {
	case "trusted":
		report.Message = "observed host key matches known_hosts"
		report.Hint = "no host-key change is required"
	case "new":
		report.Message = "endpoint has no trusted host key entry"
		report.Hint = "verify observed_fingerprint through a trusted channel, then use host-key accept with the exact fingerprint and --yes"
	case "mismatch":
		report.Message = "observed host key differs from known_hosts"
		report.Hint = "treat as a possible interception until rebuild or reassignment is confirmed out-of-band; never remove and rescan automatically"
	case "type_changed":
		report.Message = "observed host key type is not among the key types recorded in known_hosts"
		report.Hint = "the server no longer presents a recorded key type; verify observed_fingerprint out-of-band before host-key accept, which adds this key type and keeps the other recorded types; never remove and rescan automatically"
	}
	report.OK = true
	return report, nil
}

func inspectKnownHost(path, address string, remote net.Addr, observed gossh.PublicKey) (string, []string, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "new", nil, nil
		}
		return "", nil, hostKeyError(machinecontract.KnownHostsPermissionsFailed, err.Error(), err)
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return "", nil, hostKeyError(machinecontract.KnownHostsMalformed, err.Error(), err)
	}
	err = callback(address, remote, observed)
	if err == nil {
		return "trusted", []string{gossh.FingerprintSHA256(observed)}, nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return "", nil, hostKeyError(machinecontract.KnownHostsInspectionFailed, err.Error(), err)
	}
	if len(keyErr.Want) == 0 {
		return "new", nil, nil
	}
	fingerprints := make([]string, 0, len(keyErr.Want))
	seen := map[string]bool{}
	for _, known := range keyErr.Want {
		fingerprint := gossh.FingerprintSHA256(known.Key)
		if !seen[fingerprint] {
			seen[fingerprint] = true
			fingerprints = append(fingerprints, fingerprint)
		}
	}
	sort.Strings(fingerprints)
	if plain, hasAuthority := splitCertAuthorities(path, keyErr.Want); !hasAuthority && !wantHasKeyType(plain, observed) {
		return "type_changed", fingerprints, nil
	}
	return "mismatch", fingerprints, nil
}

// AcceptHostKey re-observes the endpoint and changes known_hosts only when the
// caller-provided full SHA-256 fingerprint matches exactly.
func AcceptHostKey(c config.Connection, expectedFingerprint string) (HostKeyInspection, error) {
	return AcceptHostKeyWithVault(c, nil, expectedFingerprint)
}

// AcceptHostKeyWithVault is AcceptHostKey for connections that may use a
// proxy_jump chain; only the target's key is ever recorded.
func AcceptHostKeyWithVault(c config.Connection, v *config.Vault, expectedFingerprint string) (HostKeyInspection, error) {
	report, err := InspectHostKeyWithVault(c, v)
	if err != nil {
		return report, err
	}
	if expectedFingerprint == "" || expectedFingerprint != report.Fingerprint {
		return report, hostKeyError(
			machinecontract.HostKeyFingerprintMismatch,
			fmt.Sprintf("observed fingerprint %q does not match the explicitly accepted fingerprint", report.Fingerprint),
			nil,
		)
	}
	if report.Status == "trusted" {
		report.Accepted = true
		return report, nil
	}
	key, err := scanObservedKey(c, v)
	if err != nil {
		return report, err
	}
	if gossh.FingerprintSHA256(key) != expectedFingerprint {
		return report, hostKeyError(
			machinecontract.HostKeyFingerprintChanged,
			"host key changed between inspection and known_hosts update",
			nil,
		)
	}

	path := report.KnownHostsPath
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return report, hostKeyError(machinecontract.SSHDirectoryPermissionsFailed, err.Error(), err)
	}
	if report.Status == "mismatch" {
		if err := replaceKnownHost(path, knownHostToken(c), key); err != nil {
			return report, err
		}
	} else if err := saveHostKey(path, knownHostToken(c), key); err != nil {
		return report, hostKeyError(machinecontract.KnownHostsPermissionsFailed, err.Error(), err)
	}
	report.Status = "trusted"
	report.Classification = "trusted"
	report.KnownFingerprints = []string{expectedFingerprint}
	report.Accepted = true
	report.Message = "exact observed host key fingerprint accepted"
	report.Hint = "future connections will require this trusted key"
	return report, nil
}

func scanObservedKey(c config.Connection, v *config.Vault) (gossh.PublicKey, error) {
	port := c.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(c.Host, strconv.Itoa(port))
	conn, closeObservation, err := openObservationConn(c, v, address)
	if err != nil {
		return nil, err
	}
	defer closeObservation()
	var observed gossh.PublicKey
	stop := errors.New("ssm host key captured")
	_, _, _, err = gossh.NewClientConn(conn, address, &gossh.ClientConfig{
		User: c.User,
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			observed = key
			return stop
		},
		HostKeyAlgorithms: hostKeyAlgorithmsFor(KnownHostsPath(), address),
	})
	if observed == nil {
		message := "SSH handshake ended before a host key was received"
		if err != nil {
			message = err.Error()
		}
		return nil, hostKeyError(machinecontract.HostKeyScanFailed, message, err)
	}
	return observed, nil
}

// replaceKnownHost records key for token in the known_hosts file at path. It
// removes only the entries for that endpoint that have the same key type as
// key and appends the new entry. Every other line (other hosts, other key
// types, comments, blank lines, @cert-authority and @revoked markers) is kept
// byte for byte. The file is replaced atomically and keeps its permissions.
func replaceKnownHost(path, token string, key gossh.PublicKey) error {
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	}
	info, err := os.Stat(target)
	if err != nil {
		return hostKeyError(machinecontract.KnownHostsPermissionsFailed, err.Error(), err)
	}
	original, err := os.ReadFile(target) //nolint:gosec // fixed ~/.ssh/known_hosts path
	if err != nil {
		return hostKeyError(machinecontract.KnownHostsPermissionsFailed, err.Error(), err)
	}

	updated := make([]byte, 0, len(original)+256)
	for rest := original; len(rest) > 0; {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			rest = nil
		}
		updated = append(updated, dropKnownHostEntry(line, token, key.Type())...)
	}
	if len(updated) > 0 && updated[len(updated)-1] != '\n' {
		updated = append(updated, '\n')
	}
	updated = append(updated, knownhosts.Line([]string{token}, key)...)
	updated = append(updated, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(target), ".known_hosts.ssm.*")
	if err != nil {
		return hostKeyError(machinecontract.SSHDirectoryPermissionsFailed, err.Error(), err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return hostKeyError(machinecontract.SSHDirectoryPermissionsFailed, err.Error(), err)
	}
	if runtime.GOOS == "windows" {
		// Windows has no mode bits to preserve; keep the private-ACL policy.
		if err := privatepath.RestrictFile(tmpPath); err != nil {
			_ = tmp.Close()
			return hostKeyError(machinecontract.SSHDirectoryPermissionsFailed, err.Error(), err)
		}
	}
	if _, err := tmp.Write(updated); err != nil {
		_ = tmp.Close()
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	if err := tmp.Close(); err != nil {
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	committed = true
	return nil
}

// dropKnownHostEntry returns line without the token entry of the given key
// type, or unchanged when it does not carry one. Marker lines (@cert-authority,
// @revoked), comments, blank lines and lines of other key types are returned
// unchanged. When the line also lists other host patterns, only the token
// pattern is removed from its host field and the rest of the line is kept.
func dropKnownHostEntry(line []byte, token, keyType string) []byte {
	text := string(line)
	trimmed := strings.TrimLeft(text, " \t")
	if trimmed == "" || trimmed[0] == '#' || trimmed[0] == '@' || trimmed[0] == '\n' || trimmed[0] == '\r' {
		return line
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 3 || fields[1] != keyType {
		return line
	}
	patterns := strings.Split(fields[0], ",")
	kept := make([]string, 0, len(patterns))
	matched := false
	for _, pattern := range patterns {
		if knownHostPatternIs(pattern, token) {
			matched = true
			continue
		}
		kept = append(kept, pattern)
	}
	if !matched {
		return line
	}
	if len(kept) == 0 {
		return nil
	}
	leading := text[:len(text)-len(trimmed)]
	return []byte(leading + strings.Join(kept, ",") + trimmed[len(fields[0]):])
}

// knownHostPatternIs reports whether one known_hosts host pattern, plain or
// hashed, names exactly the normalized host token.
func knownHostPatternIs(pattern, token string) bool {
	if strings.HasPrefix(pattern, "|") {
		parts := strings.Split(pattern, "|")
		if len(parts) != 4 || parts[1] != "1" {
			return false
		}
		salt, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return false
		}
		want, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil {
			return false
		}
		mac := hmac.New(sha1.New, salt) //nolint:gosec // known_hosts hashed host names are HMAC-SHA1 by definition
		_, _ = mac.Write([]byte(token))
		return hmac.Equal(mac.Sum(nil), want)
	}
	if strings.HasPrefix(pattern, "!") || strings.ContainsAny(pattern, "*?") {
		return false
	}
	return knownhosts.Normalize(pattern) == token
}

func knownHostToken(c config.Connection) string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return knownhosts.Normalize(net.JoinHostPort(c.Host, strconv.Itoa(port)))
}

func KnownHostsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "known_hosts")
}

// openObservationConn returns the connection over which the target's host key
// is observed without authenticating: a direct TCP connection, or a tunnel
// through the fully verified jump chain. The returned function releases the
// connection, its deadline, and every jump connection opened for it.
func openObservationConn(c config.Connection, v *config.Vault, address string) (net.Conn, func(), error) {
	if strings.TrimSpace(c.ProxyJump) == "" {
		conn, err := dialConnectDeadline(address)
		if err != nil {
			return nil, nil, ClassifyError(err, c)
		}
		return conn, func() { _ = conn.Close() }, nil
	}
	chain, err := config.ResolveJumpChain(v, c)
	if err != nil {
		return nil, nil, invalidJumpChainError(c, err)
	}
	last, closeJumps, err := dialJumpPrefix(chain, v)
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(DialTimeout())
	conn, err := dialTunnel(last, address, deadline)
	if err != nil {
		closeJumps()
		return nil, nil, classifyHop(err, c, c, true, nil, true)
	}
	// Channels have no deadlines: closing the channel ends a stalled handshake.
	timer := time.AfterFunc(time.Until(deadline), func() { _ = conn.Close() })
	return conn, func() {
		timer.Stop()
		_ = conn.Close()
		closeJumps()
	}, nil
}
