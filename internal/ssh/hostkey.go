package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

type HostKeyInspection struct {
	OK                  bool     `json:"ok"`
	Alias               string   `json:"alias"`
	ResolvedAlias       string   `json:"resolved_alias,omitempty"`
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	Address             string   `json:"address"`
	Status              string   `json:"status"` // trusted|new|mismatch
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

	conn, err := net.DialTimeout("tcp", address, DialTimeout())
	if err != nil {
		return report, ClassifyError(err, c)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(DialTimeout()))
	remote := conn.RemoteAddr()

	var observed gossh.PublicKey
	stop := errors.New("ssm host key captured")
	cfg := &gossh.ClientConfig{
		User: c.User,
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			observed = key
			return stop
		},
		Timeout: DialTimeout(),
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
	return "mismatch", fingerprints, nil
}

// AcceptHostKey re-observes the endpoint and changes known_hosts only when the
// caller-provided full SHA-256 fingerprint matches exactly.
func AcceptHostKey(c config.Connection, expectedFingerprint string) (HostKeyInspection, error) {
	report, err := InspectHostKey(c)
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
	key, err := scanObservedKey(c)
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

func scanObservedKey(c config.Connection) (gossh.PublicKey, error) {
	port := c.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(c.Host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, DialTimeout())
	if err != nil {
		return nil, ClassifyError(err, c)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(DialTimeout()))
	var observed gossh.PublicKey
	stop := errors.New("ssm host key captured")
	_, _, _, err = gossh.NewClientConn(conn, address, &gossh.ClientConfig{
		User: c.User,
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			observed = key
			return stop
		},
		Timeout: DialTimeout(),
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

func replaceKnownHost(path, token string, key gossh.PublicKey) error {
	original, err := os.ReadFile(path) //nolint:gosec // fixed ~/.ssh/known_hosts path
	if err != nil {
		return hostKeyError(machinecontract.KnownHostsPermissionsFailed, err.Error(), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".known_hosts.ssm.*")
	if err != nil {
		return hostKeyError(machinecontract.SSHDirectoryPermissionsFailed, err.Error(), err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
		_ = os.Remove(tmpPath + ".old")
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return hostKeyError(machinecontract.SSHDirectoryPermissionsFailed, err.Error(), err)
	}
	if _, err := tmp.Write(original); err != nil {
		_ = tmp.Close()
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	if err := tmp.Close(); err != nil {
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}

	cmd := exec.Command("ssh-keygen", "-R", token, "-f", tmpPath) //nolint:gosec // fixed executable and argument vector
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return hostKeyError(machinecontract.KnownHostsUpdateFailed, message, err)
	}
	if err := saveHostKey(tmpPath, token, key); err != nil {
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	updated, err := os.ReadFile(tmpPath) //nolint:gosec // private temporary known_hosts path
	if err != nil {
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	if err := config.WritePrivateFile(path, updated); err != nil {
		return hostKeyError(machinecontract.KnownHostsUnchanged, err.Error(), err)
	}
	return nil
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
