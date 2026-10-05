package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	"ssm/internal/privatepath"
)

const dialTimeout = 15 * time.Second

func buildAuth(c config.Connection, v *config.Vault) ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod
	if c.KeyName != "" {
		key := v.GetKey(c.KeyName)
		if key == nil {
			return nil, fmt.Errorf("key %q not found", c.KeyName)
		}
		signer, err := gossh.ParsePrivateKey([]byte(key.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid SSH key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}
	if c.Password != "" {
		methods = append(methods, gossh.Password(c.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no authentication configured for %q", c.Name)
	}
	return methods, nil
}

// trackedHostKeyCallback wraps the known_hosts callback so reached turns true
// once THIS hop's host key arrived, i.e. key exchange got far enough that
// credentials may follow. Each hop of a jump chain has its own flag: a failure
// at hop N with hop N's flag still false happened before any credential could
// have been sent to hop N (earlier hops authenticated successfully). When the
// dial was abandoned (abort), the callback refuses the key so nothing is sent.
func trackedHostKeyCallback(reached *atomic.Bool, abort *dialAbort) gossh.HostKeyCallback {
	callback := buildHostKeyCallback()
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		// Store before checking abort: if the check below passes (and
		// credentials may follow), the store happened before abort(), so
		// the abandoning side, which reads the flag after abort(), sees it.
		reached.Store(true)
		if abort.aborted() {
			return errDialAbandoned
		}
		return callback(hostname, remote, key)
	}
}

func buildHostKeyCallback() gossh.HostKeyCallback {
	path, err := KnownHostsPath()
	if err != nil {
		return rejectHostKey(knownHostsPathError())
	}
	return buildHostKeyCallbackForPath(path)
}

func buildHostKeyCallbackForPath(path string) gossh.HostKeyCallback {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return rejectUnknownHostKey(path)
		}
		return rejectHostKey(fmt.Errorf("known_hosts stat failed: %w", err))
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return rejectHostKey(fmt.Errorf("known_hosts parse failed: %w", err))
	}
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		err := callback(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
			// known_hosts only has other key types for this endpoint: not a
			// changed key of a known type, so report it distinctly. A matching
			// @cert-authority entry keeps the legacy mismatch classification.
			if plain, hasAuthority := splitCertAuthorities(path, keyErr.Want); !hasAuthority && !wantHasKeyType(plain, key) {
				return &machinecontract.HostKeyTypeChangedError{KeyError: keyErr, ObservedType: observedKeyType(key)}
			}
		}
		return err
	}
}

func rejectHostKey(err error) gossh.HostKeyCallback {
	return func(string, net.Addr, gossh.PublicKey) error { return err }
}

func rejectUnknownHostKey(path string) gossh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		return &knownhosts.KeyError{}
	}
}

func saveHostKey(path, hostname string, key gossh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := privatepath.RestrictDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // caller supplies the configured known_hosts path
	if err != nil {
		return err
	}
	entry := knownhosts.Line([]string{hostname}, key) + "\n"
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, info.Size()-1); err == nil && last[0] != '\n' {
			// Do not glue the new entry onto an unterminated last line.
			entry = "\n" + entry
		}
	}
	if _, err := f.WriteString(entry); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return privatepath.RestrictFile(path)
}
