package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
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

func buildHostKeyCallback() gossh.HostKeyCallback {
	home, _ := os.UserHomeDir()
	return buildHostKeyCallbackForPath(filepath.Join(home, ".ssh", "known_hosts"))
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
			return err
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // caller supplies the configured known_hosts path
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, knownhosts.Line([]string{hostname}, key)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return privatepath.RestrictFile(path)
}
