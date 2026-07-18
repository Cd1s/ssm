package ssh

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

// Session reuse: keep *ssh.Client open and open a new channel per command.
// Disable with SSM_REUSE=0/off/false or RunOptions.NoReuse.

var (
	poolMu sync.Mutex
	pool   = map[string]*pooledClient{}
)

type pooledClient struct {
	mu       sync.Mutex
	client   *gossh.Client
	lastUsed time.Time
	key      string
}

func reuseEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SSM_REUSE")))
	switch v {
	case "0", "off", "false", "no", "disable", "disabled":
		return false
	default:
		return true
	}
}

func poolKey(c config.Connection) string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%s@%s:%d|key=%s|password=%t", c.User, c.Host, port, c.KeyName, c.Password != "")
}

func getPoolEntry(key string) *pooledClient {
	poolMu.Lock()
	defer poolMu.Unlock()
	if entry, ok := pool[key]; ok {
		return entry
	}
	entry := &pooledClient{key: key}
	pool[key] = entry
	return entry
}

// dialSSH obtains an SSH client, optionally from the reuse pool.
func dialSSH(c config.Connection, v *config.Vault) (*gossh.Client, error) {
	return dialSSHOpts(c, v, false)
}

func dialSSHOpts(c config.Connection, v *config.Vault, noReuse bool) (*gossh.Client, error) {
	if !noReuse && reuseEnabled() {
		return getPooledClient(c, v)
	}
	return dialSSHFresh(c, v)
}

func dialSSHFresh(c config.Connection, v *config.Vault) (*gossh.Client, error) {
	auth, err := buildAuth(c, v)
	if err != nil {
		return nil, ClassifyError(err, c)
	}

	port := c.Port
	if port == 0 {
		port = 22
	}

	client, err := gossh.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(port)), &gossh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: buildHostKeyCallback(),
		Timeout:         DialTimeout(),
	})
	if err != nil {
		return nil, ClassifyError(err, c)
	}
	return client, nil
}

func getPooledClient(c config.Connection, v *config.Vault) (*gossh.Client, error) {
	key := poolKey(c)
	entry := getPoolEntry(key)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.client != nil {
		sess, err := entry.client.NewSession()
		if err == nil {
			_ = sess.Close()
			entry.lastUsed = time.Now()
			return entry.client, nil
		}
		_ = entry.client.Close()
		entry.client = nil
	}

	client, err := dialSSHFresh(c, v)
	if err != nil {
		return nil, err
	}
	entry.client = client
	entry.lastUsed = time.Now()
	return client, nil
}

// acquireSSHSession opens the session that the caller will actually use. It
// avoids the old "probe channel, close it, open another channel" round trip on
// every pooled command. A stale pooled connection is evicted and redialed once.
// The per-destination lock serializes only one host's dial; different hosts can
// still establish connections concurrently.
func acquireSSHSession(c config.Connection, v *config.Vault, noReuse bool) (*gossh.Client, *gossh.Session, string, error) {
	if noReuse || !reuseEnabled() {
		client, err := dialSSHFresh(c, v)
		if err != nil {
			return nil, nil, "dial", err
		}
		session, err := client.NewSession()
		if err != nil {
			_ = client.Close()
			return nil, nil, "session", err
		}
		return client, session, "", nil
	}

	entry := getPoolEntry(poolKey(c))
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.client != nil {
		session, err := entry.client.NewSession()
		if err == nil {
			entry.lastUsed = time.Now()
			return entry.client, session, "", nil
		}
		_ = entry.client.Close()
		entry.client = nil
	}

	client, err := dialSSHFresh(c, v)
	if err != nil {
		return nil, nil, "dial", err
	}
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, "session", err
	}
	entry.client = client
	entry.lastUsed = time.Now()
	return client, session, "", nil
}

// releaseClient closes the client only when reuse is disabled.
func releaseClient(client *gossh.Client, noReuse bool) {
	if client == nil {
		return
	}
	if !noReuse && reuseEnabled() {
		return
	}
	_ = client.Close()
}

// ClosePool closes every process-local SSH connection. Long-lived streaming
// callers use this when their inventory changes or the input stream ends.
func ClosePool() {
	poolMu.Lock()
	entries := make([]*pooledClient, 0, len(pool))
	for _, entry := range pool {
		entries = append(entries, entry)
	}
	pool = map[string]*pooledClient{}
	poolMu.Unlock()

	for _, entry := range entries {
		entry.mu.Lock()
		if entry.client != nil {
			_ = entry.client.Close()
			entry.client = nil
		}
		entry.mu.Unlock()
	}
}
