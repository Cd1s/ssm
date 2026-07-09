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
	return fmt.Sprintf("%s@%s:%d", c.User, c.Host, port)
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
	poolMu.Lock()
	defer poolMu.Unlock()

	if p, ok := pool[key]; ok && p.client != nil {
		sess, err := p.client.NewSession()
		if err == nil {
			_ = sess.Close()
			p.lastUsed = time.Now()
			return p.client, nil
		}
		_ = p.client.Close()
		delete(pool, key)
	}

	client, err := dialSSHFresh(c, v)
	if err != nil {
		return nil, err
	}
	pool[key] = &pooledClient{client: client, lastUsed: time.Now(), key: key}
	return client, nil
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

// ClosePool closes all pooled clients (tests / process exit).
func ClosePool() {
	poolMu.Lock()
	defer poolMu.Unlock()
	for k, p := range pool {
		if p.client != nil {
			_ = p.client.Close()
		}
		delete(pool, k)
	}
}

// PoolSize returns number of cached clients (tests).
func PoolSize() int {
	poolMu.Lock()
	defer poolMu.Unlock()
	return len(pool)
}
