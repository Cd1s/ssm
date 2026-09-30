package ssh

import (
	"os"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const (
	// keepaliveDefaultInterval is how often an idle SSH connection is probed.
	keepaliveDefaultInterval = 15 * time.Second
	// keepaliveMaxMisses is how many consecutive probes may go unanswered
	// before the connection is closed as dead.
	keepaliveMaxMisses = 3
	// keepaliveRequest is the OpenSSH global request that servers answer, so
	// an answer proves the path and the peer are alive.
	keepaliveRequest = "keepalive@openssh.com"
)

// KeepaliveInterval returns the SSH keepalive interval: 15s by default,
// SSM_KEEPALIVE=<duration|seconds> to change it, SSM_KEEPALIVE=0 (or
// off/false/no) to disable it, which is reported as 0.
func KeepaliveInterval() time.Duration {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("SSM_KEEPALIVE")))
	switch value {
	case "":
		return keepaliveDefaultInterval
	case "0", "off", "false", "no", "disable", "disabled":
		return 0
	}
	if duration, err := parseTimeout(value); err == nil && duration > 0 {
		return duration
	}
	return keepaliveDefaultInterval
}

// startKeepalive probes client in the background until the connection ends.
// The goroutines it starts exit when the client closes, whether by the caller,
// the pool, the peer, or the keepalive itself, so pooled and one-shot clients
// alike never leak them.
func startKeepalive(client *gossh.Client) {
	interval := KeepaliveInterval()
	if interval <= 0 {
		return
	}
	go runKeepalive(client, interval, keepaliveMaxMisses)
}

// runKeepalive sends keepalive@openssh.com with wantReply every interval and
// closes the client after maxMisses consecutive probes without a reply. Only
// one probe is ever outstanding, so a silent peer cannot pile up goroutines.
// Closing the client makes in-flight sessions fail with a transport error,
// which the run layer classifies as connection_lost. It returns once the
// client's connection has ended.
func runKeepalive(client *gossh.Client, interval time.Duration, maxMisses int) {
	closed := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(closed)
	}()

	replies := make(chan error, 1)
	inflight := false
	misses := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-closed:
			return
		case <-ticker.C:
		}
		if inflight {
			select {
			case err := <-replies:
				// The probe was answered (any reply), so it is no longer in
				// flight and a fresh one is sent below.
				if err != nil {
					_ = client.Close()
					return
				}
				misses = 0
			default:
				misses++
				if misses >= maxMisses {
					_ = client.Close()
					return
				}
				continue
			}
		}
		inflight = true
		go func() {
			// A reply of any kind (even "unsupported") proves liveness; only a
			// transport error means the connection is gone. SendRequest returns
			// an error when the client closes, so this goroutine also ends.
			_, _, err := client.SendRequest(keepaliveRequest, true, nil)
			replies <- err
		}()
	}
}
