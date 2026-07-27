//go:build windows

package ssh

import gossh "golang.org/x/crypto/ssh"

func serveRunTestSession(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		_ = request.Reply(false, nil)
		return
	}
}
