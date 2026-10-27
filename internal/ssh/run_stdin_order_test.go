package ssh

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// serveDropbearLikeSession mimics dropbear: a session whose stdin reaches EOF
// before a command was started is closed, so the exec request fails and the
// command never runs. OpenSSH buffers that early EOF instead.
func serveDropbearLikeSession(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	var stdin bytes.Buffer
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&stdin, channel)
		close(stdinDone)
	}()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		select {
		case <-stdinDone:
			_ = req.Reply(false, nil)
			return
		case <-time.After(100 * time.Millisecond):
		}
		_ = req.Reply(true, nil)
		<-stdinDone
		_, _ = fmt.Fprintf(channel, "stdin=%q", stdin.String())
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

func TestRunForwardsStdinOnlyAfterTheCommandStarted(t *testing.T) {
	conn, vault, _ := startRunTestSSHServerWithSessionHandler(t, serveDropbearLikeSession, newTestSigner(t, "ed25519"))
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, conn)

	for _, input := range []string{"", "hello\n"} {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			stdinFile := filepath.Join(t.TempDir(), "stdin")
			if err := os.WriteFile(stdinFile, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			res := Run(conn, vault, RunOptions{
				Command:        "cat",
				StdinFile:      stdinFile,
				Capture:        true,
				NoReuse:        true,
				RequestedAlias: conn.Name,
				Mode:           "argv",
			})
			if !res.OK || res.Exit != 0 {
				t.Fatalf("run failed: %+v", res)
			}
			if want := fmt.Sprintf("stdin=%q", input); res.Stdout != want {
				t.Fatalf("stdout=%q want=%q", res.Stdout, want)
			}
		})
	}
}
