package ssh

import (
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// execTimeoutGrace is how long a command that received SIGTERM at its
// --exec-timeout deadline may keep running (and flush output) before sshctl
// closes the session. It mirrors interruptGrace for local signals, but is
// longer because a deadline is normally hit by busy commands that need time to
// clean up.
const execTimeoutGrace = 5 * time.Second

// execSession is the part of an SSH session the exec deadline needs.
type execSession interface {
	Signal(sig gossh.Signal) error
	Close() error
}

// execWatch enforces --exec-timeout on one session: at the deadline it sends
// SIGTERM, and after the grace period it closes the session so Run returns
// even when the remote ignores the signal. Once SIGTERM was actually sent the
// result is exec_timeout regardless of how the command then ends (killed,
// trapped and exited 0, or closed by sshctl), so the EOF or exit status that
// follows is never reported as connection_lost or as a normal result. If the
// command completed before the signal was sent, its real result stands.
type execWatch struct {
	done     chan struct{}
	finished chan struct{}
	stopOnce sync.Once

	mu         sync.Mutex
	completed  bool
	signalSent bool
}

func watchExecTimeout(session *gossh.Session, timeout time.Duration) *execWatch {
	if timeout <= 0 {
		return nil
	}
	return newExecWatch(session, timeout)
}

func newExecWatch(session execSession, timeout time.Duration) *execWatch {
	watch := &execWatch{done: make(chan struct{}), finished: make(chan struct{})}
	go watch.enforce(session, timeout)
	return watch
}

func (w *execWatch) enforce(session execSession, timeout time.Duration) {
	defer close(w.finished)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	select {
	case <-w.done:
		return
	case <-deadline.C:
	}
	w.mu.Lock()
	completed := w.completed
	w.mu.Unlock()
	if completed {
		return
	}
	if err := session.Signal(gossh.SIGTERM); err != nil {
		// The signal never reached the remote (the session is already gone),
		// so the deadline did not end the command.
		return
	}
	w.mu.Lock()
	w.signalSent = true
	w.mu.Unlock()

	grace := time.NewTimer(execTimeoutGrace)
	defer grace.Stop()
	select {
	case <-w.done:
	case <-grace.C:
		_ = session.Close()
	}
}

// complete records that session.Run returned before stopping the watcher.
// Keeping this transition separate from stop closes the deadline race where a
// command completed just as the timer goroutine was being scheduled.
func (w *execWatch) complete() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.completed = true
	w.mu.Unlock()
}

// stop ends the watch once the remote command has returned.
func (w *execWatch) stop() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() { close(w.done) })
	<-w.finished
}

// timeoutApplies reports whether the exec deadline ended the command: SIGTERM
// was sent because the deadline passed. The outcome of the command afterwards
// (err) does not matter; a command that traps TERM and exits 0 still timed out.
func (w *execWatch) timeoutApplies() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.signalSent
}
