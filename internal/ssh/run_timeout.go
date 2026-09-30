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

// execWatch enforces --exec-timeout on one session: at the deadline it sends
// SIGTERM, and after the grace period it closes the session so Run returns
// even when the remote ignores the signal. It records that sshctl itself
// ended the command, so the EOF or missing exit status that follows is
// reported as exec_timeout and never as connection_lost.
type execWatch struct {
	done     chan struct{}
	finished chan struct{}
	stopOnce sync.Once

	mu        sync.Mutex
	completed bool
	timedOut  bool
}

func watchExecTimeout(session *gossh.Session, timeout time.Duration) *execWatch {
	if timeout <= 0 {
		return nil
	}
	watch := &execWatch{done: make(chan struct{}), finished: make(chan struct{})}
	go watch.enforce(session, timeout)
	return watch
}

func (w *execWatch) enforce(session *gossh.Session, timeout time.Duration) {
	defer close(w.finished)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	select {
	case <-w.done:
		return
	case <-deadline.C:
	}
	w.mu.Lock()
	if w.completed {
		w.mu.Unlock()
		return
	}
	w.timedOut = true
	w.mu.Unlock()
	_ = session.Signal(gossh.SIGTERM)

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

// expired reports whether the deadline fired before the command returned.
func (w *execWatch) expired() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.timedOut
}

// timeoutApplies reports whether a Run that returned err was ended by the exec
// deadline. The timer can fire just before a command finishes on its own; if
// Run returned success the command completed normally and SIGTERM (or the
// session close) had no effect, so it is not an exec_timeout.
func (w *execWatch) timeoutApplies(err error) bool {
	return err != nil && w.expired()
}
