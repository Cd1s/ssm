package ssh

import (
	"os"
	"os/signal"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// interruptGrace is how long an interrupted run keeps draining remote output
// after forwarding the signal before it closes the session.
const interruptGrace = 2 * time.Second

// runInterrupt forwards a local SIGINT, SIGTERM, or SIGHUP to the remote
// command of a human-mode run so the caller exits through the normal output
// flush instead of being killed with output still in flight.
type runInterrupt struct {
	signals  chan os.Signal
	done     chan struct{}
	finished chan struct{}

	mu          sync.Mutex
	interrupted bool
	exit        int
}

func watchRunInterrupt(session *gossh.Session) *runInterrupt {
	watch := &runInterrupt{
		signals:  make(chan os.Signal, 2),
		done:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	signal.Notify(watch.signals, runInterruptSignals...)
	go watch.forward(session)
	return watch
}

func (w *runInterrupt) forward(session *gossh.Session) {
	defer close(w.finished)
	var received os.Signal
	select {
	case <-w.done:
		return
	case received = <-w.signals:
	}
	remote, exit := remoteInterrupt(received)
	w.mu.Lock()
	w.interrupted = true
	w.exit = exit
	w.mu.Unlock()
	_ = session.Signal(remote)

	grace := time.NewTimer(interruptGrace)
	defer grace.Stop()
	select {
	case <-w.done:
	case <-w.signals:
		_ = session.Close()
	case <-grace.C:
		_ = session.Close()
	}
}

// stop restores default signal handling once the remote command has ended.
func (w *runInterrupt) stop() {
	signal.Stop(w.signals)
	close(w.done)
	<-w.finished
}

// result reports whether a local signal interrupted the run and the
// conventional 128+signo exit status for it.
func (w *runInterrupt) result() (int, bool) {
	if w == nil {
		return 0, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exit, w.interrupted
}
