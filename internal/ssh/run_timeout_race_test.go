package ssh

import (
	"errors"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

type fakeExecSession struct {
	mu        sync.Mutex
	signals   []gossh.Signal
	signalErr error
	closed    bool
}

func (f *fakeExecSession) Signal(sig gossh.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, sig)
	return f.signalErr
}

func (f *fakeExecSession) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeExecSession) signalCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.signals)
}

func TestExecTimeoutAppliesOnceSigtermWasSentEvenIfCommandExitsZero(t *testing.T) {
	session := &fakeExecSession{}
	watch := newExecWatch(session, 10*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for session.signalCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("SIGTERM was never sent")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The remote traps TERM and exits 0 during the grace period.
	watch.complete()
	watch.stop()
	if !watch.timeoutApplies() {
		t.Fatal("after SIGTERM was sent the result is exec_timeout even when the command exits 0")
	}
	if session.closed {
		t.Fatal("session must not be closed while the command finishes within the grace period")
	}
}

func TestExecTimeoutDoesNotApplyWhenCommandCompletedBeforeSignal(t *testing.T) {
	session := &fakeExecSession{}
	watch := newExecWatch(session, 30*time.Millisecond)
	watch.complete() // the command finished before the deadline goroutine ran
	time.Sleep(80 * time.Millisecond)
	watch.stop()
	if session.signalCount() != 0 {
		t.Fatalf("signals = %v, want none for a completed command", session.signals)
	}
	if watch.timeoutApplies() {
		t.Fatal("a command that completed before SIGTERM was sent must report its real result")
	}
}

func TestExecTimeoutDoesNotApplyWhenSignalCouldNotBeSent(t *testing.T) {
	session := &fakeExecSession{signalErr: errors.New("session closed")}
	watch := newExecWatch(session, 10*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for session.signalCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("signal not attempted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	watch.complete()
	watch.stop()
	if watch.timeoutApplies() {
		t.Fatal("SIGTERM was not delivered, so this is not an exec_timeout")
	}
	var none *execWatch
	if none.timeoutApplies() {
		t.Fatal("nil watch must never report a timeout")
	}
}
