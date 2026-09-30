package ssh

import (
	"errors"
	"testing"
)

func TestExecWatchTimeoutOnlyAppliesWhenCommandWasEnded(t *testing.T) {
	watch := &execWatch{timedOut: true}
	if watch.timeoutApplies(nil) {
		t.Fatal("a command that exited 0 after the deadline fired must not be exec_timeout")
	}
	if !watch.timeoutApplies(errors.New("wait: remote command exited without exit status")) {
		t.Fatal("a command that ended with an error after the deadline must be exec_timeout")
	}
	if (&execWatch{}).timeoutApplies(errors.New("boom")) {
		t.Fatal("no deadline, no exec_timeout")
	}
	var none *execWatch
	if none.timeoutApplies(errors.New("boom")) {
		t.Fatal("nil watch must never report a timeout")
	}
}
