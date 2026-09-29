package ssh

import (
	"errors"
	"testing"
	"time"
)

func TestClosePoolBlocksReplacementUntilEveryPriorEntryIsClosed(t *testing.T) {
	ClosePool()
	t.Cleanup(ClosePool)

	old := lockPoolEntry("pool-close-order")

	closeDone := make(chan struct{})
	go func() {
		ClosePool()
		close(closeDone)
	}()

	// Give ClosePool the lock opportunity it needs to reach the deliberately
	// blocked old entry before attempting a replacement acquisition.
	time.Sleep(20 * time.Millisecond)
	acquired := make(chan *pooledClient, 1)
	go func() {
		acquired <- lockPoolEntry("pool-close-order")
	}()

	replacementEnteredEarly := false
	var replacement *pooledClient
	select {
	case replacement = <-acquired:
		replacementEnteredEarly = true
	case <-time.After(20 * time.Millisecond):
	}

	old.mu.Unlock()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("ClosePool did not finish after the prior entry was released")
	}

	if !replacementEnteredEarly {
		select {
		case replacement = <-acquired:
		case <-time.After(time.Second):
			t.Fatal("replacement acquisition did not resume after ClosePool")
		}
	}
	if replacementEnteredEarly {
		t.Fatal("replacement pool acquisition entered before every prior entry was closed")
	}
	if replacement == old {
		replacement.mu.Unlock()
		t.Fatal("replacement acquisition reused the closed pool entry")
	}
	replacement.mu.Unlock()
}

func TestSessionLimitErrorsAreRetriedWithoutEvictingHealthyPool(t *testing.T) {
	for _, message := range []string{
		"ssh: rejected: administratively prohibited",
		"ssh: channel open failed: open failed",
		"remote MaxSessions limit reached",
	} {
		if !isSessionLimitError(errors.New(message)) {
			t.Errorf("isSessionLimitError(%q) = false", message)
		}
	}
	if isSessionLimitError(errors.New("ssh: connection reset by peer")) {
		t.Fatal("connection loss must trigger eviction and redial")
	}
}
