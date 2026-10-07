package syncserver

import (
	"fmt"
	"testing"
)

func TestTokenHistoryOutlivesALargeFleet(t *testing.T) {
	var tokens []string
	for i := 0; i < 100; i++ {
		tokens = appendTokenHash(tokens, fmt.Sprintf("hash-%03d", i))
	}
	if len(tokens) != 100 || tokens[0] != "hash-000" {
		t.Fatalf("100 logins kept %d tokens, first %q; an earlier login must stay valid", len(tokens), tokens[0])
	}
}

func TestTokenHistoryIsBoundedAndKeepsNewest(t *testing.T) {
	var tokens []string
	for i := 0; i < maxTokenHashes+10; i++ {
		tokens = appendTokenHash(tokens, fmt.Sprintf("hash-%03d", i))
	}
	if len(tokens) != maxTokenHashes {
		t.Fatalf("history length = %d, want %d", len(tokens), maxTokenHashes)
	}
	if tokens[len(tokens)-1] != fmt.Sprintf("hash-%03d", maxTokenHashes+9) || tokens[0] != "hash-010" {
		t.Fatalf("history kept %q..%q, want the newest %d", tokens[0], tokens[len(tokens)-1], maxTokenHashes)
	}
	if again := appendTokenHash(tokens, tokens[3]); len(again) != maxTokenHashes {
		t.Fatalf("repeated token changed history length to %d", len(again))
	}
}
