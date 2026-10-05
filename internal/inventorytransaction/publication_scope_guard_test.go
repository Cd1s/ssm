package inventorytransaction

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	"ssm/internal/config"
	"ssm/internal/synctransaction"
)

func TestMatchesRecovery(t *testing.T) {
	tests := []struct {
		name     string
		only     string
		recovery *PublicationRecovery
		want     bool
	}{
		{name: "all scope", recovery: &PublicationRecovery{Scope: "all", TransactionIDs: []string{"alpha", "bravo"}}, want: true},
		{name: "all with only", only: "alpha", recovery: &PublicationRecovery{Scope: "all", TransactionIDs: []string{"alpha"}}, want: true},
		{name: "only exact", only: "alpha", recovery: &PublicationRecovery{Scope: "only", TransactionIDs: []string{"alpha"}}, want: true},
		{name: "only ignores scope", only: "alpha", recovery: &PublicationRecovery{Scope: "all", TransactionIDs: []string{"alpha"}}, want: true},
		{name: "all rejects only scope", recovery: &PublicationRecovery{Scope: "only", TransactionIDs: []string{"alpha"}}, want: false},
		{name: "only rejects multiple", only: "alpha", recovery: &PublicationRecovery{Scope: "only", TransactionIDs: []string{"alpha", "bravo"}}, want: false},
		{name: "only rejects other id", only: "bravo", recovery: &PublicationRecovery{Scope: "only", TransactionIDs: []string{"alpha"}}, want: false},
		{name: "all rejects empty scope", recovery: &PublicationRecovery{Scope: "", TransactionIDs: []string{"alpha"}}, want: false},
		{name: "nil recovery", only: "alpha", want: false},
		{name: "empty ids", only: "alpha", recovery: &PublicationRecovery{Scope: "all"}, want: false},
		{name: "all accepts empty recorded ids", recovery: &PublicationRecovery{Scope: "all"}, want: true},
		{name: "empty recorded id is not all scope", recovery: &PublicationRecovery{Scope: "only", TransactionIDs: []string{""}}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesRecovery(tt.only, tt.recovery); got != tt.want {
				t.Fatalf("matchesRecovery(%q, %#v) = %v, want %v", tt.only, tt.recovery, got, tt.want)
			}
		})
	}
}

type publicationEntropyObserver struct {
	reader io.Reader
	reads  int
}

func (observer *publicationEntropyObserver) Read(buffer []byte) (int, error) {
	observer.reads++
	return observer.reader.Read(buffer)
}

func TestPublicationScopeGuardRejectsBeforeEncryption(t *testing.T) {
	t.Setenv("SSM_CONFIG_DIR", t.TempDir())
	alpha := config.Connection{Name: "alpha", Host: "alpha.example", Port: 22, User: "root"}
	bravo := config.Connection{Name: "bravo", Host: "bravo.example", Port: 22, User: "root"}
	value := &config.Vault{
		Connections: []config.Connection{alpha, bravo}, PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{
			{ID: "alpha", Alias: "alpha", Operation: "created", CreatedAt: "2026-07-29T00:00:01Z", After: &alpha},
			{ID: "bravo", Alias: "bravo", Operation: "created", CreatedAt: "2026-07-29T00:00:02Z", After: &bravo},
		},
	}
	if err := config.Save(value, "scope-guard-test-passphrase"); err != nil {
		t.Fatal(err)
	}
	intent := publishingIntent{Version: publishingIntentVersion, State: intentPrepared, Scope: "only", TransactionIDs: []string{"alpha"}, Transactions: publishingIntentTransactions(value.PendingMutations[:1]), TargetIdentity: strings.Repeat("a", 64)}
	if err := savePublishingIntent(intent); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(config.Path()) //nolint:gosec // config path is constrained to this test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	session, err := BeginPublication()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	observer := &publicationEntropyObserver{reader: rand.Reader}
	rand.Reader = observer
	defer func() { rand.Reader = observer.reader }()
	transaction := New(Options{MasterPass: "scope-guard-test-passphrase", Sync: synctransaction.New(synctransaction.Options{Offline: true})})
	_, err = session.Publish(transaction, value, "bravo")
	if observer.reads != 0 {
		t.Fatalf("scope mismatch reached encryption: entropy reads = %d", observer.reads)
	}
	if err != errPublicationScopePending {
		t.Fatalf("scope mismatch error = %v, want pending-scope rejection", err)
	}
	after, err := os.ReadFile(config.Path()) //nolint:gosec // config path is constrained to this test's temporary directory
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("scope mismatch changed the encrypted vault")
	}
	if _, err := os.Stat(publishingIntentPath()); !os.IsNotExist(err) {
		t.Fatalf("prepared recovery intent was recreated: %v", err)
	}
}
