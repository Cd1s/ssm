package inventorytransaction_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
)

func TestPendingLedgerKeyDeltaScalesLinearly(t *testing.T) {
	small := pendingLedgerSize(t, 8)
	large := pendingLedgerSize(t, 40)
	t.Logf("serialized pending ledger: 8 hosts=%d bytes, 40 hosts=%d bytes", small, large)
	if large >= small*5 {
		t.Fatalf("pending ledger grew too quickly: 8 hosts=%d bytes, 40 hosts=%d bytes", small, large)
	}
}

func pendingLedgerSize(t *testing.T, hosts int) int {
	t.Helper()
	t.Setenv("SSM_CONFIG_DIR", t.TempDir())
	passphrase := "ledger-size-test-passphrase"
	if err := config.Save(&config.Vault{}, passphrase); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, testPrivateKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, hosts*32)
	for block := 0; block < hosts*2; block++ {
		binary.BigEndian.PutUint64(seed[block*16:], uint64(block+1))
	}
	transaction := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: passphrase,
		Random:     bytes.NewReader(seed),
		Now:        func() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) },
	})
	for hostIndex := 1; hostIndex <= hosts; hostIndex++ {
		before, err := config.Load(passphrase)
		if err != nil {
			t.Fatal(err)
		}
		address, user := "192.0.2.1", "root"
		alias, keyName := fmt.Sprintf("host-%03d", hostIndex), fmt.Sprintf("key-%03d", hostIndex)
		if _, err := transaction.ApplyHost(before, inventorytransaction.HostChange{
			Action: inventorytransaction.HostAdd, Alias: alias, Host: &address, User: &user,
			KeyFile: &keyPath, KeyName: &keyName,
		}); err != nil {
			t.Fatal(err)
		}
	}
	vault, err := config.Load(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	ledger := struct {
		Base      *config.InventorySnapshot `json:"pending_base"`
		Mutations []config.PendingMutation  `json:"pending_mutations"`
	}{vault.PendingBase, vault.PendingMutations}
	encoded, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	return len(encoded)
}

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(privateKey, "ledger-size-test")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}
