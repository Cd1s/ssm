package inventorytransaction

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

func TestPendingLedgerKeyDeltaPreservesConsumers(t *testing.T) {
	base := &config.Vault{
		Connections: []config.Connection{
			{Name: "base-one", Host: "one.example", Port: 22, User: "root", KeyName: "base-one"},
			{Name: "base-two", Host: "two.example", Port: 22, User: "root", KeyName: "base-two"},
		},
		Keys: []config.SSHKey{
			{Name: "base-one", PrivateKey: "one-material"},
			{Name: "base-two", PrivateKey: "two-material"},
			{Name: "spare", PrivateKey: "spare-material"},
		},
	}
	transaction, passphrase, keyFiles := newKeyDeltaFixture(t, base)
	random := rand.New(rand.NewSource(20261005)) //nolint:gosec // fixed seed keeps the sequence deterministic; not security related
	legacy := cloneVault(base)
	step := 0
	for round := 0; round < 2; round++ {
		for _, action := range random.Perm(5) {
			before := loadKeyDeltaVault(t, passphrase)
			step++
			var err error
			switch action {
			case 0:
				address, user := "192.0.2.1", "root"
				alias, keyName := fmt.Sprintf("host-%02d", step), fmt.Sprintf("key-%02d", step)
				_, err = transaction.ApplyHost(before, HostChange{
					Action: HostAdd, Alias: alias, Host: &address, User: &user,
					KeyFile: &keyFiles[round], KeyName: &keyName,
				})
			case 1:
				connection := before.Connections[random.Intn(len(before.Connections))]
				group := fmt.Sprintf("group-%02d", step)
				change := HostChange{Action: HostUpdate, Alias: connection.Name, Group: &group, KeyFile: &keyFiles[round]}
				if round == 1 {
					keyName := fmt.Sprintf("renamed-%02d", step)
					change.KeyName = &keyName
				}
				_, err = transaction.ApplyHost(before, change)
			case 2:
				connection := before.Connections[random.Intn(len(before.Connections))]
				_, err = transaction.ApplyHost(before, HostChange{
					Action: HostRemove, Alias: connection.Name, PruneKey: round == 1,
				})
			case 3:
				unreferenced := make([]string, 0)
				for _, key := range before.Keys {
					if keyReferenceCount(before, key.Name) == 0 {
						unreferenced = append(unreferenced, key.Name)
					}
				}
				if len(unreferenced) == 0 {
					t.Fatal("sequence needs an unreferenced saved key")
				}
				_, err = transaction.RemoveSavedKey(before, unreferenced[random.Intn(len(unreferenced))])
			case 4:
				imported := inventoryOnly(before)
				if round == 1 {
					for _, key := range before.Keys {
						if keyReferenceCount(before, key.Name) == 0 {
							removeKeyByName(imported, key.Name)
							break
						}
					}
				}
				keyIndex := random.Intn(len(imported.Keys))
				imported.Keys[keyIndex].PrivateKey = fmt.Sprintf("import-value-%02d", step)
				name := fmt.Sprintf("imported-%02d", step)
				imported.Keys = append(imported.Keys,
					config.SSHKey{Name: name, PrivateKey: "imported-material"},
					config.SSHKey{Name: fmt.Sprintf("spare-%02d", step), PrivateKey: "spare-material"},
				)
				imported.Connections = append(imported.Connections, config.Connection{
					Name: name, Host: "import.example", Port: 22, User: "root", KeyName: name,
				})
				_, err = transaction.ApplyImport(before, imported, round == 1)
			}
			if err != nil {
				t.Fatalf("step %d action %d: %v", step, action, err)
			}
			after := loadKeyDeltaVault(t, passphrase)
			mutation := after.PendingMutations[len(after.PendingMutations)-1]
			expectedBefore, expectedAfter := testKeyDelta(before.Keys, after.Keys)
			if !reflect.DeepEqual(mutation.KeysBefore, expectedBefore) || !reflect.DeepEqual(mutation.KeysAfter, expectedAfter) {
				t.Fatalf("step %d recorded unchanged saved keys or lost changed keys", step)
			}
			fullMutation := mutation
			fullMutation.KeysBefore = append([]config.SSHKey(nil), before.Keys...)
			fullMutation.KeysAfter = append([]config.SSHKey(nil), after.Keys...)
			legacy.Connections = after.Connections
			legacy.Keys = after.Keys
			legacy.PendingBase = after.PendingBase
			legacy.PendingMutations = append(legacy.PendingMutations, fullMutation)
			assertKeyDeltaConsumersEqual(t, legacy, after)
		}
	}
}

func TestPendingLedgerLegacyKeysRemainReadableAndAppendable(t *testing.T) {
	base := config.InventorySnapshot{Keys: []config.SSHKey{{Name: "unchanged", PrivateKey: "unchanged-material"}}}
	connection := config.Connection{Name: "old-host", Host: "old.example", Port: 22, User: "root", KeyName: "old"}
	legacy := config.PendingMutation{
		ID: "legacy", Alias: connection.Name, Operation: "created", After: &connection,
		KeysBefore: append([]config.SSHKey(nil), base.Keys...),
		KeysAfter:  append(append([]config.SSHKey(nil), base.Keys...), config.SSHKey{Name: "old", PrivateKey: "old-material"}),
	}
	vault := &config.Vault{
		Connections: []config.Connection{connection}, Keys: legacy.KeysAfter,
		PendingBase: &base, PendingMutations: []config.PendingMutation{legacy},
	}
	transaction, passphrase, keyFiles := newKeyDeltaFixture(t, vault)
	before := loadKeyDeltaVault(t, passphrase)
	if !reflect.DeepEqual(before.PendingMutations[0], legacy) {
		t.Fatal("legacy full snapshots changed during encrypted load")
	}
	address, user, savedKey := "new.example", "root", "old"
	receipt, err := transaction.ApplyHost(before, HostChange{
		Action: HostAdd, Alias: "new-host", Host: &address, User: &user, SavedKey: &savedKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	after := loadKeyDeltaVault(t, passphrase)
	dependencies, preflightErr := Preflight(after, receipt.TransactionID)
	if preflightErr == nil || len(dependencies) != 1 || dependencies[0].ID != legacy.ID || dependencies[0].Reason != "saved_key_create" {
		t.Fatal("appended host lost its dependency on legacy saved-key creation")
	}
	mutation := after.PendingMutations[1]
	if len(mutation.KeysBefore) != 0 || len(mutation.KeysAfter) != 0 {
		t.Fatal("appended host unnecessarily recorded unchanged keys")
	}
	keyName := "brand-new"
	if _, err := transaction.ApplyHost(after, HostChange{
		Action: HostAdd, Alias: keyName, Host: &address, User: &user, KeyFile: &keyFiles[0], KeyName: &keyName,
	}); err != nil {
		t.Fatal(err)
	}
	after = loadKeyDeltaVault(t, passphrase)
	if !reflect.DeepEqual(after.PendingMutations[0], legacy) || len(after.PendingMutations[2].KeysAfter) != 1 {
		t.Fatal("appending delta keys rewrote legacy snapshots or recorded unchanged keys")
	}
	projected, err := project(after, "")
	if err != nil {
		t.Fatal(err)
	}
	current := inventoryOnly(after)
	sort.Slice(current.Connections, func(left, right int) bool { return current.Connections[left].Name < current.Connections[right].Name })
	sort.Slice(current.Keys, func(left, right int) bool { return current.Keys[left].Name < current.Keys[right].Name })
	if !reflect.DeepEqual(projected.Vault, current) {
		t.Fatal("legacy and delta mutations did not reconstruct the current inventory")
	}
}

func assertKeyDeltaConsumersEqual(t *testing.T, full, delta *config.Vault) {
	t.Helper()
	targets := []string{""}
	for index, mutation := range full.PendingMutations {
		targets = append(targets, mutation.ID)
		if !reflect.DeepEqual(directDependencyEdges(full.PendingMutations, index), directDependencyEdges(delta.PendingMutations, index)) {
			t.Fatalf("dependency edges differ at %s", mutation.ID)
		}
		fullProjection, fullErr := projectTransactionIDs(full, []string{mutation.ID})
		deltaProjection, deltaErr := projectTransactionIDs(delta, []string{mutation.ID})
		normalizeKeyDeltaProjection(&fullProjection)
		if fmt.Sprint(fullErr) != fmt.Sprint(deltaErr) || !reflect.DeepEqual(fullProjection, deltaProjection) {
			t.Fatalf("transaction-ID projection differs at %s", mutation.ID)
		}
		for _, key := range append(append([]config.SSHKey(nil), mutation.KeysBefore...), mutation.KeysAfter...) {
			deltaMutation := delta.PendingMutations[index]
			if keyChange(mutation.KeysBefore, mutation.KeysAfter, key.Name) != keyChange(deltaMutation.KeysBefore, deltaMutation.KeysAfter, key.Name) {
				t.Fatalf("key lifecycle differs at %s", mutation.ID)
			}
		}
	}
	for _, target := range targets {
		fullDependencies, fullErr := Preflight(full, target)
		deltaDependencies, deltaErr := Preflight(delta, target)
		if fmt.Sprint(fullErr) != fmt.Sprint(deltaErr) || !reflect.DeepEqual(fullDependencies, deltaDependencies) {
			t.Fatalf("Preflight differs at %q", target)
		}
		fullProjection, fullErr := project(full, target)
		deltaProjection, deltaErr := project(delta, target)
		normalizeKeyDeltaProjection(&fullProjection)
		if fmt.Sprint(fullErr) != fmt.Sprint(deltaErr) || !reflect.DeepEqual(fullProjection, deltaProjection) {
			t.Fatalf("projection differs at %q", target)
		}
	}
}

func normalizeKeyDeltaProjection(projected *projection) {
	projected.Selected = append([]config.PendingMutation(nil), projected.Selected...)
	for index := range projected.Selected {
		mutation := &projected.Selected[index]
		mutation.KeysBefore, mutation.KeysAfter = testKeyDelta(mutation.KeysBefore, mutation.KeysAfter)
	}
}

func newKeyDeltaFixture(t *testing.T, vault *config.Vault) (*Transaction, string, [2]string) {
	t.Helper()
	t.Setenv("SSM_CONFIG_DIR", t.TempDir())
	passphrase := "ledger-key-delta-test-passphrase"
	if err := config.Save(vault, passphrase); err != nil {
		t.Fatal(err)
	}
	var keyFiles [2]string
	for index := range keyFiles {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(index + 1)
		block, err := gossh.MarshalPrivateKey(ed25519.NewKeyFromSeed(seed), "ledger-test")
		if err != nil {
			t.Fatal(err)
		}
		keyFiles[index] = filepath.Join(t.TempDir(), "id_ed25519")
		if err := os.WriteFile(keyFiles[index], pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return New(Options{
		MasterPass: passphrase,
		Random:     rand.New(rand.NewSource(20261005)), //nolint:gosec // fixed seed keeps the sequence deterministic; not security related
		Now:        func() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) },
	}), passphrase, keyFiles
}

func loadKeyDeltaVault(t *testing.T, passphrase string) *config.Vault {
	t.Helper()
	vault, err := config.Load(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

func testKeyDelta(before, after []config.SSHKey) ([]config.SSHKey, []config.SSHKey) {
	beforeByName := make(map[string]config.SSHKey, len(before))
	afterByName := make(map[string]config.SSHKey, len(after))
	names := make(map[string]bool, len(before)+len(after))
	for _, key := range before {
		beforeByName[key.Name] = key
		names[key.Name] = true
	}
	for _, key := range after {
		afterByName[key.Name] = key
		names[key.Name] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		if previous, ok := beforeByName[name]; !ok {
			ordered = append(ordered, name)
		} else if next, exists := afterByName[name]; !exists || next != previous {
			ordered = append(ordered, name)
		}
	}
	sort.Strings(ordered)
	var changedBefore, changedAfter []config.SSHKey
	for _, name := range ordered {
		if key, ok := beforeByName[name]; ok {
			changedBefore = append(changedBefore, key)
		}
		if key, ok := afterByName[name]; ok {
			changedAfter = append(changedAfter, key)
		}
	}
	return changedBefore, changedAfter
}
