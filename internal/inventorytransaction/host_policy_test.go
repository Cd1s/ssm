package inventorytransaction_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
)

func TestInventoryTransactionHostCandidateSafety(t *testing.T) {
	t.Run("update preserves fields and normalizes legacy port", func(t *testing.T) {
		key := config.SSHKey{Name: "deploy", PrivateKey: "material"}
		base := &config.Vault{
			Connections: []config.Connection{{
				Name: "prod-api", Host: "old.example", User: "root", Group: "prod", KeyName: key.Name,
			}},
			Keys: []config.SSHKey{key},
		}
		transaction, passphrase := newHostPolicyFixture(t, base)
		address := "new.example"
		receipt, err := transaction.ApplyHost(base, inventorytransaction.HostChange{
			Action: inventorytransaction.HostUpdate,
			Alias:  "prod-api",
			Host:   &address,
		})
		if err != nil {
			t.Fatal(err)
		}
		persisted := loadHostPolicyVault(t, passphrase)
		got := persisted.Connections[0]
		if !receipt.Changed || got.Host != address || got.Port != 22 ||
			got.User != "root" || got.Group != "prod" || got.KeyName != key.Name {
			t.Fatal("candidate update changed unspecified fields or failed legacy port normalization")
		}
	})

	t.Run("key file cannot overwrite shared or unrelated saved key", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "id_ed25519")
		if err := os.WriteFile(keyPath, testInventoryPrivateKey(t), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Run("shared", func(t *testing.T) {
			base := &config.Vault{
				Connections: []config.Connection{
					{Name: "one", Host: "one.example", Port: 22, User: "root", KeyName: "shared"},
					{Name: "two", Host: "two.example", Port: 22, User: "root", KeyName: "shared"},
				},
				Keys: []config.SSHKey{{Name: "shared", PrivateKey: "different-material"}},
			}
			transaction, passphrase := newHostPolicyFixture(t, base)
			if _, err := transaction.ApplyHost(base, inventorytransaction.HostChange{
				Action:  inventorytransaction.HostUpdate,
				Alias:   "one",
				KeyFile: &keyPath,
			}); err == nil || !strings.Contains(err.Error(), "shared") {
				t.Fatalf("shared key overwrite error = %v", err)
			}
			if got := loadHostPolicyVault(t, passphrase); !reflect.DeepEqual(got, base) {
				t.Fatal("shared key conflict changed the encrypted candidate")
			}
		})
		t.Run("unrelated", func(t *testing.T) {
			base := &config.Vault{
				Keys: []config.SSHKey{{Name: "new-host", PrivateKey: "unrelated-material"}},
			}
			transaction, passphrase := newHostPolicyFixture(t, base)
			address, user := "new.example", "root"
			if _, err := transaction.ApplyHost(base, inventorytransaction.HostChange{
				Action:  inventorytransaction.HostAdd,
				Alias:   "new-host",
				Host:    &address,
				User:    &user,
				KeyFile: &keyPath,
			}); err == nil || !strings.Contains(err.Error(), "--key-name") {
				t.Fatalf("unrelated key overwrite error = %v", err)
			}
			if got := loadHostPolicyVault(t, passphrase); !reflect.DeepEqual(got, base) {
				t.Fatal("unrelated key conflict changed the encrypted candidate")
			}
		})
	})

	t.Run("prune removes only the last saved-key reference", func(t *testing.T) {
		base := &config.Vault{
			Connections: []config.Connection{
				{Name: "one", Host: "one.example", Port: 22, User: "root", KeyName: "shared"},
				{Name: "two", Host: "two.example", Port: 22, User: "root", KeyName: "shared"},
			},
			Keys: []config.SSHKey{{Name: "shared", PrivateKey: "material"}},
		}
		transaction, passphrase := newHostPolicyFixture(t, base)
		first, err := transaction.ApplyHost(base, inventorytransaction.HostChange{
			Action: inventorytransaction.HostRemove, Alias: "one", PruneKey: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		afterFirst := loadHostPolicyVault(t, passphrase)
		if first.KeyPruned != "" || len(afterFirst.Keys) != 1 {
			t.Fatal("shared key was pruned before its last reference")
		}
		second, err := transaction.ApplyHost(afterFirst, inventorytransaction.HostChange{
			Action: inventorytransaction.HostRemove, Alias: "two", PruneKey: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		afterSecond := loadHostPolicyVault(t, passphrase)
		if second.KeyPruned != "shared" || len(afterSecond.Keys) != 0 {
			t.Fatal("last-reference saved key was not pruned")
		}
	})

	t.Run("unsafe alias address and oversized credential are rejected", func(t *testing.T) {
		base := &config.Vault{
			Keys: []config.SSHKey{{Name: "deploy", PrivateKey: "material"}},
		}
		transaction, passphrase := newHostPolicyFixture(t, base)
		user, savedKey := "root", "deploy"
		for _, fixture := range []struct {
			alias   string
			address string
		}{
			{alias: "bad alias", address: "example.com"},
			{alias: "good-alias", address: "root@example.com"},
			{alias: "good-alias", address: "https://example.com"},
		} {
			address := fixture.address
			if _, err := transaction.ApplyHost(base, inventorytransaction.HostChange{
				Action:   inventorytransaction.HostAdd,
				Alias:    fixture.alias,
				Host:     &address,
				User:     &user,
				SavedKey: &savedKey,
			}); err == nil {
				t.Fatal("unsafe host candidate was accepted")
			}
		}
		oversizedPath := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(oversizedPath, make([]byte, (1<<20)+1), 0o600); err != nil {
			t.Fatal(err)
		}
		address := "example.com"
		if _, err := transaction.ApplyHost(base, inventorytransaction.HostChange{
			Action:       inventorytransaction.HostAdd,
			Alias:        "oversized",
			Host:         &address,
			User:         &user,
			PasswordFile: &oversizedPath,
		}); err == nil {
			t.Fatal("oversized credential file was accepted")
		}
		if got := loadHostPolicyVault(t, passphrase); !reflect.DeepEqual(got, base) {
			t.Fatal("rejected candidates changed the encrypted vault")
		}
	})
}

func newHostPolicyFixture(
	t *testing.T,
	vault *config.Vault,
) (*inventorytransaction.Transaction, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	passphrase := strings.Repeat("host-unlock-", 4)
	if err := config.Save(vault, passphrase); err != nil {
		t.Fatal(err)
	}
	return inventorytransaction.New(inventorytransaction.Options{MasterPass: passphrase}), passphrase
}

func loadHostPolicyVault(t *testing.T, passphrase string) *config.Vault {
	t.Helper()
	vault, err := config.Load(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

func testInventoryPrivateKey(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(privateKey, "ssm-test")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}
