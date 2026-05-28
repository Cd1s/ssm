package config

import "testing"

func TestMergeVaultsKeepsStableOrderAndRemoteWinsConflicts(t *testing.T) {
	local := &Vault{
		Connections: []Connection{
			{Name: "alpha", Host: "local-alpha"},
			{Name: "shared", Host: "local-shared"},
		},
		Keys: []SSHKey{
			{Name: "key-a", PrivateKey: "local-a"},
			{Name: "shared-key", PrivateKey: "local-shared"},
		},
	}
	remote := &Vault{
		Connections: []Connection{
			{Name: "shared", Host: "remote-shared"},
			{Name: "beta", Host: "remote-beta"},
		},
		Keys: []SSHKey{
			{Name: "shared-key", PrivateKey: "remote-shared"},
			{Name: "key-b", PrivateKey: "remote-b"},
		},
	}

	merged := MergeVaults(local, remote)

	if got := connectionNames(merged.Connections); got != "alpha,shared,beta" {
		t.Fatalf("connection order = %q, want alpha,shared,beta", got)
	}
	if merged.Connections[1].Host != "remote-shared" {
		t.Fatalf("shared host = %q, want remote value", merged.Connections[1].Host)
	}
	if got := keyNames(merged.Keys); got != "key-a,shared-key,key-b" {
		t.Fatalf("key order = %q, want key-a,shared-key,key-b", got)
	}
	if merged.Keys[1].PrivateKey != "remote-shared" {
		t.Fatalf("shared key = %q, want remote value", merged.Keys[1].PrivateKey)
	}
}

func connectionNames(conns []Connection) string {
	out := ""
	for i, c := range conns {
		if i > 0 {
			out += ","
		}
		out += c.Name
	}
	return out
}

func keyNames(keys []SSHKey) string {
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += k.Name
	}
	return out
}
