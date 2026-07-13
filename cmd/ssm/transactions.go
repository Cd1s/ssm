package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"ssm/internal/config"
)

type pendingMutationView struct {
	ID        string `json:"id"`
	Alias     string `json:"alias"`
	Operation string `json:"operation"`
	CreatedAt string `json:"created_at"`
}

func newTransactionID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate transaction id: %w", err)
	}
	return "tx_" + hex.EncodeToString(raw), nil
}

func appendHostMutation(before, after *config.Vault, result *hostMutationResult) error {
	if !result.Changed {
		return nil
	}
	id, err := newTransactionID()
	if err != nil {
		return err
	}
	if after.PendingBase == nil {
		after.PendingBase = snapshotInventory(before)
	}
	mutation := config.PendingMutation{
		ID: id, Alias: result.Host.Name, Operation: result.Action,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		KeysBefore: append([]config.SSHKey(nil), before.Keys...),
		KeysAfter:  append([]config.SSHKey(nil), after.Keys...),
	}
	if idx := exactConnectionIndex(before, result.Host.Name); idx >= 0 {
		value := before.Connections[idx]
		mutation.Before = &value
	}
	if idx := exactConnectionIndex(after, result.Host.Name); idx >= 0 {
		value := after.Connections[idx]
		mutation.After = &value
	}
	after.PendingMutations = append(after.PendingMutations, mutation)
	result.TransactionID = id
	return nil
}

func snapshotInventory(v *config.Vault) *config.InventorySnapshot {
	return &config.InventorySnapshot{
		Connections: append([]config.Connection(nil), v.Connections...),
		Keys:        append([]config.SSHKey(nil), v.Keys...),
	}
}

func pendingMutationViews(v *config.Vault) []pendingMutationView {
	views := make([]pendingMutationView, 0, len(v.PendingMutations))
	for _, mutation := range v.PendingMutations {
		views = append(views, pendingMutationView{ID: mutation.ID, Alias: mutation.Alias, Operation: mutation.Operation, CreatedAt: mutation.CreatedAt})
	}
	return views
}

func publishProjection(v *config.Vault, only string) (*config.Vault, []config.PendingMutation, error) {
	if v.PendingBase == nil || len(v.PendingMutations) == 0 {
		return inventoryOnly(v), nil, nil
	}
	selected := make([]config.PendingMutation, 0)
	if only == "" {
		selected = append(selected, v.PendingMutations...)
	} else {
		selectedIndex := -1
		for i, mutation := range v.PendingMutations {
			if mutation.ID == only {
				selectedIndex = i
				break
			}
		}
		if selectedIndex < 0 {
			return nil, nil, fmt.Errorf("pending transaction %q not found", only)
		}
		for i := 0; i < selectedIndex; i++ {
			if v.PendingMutations[i].Alias == v.PendingMutations[selectedIndex].Alias {
				return nil, nil, fmt.Errorf("transaction %q depends on earlier pending transaction %q for alias %q", only, v.PendingMutations[i].ID, v.PendingMutations[i].Alias)
			}
		}
		selected = append(selected, v.PendingMutations[selectedIndex])
	}

	projected := &config.Vault{
		Connections: append([]config.Connection(nil), v.PendingBase.Connections...),
		Keys:        append([]config.SSHKey(nil), v.PendingBase.Keys...),
	}
	for _, mutation := range selected {
		applyMutation(projected, mutation)
	}
	return projected, selected, nil
}

func applyMutation(v *config.Vault, mutation config.PendingMutation) {
	idx := exactConnectionIndex(v, mutation.Alias)
	switch {
	case mutation.After == nil:
		if idx >= 0 {
			v.Connections = append(v.Connections[:idx], v.Connections[idx+1:]...)
		}
	case idx >= 0:
		v.Connections[idx] = *mutation.After
	default:
		v.Connections = append(v.Connections, *mutation.After)
	}
	applyKeyDelta(v, mutation.KeysBefore, mutation.KeysAfter)
	sort.SliceStable(v.Connections, func(i, j int) bool { return v.Connections[i].Name < v.Connections[j].Name })
}

func applyKeyDelta(v *config.Vault, before, after []config.SSHKey) {
	beforeByName := make(map[string]config.SSHKey, len(before))
	afterByName := make(map[string]config.SSHKey, len(after))
	for _, key := range before {
		beforeByName[key.Name] = key
	}
	for _, key := range after {
		afterByName[key.Name] = key
	}
	for name, previous := range beforeByName {
		next, exists := afterByName[name]
		if exists && next == previous {
			continue
		}
		removeKeyByName(v, name)
		if exists {
			v.Keys = append(v.Keys, next)
		}
	}
	for name, next := range afterByName {
		if _, existed := beforeByName[name]; !existed {
			removeKeyByName(v, name)
			v.Keys = append(v.Keys, next)
		}
	}
	sort.SliceStable(v.Keys, func(i, j int) bool { return v.Keys[i].Name < v.Keys[j].Name })
}

func inventoryOnly(v *config.Vault) *config.Vault {
	return &config.Vault{Connections: append([]config.Connection(nil), v.Connections...), Keys: append([]config.SSHKey(nil), v.Keys...)}
}

func markPublished(v *config.Vault, selected []config.PendingMutation, projected *config.Vault) {
	if len(selected) == 0 {
		return
	}
	published := make(map[string]bool, len(selected))
	for _, mutation := range selected {
		published[mutation.ID] = true
	}
	remaining := v.PendingMutations[:0]
	for _, mutation := range v.PendingMutations {
		if !published[mutation.ID] {
			remaining = append(remaining, mutation)
		}
	}
	v.PendingMutations = remaining
	if len(remaining) == 0 {
		v.PendingBase = nil
	} else {
		v.PendingBase = snapshotInventory(projected)
	}
}
