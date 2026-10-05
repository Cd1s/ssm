package synctransaction

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"ssm/internal/config"
)

const maxSuperseded = 64

var errRemoteSuperseded = fmt.Errorf("%w: remote vault is a version this machine already replaced (possible rollback); review, then pull --adopt-remote", ErrConflict)

type supersededLedger struct {
	Superseded []string `json:"superseded"`
}

func supersededPath() string {
	return filepath.Join(config.Dir(), "sync-superseded.json")
}

func loadSuperseded() []string {
	data, err := os.ReadFile(supersededPath()) //nolint:gosec // fixed private metadata path under the SSM config directory
	if err != nil {
		if !os.IsNotExist(err) {
			config.Debug("sync: superseded ledger read failed")
		}
		return nil
	}
	var ledger supersededLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		config.Debug("sync: superseded ledger decode failed")
		return nil
	}
	return ledger.Superseded
}

func recordSuperseded(old, next string) {
	if old == "" || next == "" || old == next {
		return
	}
	if err := withStateLock(func() error {
		identities := make([]string, 0, maxSuperseded+1)
		for _, identity := range loadSuperseded() {
			if identity != next && !slices.Contains(identities, identity) {
				identities = append(identities, identity)
			}
		}
		if !slices.Contains(identities, old) {
			identities = append(identities, old)
		}
		if len(identities) > maxSuperseded {
			identities = identities[len(identities)-maxSuperseded:]
		}
		data, err := json.Marshal(supersededLedger{Superseded: identities})
		if err != nil {
			return err
		}
		return config.WritePrivateFile(supersededPath(), append(data, '\n'))
	}); err != nil {
		config.Debug("sync: superseded ledger update failed")
	}
}

func isSuperseded(identity string) bool {
	return identity != "" && slices.Contains(loadSuperseded(), identity)
}

func (t *Transaction) supersededError(facts Facts, remote string) (Facts, error) {
	result, err := t.conflictError(facts, remote)
	if errors.Is(err, ErrConflict) {
		return result, errRemoteSuperseded
	}
	return result, err
}

func clearSuperseded() {
	if err := os.Remove(supersededPath()); err != nil && !os.IsNotExist(err) {
		config.Debug("sync: superseded ledger reset failed")
	}
}
