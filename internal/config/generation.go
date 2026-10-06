package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"ssm/internal/vault"
)

const generationLedgerName = "sync-generation.json"
const generationLockName = "sync-generation.lock"

type generationLedger struct {
	MaxSeen uint64 `json:"max_seen_generation"`
}

func GenerationPath() string { return filepath.Join(Dir(), generationLedgerName) }

func VaultGeneration(data []byte) (uint64, bool) { return vault.Generation(data) }

// MaxSeenGeneration is fail-open: a missing or corrupt ledger means zero.
func MaxSeenGeneration() uint64 {
	data, err := os.ReadFile(GenerationPath()) //nolint:gosec // fixed private metadata path
	if err != nil {
		return 0
	}
	var ledger generationLedger
	if json.Unmarshal(data, &ledger) != nil {
		return 0
	}
	return ledger.MaxSeen
}

// RecordMaxSeenGeneration advances the durable high-water mark best-effort.
func RecordMaxSeenGeneration(generation uint64) {
	if generation <= MaxSeenGeneration() {
		return
	}
	lock, err := AcquireFileLock(generationLockName, time.Second)
	if err != nil {
		Debug("sync: generation ledger lock failed")
		return
	}
	defer func() { _ = lock.Close() }()
	var ledger generationLedger
	if data, readErr := os.ReadFile(GenerationPath()); readErr == nil {
		_ = json.Unmarshal(data, &ledger)
	}
	if generation <= ledger.MaxSeen {
		return
	}
	data, err := json.MarshalIndent(generationLedger{MaxSeen: generation}, "", "  ")
	if err != nil {
		return
	}
	if err := WritePrivateFile(GenerationPath(), append(data, '\n')); err != nil {
		Debug("sync: generation ledger update failed")
	}
}

func ResetMaxSeenGeneration() {
	lock, err := AcquireFileLock(generationLockName, time.Second)
	if err != nil {
		Debug("sync: generation ledger lock failed")
		return
	}
	defer func() { _ = lock.Close() }()
	if err := os.Remove(GenerationPath()); err != nil && !os.IsNotExist(err) {
		Debug("sync: generation ledger reset failed")
	}
}

func SetMaxSeenGeneration(generation uint64) {
	lock, err := AcquireFileLock(generationLockName, time.Second)
	if err != nil {
		Debug("sync: generation ledger lock failed")
		return
	}
	defer func() { _ = lock.Close() }()
	data, err := json.MarshalIndent(generationLedger{MaxSeen: generation}, "", "  ")
	if err != nil {
		return
	}
	if err := WritePrivateFile(GenerationPath(), append(data, '\n')); err != nil {
		Debug("sync: generation ledger update failed")
	}
}

// NextVaultGeneration derives the next local generation from the current
// encrypted blob and the durable high-water mark.
func NextVaultGeneration() uint64 {
	var current uint64
	if data, err := os.ReadFile(Path()); err == nil {
		current, _ = vault.Generation(data)
	}
	seen := MaxSeenGeneration()
	if seen > current {
		current = seen
	}
	if current == ^uint64(0) {
		return current
	}
	return current + 1
}
