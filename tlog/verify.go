package tlog

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// ErrRollback is returned when the log shrinks below the verified position.
var ErrRollback = fmt.Errorf("transparency log rollback detected")

// ErrFork is returned when the log cannot be proven consistent with the
// verified position (fork evidence).
var ErrFork = fmt.Errorf("transparency log fork detected")

// Verifier tracks a verified log position and checks incremental
// consistency proofs to detect rollback and fork. State persists across
// restarts; already-verified positions are never recomputed.
type Verifier struct {
	mu        sync.Mutex
	statePath string
	size      uint64
	root      []byte
}

type verifierState struct {
	Size uint64 `json:"size"`
	Root []byte `json:"root"`
}

// NewVerifier opens the verifier state at statePath, restoring the last
// verified position if present.
func NewVerifier(statePath string) (*Verifier, error) {
	v := &Verifier{statePath: statePath}
	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return v, nil
		}
		return nil, fmt.Errorf("read verifier state %s: %w", statePath, err)
	}
	if len(data) == 0 {
		return v, nil
	}
	var st verifierState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("decode verifier state %s: %w", statePath, err)
	}
	v.size = st.Size
	v.root = st.Root
	return v, nil
}

// VerifiedSize returns the last verified tree size (0 if none).
func (v *Verifier) VerifiedSize() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.size
}

// Update checks the consistency proof from the verified position to the
// log's current size, then advances and persists the verified position.
// It fails with ErrRollback if the log shrank, and with ErrFork if the
// consistency proof does not connect the verified root to the current
// root. When the log has not grown, Update is a no-op and performs no
// recomputation.
func (v *Verifier) Update(l *Log) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	newSize := l.Size()
	newRoot := l.Root()
	switch {
	case newSize < v.size:
		return fmt.Errorf("%w: verified size %d, log size %d", ErrRollback, v.size, newSize)
	case newSize == v.size:
		if v.size > 0 && !bytesEqual(v.root, newRoot) {
			return fmt.Errorf("%w: same size %d but different root", ErrFork, v.size)
		}
		return nil // nothing new; no recomputation
	}
	proof, err := l.ConsistencyProof(v.size)
	if err != nil {
		return err
	}
	if !VerifyConsistency(v.size, newSize, v.root, newRoot, proof) {
		return fmt.Errorf("%w: consistency proof from %d to %d does not verify", ErrFork, v.size, newSize)
	}
	v.size = newSize
	v.root = newRoot
	return v.persistLocked()
}

func (v *Verifier) persistLocked() error {
	st := verifierState{Size: v.size, Root: v.root}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := v.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.statePath)
}

// Close persists the verified position.
func (v *Verifier) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.persistLocked()
}
