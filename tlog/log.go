// Package tlog implements a locally simulated append-only transparency log
// (RFC 6962-style Merkle tree) with persistence, restart-safe verified
// positions and incremental consistency verification.
package tlog

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"sync"
)

// HashLeaf hashes a leaf per RFC 6962: SHA-256(0x00 || data).
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// HashChildren hashes an interior node: SHA-256(0x01 || left || right).
func HashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Log is an append-only Merkle transparency log backed by a local file.
// State is written through on every Append, so a restart restores the exact
// pre-shutdown tree.
type Log struct {
	mu     sync.Mutex
	path   string
	leaves [][]byte // raw leaf payloads
}

type diskState struct {
	Leaves [][]byte `json:"leaves"`
}

// Open opens or creates the log at path, restoring persisted state.
func Open(path string) (*Log, error) {
	l := &Log{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, fmt.Errorf("read log %s: %w", path, err)
	}
	if len(data) == 0 {
		return l, nil
	}
	var st diskState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("decode log %s: %w", path, err)
	}
	l.leaves = st.Leaves
	return l, nil
}

func (l *Log) persistLocked() error {
	st := diskState{Leaves: l.leaves}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// Append adds a leaf and returns its index.
func (l *Log) Append(leaf []byte) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := append([]byte(nil), leaf...)
	l.leaves = append(l.leaves, cp)
	if err := l.persistLocked(); err != nil {
		l.leaves = l.leaves[:len(l.leaves)-1]
		return 0, fmt.Errorf("persist append: %w", err)
	}
	return uint64(len(l.leaves)) - 1, nil
}

// Size returns the current tree size.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves))
}

// Leaf returns the raw payload at index.
func (l *Log) Leaf(index uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of range (size %d)", index, len(l.leaves))
	}
	return append([]byte(nil), l.leaves[index]...), nil
}

// Root returns the current tree head hash. Empty tree hashes as SHA-256("").
func (l *Log) Root() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return rootOf(l.leaves)
}

// rootOf computes the Merkle Tree Hash of the given leaves.
func rootOf(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		empty := sha256.Sum256(nil)
		return empty[:]
	}
	return mth(leaves, 0, n)
}

// mth computes MTH over leaves[start:end].
func mth(leaves [][]byte, start, end int) []byte {
	n := end - start
	if n == 1 {
		return HashLeaf(leaves[start])
	}
	k := splitPoint(n)
	return HashChildren(mth(leaves, start, start+k), mth(leaves, start+k, end))
}

// splitPoint returns the largest power of two strictly less than n.
func splitPoint(n int) int {
	if n <= 1 {
		return 0
	}
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// InclusionProof returns the audit path proving the leaf at index is in
// the tree of the current size.
func (l *Log) InclusionProof(index uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.leaves)
	if index >= uint64(n) {
		return nil, fmt.Errorf("leaf index %d out of range (size %d)", index, n)
	}
	return auditPath(int(index), l.leaves, 0, n), nil
}

// auditPath builds the RFC 6962 audit path for leaf m in leaves[start:end].
func auditPath(m int, leaves [][]byte, start, end int) [][]byte {
	n := end - start
	if n == 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(auditPath(m, leaves, start, start+k), mth(leaves, start+k, end))
	}
	return append(auditPath(m-k, leaves, start+k, end), mth(leaves, start, start+k))
}

// ConsistencyProof returns the proof that the tree at oldSize is a prefix
// of the current tree.
func (l *Log) ConsistencyProof(oldSize uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := uint64(len(l.leaves))
	if oldSize > n {
		return nil, fmt.Errorf("old size %d exceeds current size %d", oldSize, n)
	}
	if oldSize == 0 || oldSize == n {
		return nil, nil
	}
	return subproof(int(oldSize), l.leaves, 0, int(n), true), nil
}

// subproof implements SUBPROOF(m, D_n, b) from RFC 6962 §2.1.2.
func subproof(m int, leaves [][]byte, start, end int, b bool) [][]byte {
	n := end - start
	if m == n {
		if b {
			return nil
		}
		return [][]byte{mth(leaves, start, end)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subproof(m, leaves, start, start+k, b), mth(leaves, start+k, end))
	}
	return append(subproof(m-k, leaves, start+k, end, false), mth(leaves, start, start+k))
}

// Close flushes state to disk.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.persistLocked()
}

// VerifyInclusion recomputes the root from a raw leaf payload and audit
// path per RFC 6962 §2.1.1 and compares it with the expected root.
func VerifyInclusion(leaf []byte, index, size uint64, path [][]byte, root []byte) bool {
	if size == 0 || index >= size {
		return false
	}
	fn := index
	sn := size - 1
	r := HashLeaf(leaf)
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = HashChildren(p, r)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = HashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytesEqual(r, root)
}

// VerifyConsistency checks that oldRoot (tree of oldSize) is a prefix of
// newRoot (tree of newSize) given the consistency proof, per RFC 6962
// §2.1.3. A false result indicates rollback or fork evidence.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot []byte, proof [][]byte) bool {
	if oldSize > newSize {
		return false
	}
	if oldSize == newSize {
		return len(proof) == 0 && bytesEqual(oldRoot, newRoot)
	}
	if oldSize == 0 {
		return len(proof) == 0
	}
	if len(proof) == 0 {
		return false
	}
	fn := oldSize - 1
	sn := newSize - 1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr := append([]byte(nil), proof[0]...)
	sr := append([]byte(nil), proof[0]...)
	for _, c := range proof[1:] {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			fr = HashChildren(c, fr)
			sr = HashChildren(c, sr)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = HashChildren(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytesEqual(fr, oldRoot) && bytesEqual(sr, newRoot)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
