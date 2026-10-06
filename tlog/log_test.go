package tlog

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestInclusionProofRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(filepath.Join(dir, "log.json"))
	if err != nil {
		t.Fatal(err)
	}
	var leaves [][]byte
	for i := 0; i < 17; i++ {
		payload := []byte(fmt.Sprintf("artifact-%d", i))
		leaves = append(leaves, payload)
		if _, err := l.Append(payload); err != nil {
			t.Fatal(err)
		}
	}
	root := l.Root()
	for i, payload := range leaves {
		proof, err := l.InclusionProof(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyInclusion(payload, uint64(i), l.Size(), proof, root) {
			t.Fatalf("inclusion proof for leaf %d does not verify", i)
		}
		// Tampered leaf must fail.
		if VerifyInclusion([]byte("tampered"), uint64(i), l.Size(), proof, root) {
			t.Fatalf("tampered leaf %d verified", i)
		}
	}
}

func TestConsistencyAndRollback(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.json")
	statePath := filepath.Join(dir, "state.json")

	l, _ := Open(logPath)
	for i := 0; i < 5; i++ {
		l.Append([]byte(fmt.Sprintf("a-%d", i)))
	}
	v, _ := NewVerifier(statePath)
	if err := v.Update(l); err != nil {
		t.Fatal(err)
	}
	if v.VerifiedSize() != 5 {
		t.Fatalf("verified size = %d, want 5", v.VerifiedSize())
	}
	for i := 5; i < 9; i++ {
		l.Append([]byte(fmt.Sprintf("a-%d", i)))
	}
	if err := v.Update(l); err != nil {
		t.Fatalf("incremental update: %v", err)
	}
	if v.VerifiedSize() != 9 {
		t.Fatalf("verified size = %d, want 9", v.VerifiedSize())
	}

	// Restart: verified position must survive and not recompute.
	v2, _ := NewVerifier(statePath)
	if v2.VerifiedSize() != 9 {
		t.Fatalf("after restart verified size = %d, want 9", v2.VerifiedSize())
	}
	l2, _ := Open(logPath)
	if err := v2.Update(l2); err != nil {
		t.Fatalf("no-op update after restart: %v", err)
	}

	// Rollback: truncate the log file to 3 entries.
	var st diskState
	st.Leaves = l2.leaves[:3]
	writeState(t, logPath, &st)
	l3, _ := Open(logPath)
	if err := v2.Update(l3); !errors.Is(err, ErrRollback) {
		t.Fatalf("expected rollback error, got %v", err)
	}

	// Fork: same size, different content.
	st.Leaves = l2.leaves[:9]
	st.Leaves[8] = []byte("forged")
	writeState(t, logPath, &st)
	l4, _ := Open(logPath)
	if err := v2.Update(l4); !errors.Is(err, ErrFork) {
		t.Fatalf("expected fork error, got %v", err)
	}
}

func TestForkAtLargerSize(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.json")
	statePath := filepath.Join(dir, "state.json")
	l, _ := Open(logPath)
	for i := 0; i < 4; i++ {
		l.Append([]byte(fmt.Sprintf("x-%d", i)))
	}
	v, _ := NewVerifier(statePath)
	if err := v.Update(l); err != nil {
		t.Fatal(err)
	}
	// Fork: replace an old leaf and extend.
	var st diskState
	st.Leaves = append([][]byte(nil), l.leaves...)
	st.Leaves[1] = []byte("forged")
	st.Leaves = append(st.Leaves, []byte("x-4"))
	writeState(t, logPath, &st)
	l2, _ := Open(logPath)
	if err := v.Update(l2); !errors.Is(err, ErrFork) {
		t.Fatalf("expected fork error, got %v", err)
	}
	// Failed update must not advance the verified position.
	if v.VerifiedSize() != 4 {
		t.Fatalf("verified size moved to %d after fork", v.VerifiedSize())
	}
}

func writeState(t *testing.T, path string, st *diskState) {
	t.Helper()
	data, err := jsonMarshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := osWriteFile(path, data); err != nil {
		t.Fatal(err)
	}
}

// Sanity: root changes when any leaf changes.
func TestRootSensitivity(t *testing.T) {
	dir := t.TempDir()
	l1, _ := Open(filepath.Join(dir, "a.json"))
	l2, _ := Open(filepath.Join(dir, "b.json"))
	l1.Append([]byte("same"))
	l2.Append([]byte("same"))
	l1.Append([]byte("x"))
	l2.Append([]byte("y"))
	if bytes.Equal(l1.Root(), l2.Root()) {
		t.Fatal("different leaves produced identical roots")
	}
}
