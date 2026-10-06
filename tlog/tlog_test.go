package tlog

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func entry(i int) Entry {
	return Entry{ArtifactDigest: fmt.Sprintf("sha256:%064x", i+1), Component: fmt.Sprintf("c%d@1.0.0", i)}
}

func TestInclusionProof(t *testing.T) {
	l, _ := Open("")
	for i := 0; i < 17; i++ {
		if _, err := l.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 17; i++ {
		p, err := l.ProveInclusion(i)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(entry(i), p); err != nil {
			t.Fatalf("inclusion %d: %v", i, err)
		}
		// 篡改记录必须失败。
		bad := entry(i)
		bad.Component = "evil@9.9.9"
		if err := VerifyInclusion(bad, p); !errors.Is(err, ErrInclusion) {
			t.Fatalf("tampered entry %d should fail: %v", i, err)
		}
	}
}

func TestConsistencyProof(t *testing.T) {
	l, _ := Open("")
	var roots []string
	for i := 0; i < 20; i++ {
		l.Append(entry(i))
		r, _ := l.RootHash()
		roots = append(roots, r)
	}
	newRoot, _ := l.RootHash()
	for old := 0; old < 20; old++ {
		p, err := l.ProveConsistency(old)
		if err != nil {
			t.Fatal(err)
		}
		oldRoot := ""
		if old > 0 {
			oldRoot = roots[old-1]
		} else {
			r0, _ := l.RootHashAt(0)
			oldRoot = r0
		}
		if err := VerifyConsistency(oldRoot, p, newRoot); err != nil {
			t.Fatalf("consistency %d->20: %v", old, err)
		}
		// 错误的旧根必须失败（模拟分叉）。
		if old > 0 {
			if err := VerifyConsistency(roots[0], p, newRoot); old > 1 && !errors.Is(err, ErrConsistency) {
				t.Fatalf("wrong old root at %d should fail", old)
			}
		}
	}
}

func TestIncrementalVerifierRestart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.json")
	cpPath := filepath.Join(dir, "checkpoint.json")

	l, _ := Open(logPath)
	for i := 0; i < 5; i++ {
		l.Append(entry(i))
	}
	v, err := NewIncrementalVerifier(l, cpPath)
	if err != nil {
		t.Fatal(err)
	}
	n, err := v.VerifyNew()
	if err != nil || n != 5 {
		t.Fatalf("first verify n=%d err=%v", n, err)
	}

	// 模拟重启：重新打开日志与检查点。
	l2, _ := Open(logPath)
	v2, err := NewIncrementalVerifier(l2, cpPath)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Checkpoint().Size != 5 {
		t.Fatalf("checkpoint lost after restart: %+v", v2.Checkpoint())
	}
	// 无新增：不得重复计算。
	n, err = v2.VerifyNew()
	if err != nil || n != 0 {
		t.Fatalf("no-op verify n=%d err=%v", n, err)
	}
	// 追加后只校验增量。
	for i := 5; i < 8; i++ {
		l2.Append(entry(i))
	}
	n, err = v2.VerifyNew()
	if err != nil || n != 3 {
		t.Fatalf("incremental verify n=%d err=%v, want 3", n, err)
	}
}

func TestRollbackDetected(t *testing.T) {
	dir := t.TempDir()
	cpPath := filepath.Join(dir, "checkpoint.json")
	l, _ := Open("")
	for i := 0; i < 6; i++ {
		l.Append(entry(i))
	}
	v, _ := NewIncrementalVerifier(l, cpPath)
	if _, err := v.VerifyNew(); err != nil {
		t.Fatal(err)
	}
	// 构造回滚：更短的日志。
	l2, _ := Open("")
	for i := 0; i < 3; i++ {
		l2.Append(entry(i))
	}
	v2, _ := NewIncrementalVerifier(l2, cpPath)
	if _, err := v2.VerifyNew(); !errors.Is(err, ErrConsistency) {
		t.Fatalf("rollback should fail with ErrConsistency, got %v", err)
	}
	// 构造分叉：同长度但内容不同。
	l3, _ := Open("")
	for i := 0; i < 6; i++ {
		e := entry(i)
		if i == 4 {
			e.Component = "forked@1.0.0"
		}
		l3.Append(e)
	}
	v3, _ := NewIncrementalVerifier(l3, cpPath)
	if _, err := v3.VerifyNew(); !errors.Is(err, ErrConsistency) {
		t.Fatalf("fork should fail with ErrConsistency, got %v", err)
	}
}
