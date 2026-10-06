package tlog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var (
	// ErrInclusion 表示包含证明校验失败。
	ErrInclusion = errors.New("tlog: inclusion proof invalid")
	// ErrConsistency 表示一致性证明校验失败（回滚或分叉）。
	ErrConsistency = errors.New("tlog: consistency proof invalid (rollback or fork)")
)

// VerifyInclusion 校验包含证明：由叶哈希与审计路径重算根并与证明根比对。
func VerifyInclusion(e Entry, p *InclusionProof) error {
	if p == nil {
		return fmt.Errorf("%w: nil proof", ErrInclusion)
	}
	if p.LeafIndex < 0 || p.LeafIndex >= p.TreeSize {
		return fmt.Errorf("%w: bad index %d size %d", ErrInclusion, p.LeafIndex, p.TreeSize)
	}
	proof, err := decodeAll(p.Hashes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInclusion, err)
	}
	root, err := hex.DecodeString(p.RootHash)
	if err != nil {
		return fmt.Errorf("%w: bad root encoding", ErrInclusion)
	}
	got := recomputeInclusionRoot(leafHash(e), p.LeafIndex, p.TreeSize, proof)
	if !bytes.Equal(got, root) {
		return fmt.Errorf("%w: recomputed root mismatch", ErrInclusion)
	}
	return nil
}

// recomputeInclusionRoot 沿审计路径（叶->根）重算树根。
// 先自顶向下记录分裂方向，再自底向上折叠，保证左右顺序正确。
func recomputeInclusionRoot(leaf []byte, index, size int, proof [][]byte) []byte {
	var wentLeft []bool
	s, i := size, index
	for s > 1 {
		k := largestSplit(s)
		if i < k {
			wentLeft = append(wentLeft, true)
			s = k
		} else {
			wentLeft = append(wentLeft, false)
			i -= k
			s -= k
		}
	}
	if len(proof) != len(wentLeft) {
		return nil
	}
	cur := leaf
	for j := len(wentLeft) - 1; j >= 0; j-- {
		sib := proof[len(wentLeft)-1-j]
		if wentLeft[j] {
			cur = nodeHash(cur, sib)
		} else {
			cur = nodeHash(sib, cur)
		}
	}
	return cur
}

// VerifyConsistency 校验一致性证明：确认 oldRoot 代表的旧树是
// newRoot 代表的新树的前缀，用于识别回滚与分叉。
func VerifyConsistency(oldRoot string, p *ConsistencyProof, newRoot string) error {
	if p == nil {
		return fmt.Errorf("%w: nil proof", ErrConsistency)
	}
	if p.OldSize < 0 || p.NewSize < p.OldSize {
		return fmt.Errorf("%w: bad sizes %d->%d", ErrConsistency, p.OldSize, p.NewSize)
	}
	if p.OldSize == p.NewSize {
		if oldRoot != newRoot {
			return fmt.Errorf("%w: same size %d but different roots", ErrConsistency, p.OldSize)
		}
		return nil
	}
	if p.OldSize == 0 {
		return nil // 空旧树是任何树的前缀
	}
	proof, err := decodeAll(p.Hashes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConsistency, err)
	}
	oldRootB, err := hex.DecodeString(oldRoot)
	if err != nil {
		return fmt.Errorf("%w: bad old root", ErrConsistency)
	}
	newRootB, err := hex.DecodeString(newRoot)
	if err != nil {
		return fmt.Errorf("%w: bad new root", ErrConsistency)
	}
	gotOld, gotNew, ok := foldConsistency(proof, p.OldSize, p.NewSize)
	if !ok || !bytes.Equal(gotOld, oldRootB) || !bytes.Equal(gotNew, newRootB) {
		return fmt.Errorf("%w: proof does not link %d->%d", ErrConsistency, p.OldSize, p.NewSize)
	}
	return nil
}

// foldConsistency 由证明哈希重放生成端的分裂结构，折叠出 (旧根, 新根)。
// 与 log.go 中 subproof 的生成过程严格对偶。
func foldConsistency(proof [][]byte, m, n int) (oldRoot, newRoot []byte, ok bool) {
	pos := 0
	oldH, newH, ok := foldRec(proof, &pos, m, n)
	if !ok || pos != len(proof) {
		return nil, nil, false
	}
	return oldH, newH, true
}

// foldRec 递归消费证明元素：
// 生成端 subproof(leaves[:n], m, false) 在 m==n 时产生 [subtreeHash]，
// 否则先递归子证明再追加兄弟子树哈希；此处按同序消费并重算。
func foldRec(proof [][]byte, pos *int, m, n int) (oldH, newH []byte, ok bool) {
	if m == n {
		if *pos >= len(proof) {
			return nil, nil, false
		}
		h := proof[*pos]
		*pos++
		return h, h, true
	}
	k := largestSplit(n)
	if m <= k {
		oL, nL, ok := foldRec(proof, pos, m, k)
		if !ok || *pos >= len(proof) {
			return nil, nil, false
		}
		sib := proof[*pos]
		*pos++
		return oL, nodeHash(nL, sib), true
	}
	oR, nR, ok := foldRec(proof, pos, m-k, n-k)
	if !ok || *pos >= len(proof) {
		return nil, nil, false
	}
	sib := proof[*pos]
	*pos++
	// m > k 时左子树整体属于旧树，旧根与新根都要带上左侧兄弟。
	return nodeHash(sib, oR), nodeHash(sib, nR), true
}

func decodeAll(ss []string) ([][]byte, error) {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

// Checkpoint 记录已校验到的日志位置，持久化后重启不丢失。
type Checkpoint struct {
	Size     int    `json:"size"`
	RootHash string `json:"rootHash"`
}

// IncrementalVerifier 增量校验器：只校验上次检查点之后的新条目，
// 并通过一致性证明确认日志未回滚、未分叉。
type IncrementalVerifier struct {
	log    *Log
	cp     Checkpoint
	cpPath string
}

// NewIncrementalVerifier 从检查点文件恢复；文件不存在时从零开始。
func NewIncrementalVerifier(log *Log, checkpointPath string) (*IncrementalVerifier, error) {
	v := &IncrementalVerifier{log: log, cpPath: checkpointPath}
	data, err := os.ReadFile(checkpointPath)
	if err != nil {
		if os.IsNotExist(err) {
			return v, nil
		}
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &v.cp); err != nil {
			return nil, fmt.Errorf("tlog: corrupt checkpoint: %w", err)
		}
	}
	return v, nil
}

// Checkpoint 返回当前已校验位置。
func (v *IncrementalVerifier) Checkpoint() Checkpoint { return v.cp }

// VerifyNew 校验自上次检查点以来的新增条目并推进检查点。
// 返回本次新校验的条目数（不重复计算已校验部分）。
// 日志回滚（变小）或分叉（旧位置根哈希变化）时返回 ErrConsistency。
func (v *IncrementalVerifier) VerifyNew() (int, error) {
	newSize := v.log.Size()
	if newSize < v.cp.Size {
		return 0, fmt.Errorf("%w: log shrank %d -> %d (rollback)", ErrConsistency, v.cp.Size, newSize)
	}
	// 校验已验证位置未变（识别分叉/回滚后重放）。
	if v.cp.Size > 0 {
		rootAtCp, err := v.log.RootHashAt(v.cp.Size)
		if err != nil {
			return 0, err
		}
		if rootAtCp != v.cp.RootHash {
			return 0, fmt.Errorf("%w: root at checkpoint %d changed (fork)", ErrConsistency, v.cp.Size)
		}
	}
	if newSize == v.cp.Size {
		return 0, nil
	}
	proof, err := v.log.ProveConsistency(v.cp.Size)
	if err != nil {
		return 0, err
	}
	newRoot, err := v.log.RootHash()
	if err != nil {
		return 0, err
	}
	if err := VerifyConsistency(v.cp.RootHash, proof, newRoot); err != nil {
		return 0, err
	}
	// 逐条校验新增记录可被包含证明覆盖（抽样重算根已含于一致性证明，
	// 这里对每条新记录生成并校验包含证明，确保条目级有效）。
	for i := v.cp.Size; i < newSize; i++ {
		e, err := v.log.EntryAt(i)
		if err != nil {
			return 0, err
		}
		ip, err := v.log.ProveInclusion(i)
		if err != nil {
			return 0, err
		}
		if err := VerifyInclusion(e, ip); err != nil {
			return 0, err
		}
	}
	verified := newSize - v.cp.Size
	v.cp = Checkpoint{Size: newSize, RootHash: newRoot}
	if v.cpPath != "" {
		data, err := json.Marshal(v.cp)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(v.cpPath, data, 0o644); err != nil {
			return 0, err
		}
	}
	return verified, nil
}
