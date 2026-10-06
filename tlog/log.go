// Package tlog 实现本地模拟的只追加透明日志（Merkle 树），
// 支持包含证明、一致性证明与可重启的增量校验。
package tlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Entry 是日志中的一条记录（制品摘要承诺）。
type Entry struct {
	ArtifactDigest string `json:"artifactDigest"` // sha256:...
	Component      string `json:"component"`      // name@version
}

// InclusionProof 是 Merkle 包含证明。
type InclusionProof struct {
	LeafIndex int      `json:"leafIndex"`
	TreeSize  int      `json:"treeSize"`
	Hashes    []string `json:"hashes"` // 十六进制审计路径
	RootHash  string   `json:"rootHash"`
}

// ConsistencyProof 证明旧树是新树的前缀。
type ConsistencyProof struct {
	OldSize int      `json:"oldSize"`
	NewSize int      `json:"newSize"`
	Hashes  []string `json:"hashes"`
}

// Log 是可持久化的本地只追加日志。
type Log struct {
	mu      sync.Mutex
	path    string // 磁盘文件；空表示纯内存
	entries []Entry
	leaves  [][]byte // 叶哈希缓存
}

// Open 打开（或创建）位于 path 的日志；path 为空时仅内存。
func Open(path string) (*Log, error) {
	l := &Log{path: path}
	if path == "" {
		return l, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return l, nil
	}
	if err := json.Unmarshal(data, &l.entries); err != nil {
		return nil, fmt.Errorf("tlog: corrupt log file: %w", err)
	}
	for _, e := range l.entries {
		l.leaves = append(l.leaves, leafHash(e))
	}
	return l, nil
}

// Append 追加一条记录并返回其叶索引。
func (l *Log) Append(e Entry) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	l.leaves = append(l.leaves, leafHash(e))
	if l.path != "" {
		data, err := json.Marshal(l.entries)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(l.path, data, 0o644); err != nil {
			return 0, err
		}
	}
	return len(l.entries) - 1, nil
}

// Size 返回当前树大小。
func (l *Log) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// EntryAt 返回指定索引的记录。
func (l *Log) EntryAt(i int) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i < 0 || i >= len(l.entries) {
		return Entry{}, fmt.Errorf("tlog: index %d out of range", i)
	}
	return l.entries[i], nil
}

// RootHash 返回当前树根哈希。
func (l *Log) RootHash() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return hex.EncodeToString(rootHash(l.leaves)), nil
}

// RootHashAt 返回前 n 条记录构成的子树根哈希。
func (l *Log) RootHashAt(n int) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n < 0 || n > len(l.leaves) {
		return "", fmt.Errorf("tlog: size %d out of range", n)
	}
	return hex.EncodeToString(rootHash(l.leaves[:n])), nil
}

// ProveInclusion 为叶索引生成包含证明。
func (l *Log) ProveInclusion(leafIndex int) (*InclusionProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if leafIndex < 0 || leafIndex >= len(l.entries) {
		return nil, fmt.Errorf("tlog: index %d out of range", leafIndex)
	}
	path := inclusionPath(l.leaves, leafIndex)
	hashes := make([]string, len(path))
	for i, h := range path {
		hashes[i] = hex.EncodeToString(h)
	}
	return &InclusionProof{
		LeafIndex: leafIndex,
		TreeSize:  len(l.entries),
		Hashes:    hashes,
		RootHash:  hex.EncodeToString(rootHash(l.leaves)),
	}, nil
}

// ProveConsistency 生成 oldSize -> 当前大小的一致性证明。
func (l *Log) ProveConsistency(oldSize int) (*ConsistencyProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if oldSize < 0 || oldSize > len(l.entries) {
		return nil, fmt.Errorf("tlog: old size %d out of range", oldSize)
	}
	proof := consistencyProof(l.leaves, oldSize)
	hashes := make([]string, len(proof))
	for i, h := range proof {
		hashes[i] = hex.EncodeToString(h)
	}
	return &ConsistencyProof{OldSize: oldSize, NewSize: len(l.entries), Hashes: hashes}, nil
}

// Find 按组件与制品摘要查找叶索引，未找到返回 -1。
func (l *Log) Find(component, artifactDigest string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, e := range l.entries {
		if e.Component == component && e.ArtifactDigest == artifactDigest {
			return i
		}
	}
	return -1
}

// ---- Merkle 树原语（RFC 6962 风格） ----

func leafHash(e Entry) []byte {
	data, _ := json.Marshal(e)
	h := sha256.Sum256(append([]byte{0x00}, data...))
	return h[:]
}

func nodeHash(l, r []byte) []byte {
	h := sha256.Sum256(append(append([]byte{0x01}, l...), r...))
	return h[:]
}

// rootHash 计算 Merkle 树根；空树返回空串哈希。
func rootHash(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		h := sha256.Sum256(nil)
		return h[:]
	}
	return subtreeHash(leaves)
}

// largestSplit 返回小于 n 的最大 2 的幂。
func largestSplit(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func subtreeHash(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := largestSplit(len(leaves))
	return nodeHash(subtreeHash(leaves[:k]), subtreeHash(leaves[k:]))
}

// inclusionPath 生成叶 index 的审计路径。
func inclusionPath(leaves [][]byte, index int) [][]byte {
	var path [][]byte
	var walk func(lo, hi int)
	walk = func(lo, hi int) {
		if hi-lo == 1 {
			return
		}
		k := largestSplit(hi - lo)
		if index-lo < k {
			path = append(path, subtreeHash(leaves[lo+k:hi]))
			walk(lo, lo+k)
		} else {
			path = append(path, subtreeHash(leaves[lo:lo+k]))
			walk(lo+k, hi)
		}
	}
	walk(0, len(leaves))
	// 反转：从叶到根。
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

// consistencyProof 生成 oldSize -> len(leaves) 的一致性证明（RFC 6962 §2.1.2）。
func consistencyProof(leaves [][]byte, oldSize int) [][]byte {
	if oldSize == 0 || oldSize == len(leaves) {
		return nil
	}
	return subproof(leaves, oldSize, true)
}

// subproof 返回证明前 m 片叶是全部 n 片叶前缀的节点哈希集合。
func subproof(leaves [][]byte, m int, startFromRoot bool) [][]byte {
	n := len(leaves)
	if m == n {
		if startFromRoot {
			return nil
		}
		return [][]byte{subtreeHash(leaves)}
	}
	k := largestSplit(n)
	if m <= k {
		right := subtreeHash(leaves[k:])
		return append(subproof(leaves[:k], m, false), right)
	}
	left := subtreeHash(leaves[:k])
	return append(subproof(leaves[k:], m-k, false), left)
}
