// Package lockfile 实现依赖固定与漂移检测。
package lockfile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

// Entry 是锁定记录中的一条。
type Entry struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`     // 制品内容 sha256:...
	SourcePath string `json:"sourcePath"` // 制品来源路径（本地）
}

// Lock 是一份锁定记录。
type Lock struct {
	Entries []Entry `json:"entries"`
}

// Drift 描述一处漂移。
type Drift struct {
	Component  string // name@version 或 name
	SourcePath string
	Reason     string
}

func (d *Drift) Error() string {
	return "drift: " + d.Component + " at " + d.SourcePath + ": " + d.Reason
}

// FromGraph 由解析图与摘要函数生成锁定记录（依赖固定）。输出排序确定。
func FromGraph(g *depgraph.Graph, digestOf func(name, version string) (string, error), sourceOf func(name, version string) string) (*Lock, error) {
	l := &Lock{}
	for _, n := range g.Nodes { // 已排序
		v := n.Version.String()
		d, err := digestOf(n.Name, v)
		if err != nil {
			return nil, fmt.Errorf("lockfile: digest for %s@%s: %w", n.Name, v, err)
		}
		l.Entries = append(l.Entries, Entry{
			Name:       n.Name,
			Version:    v,
			Digest:     d,
			SourcePath: sourceOf(n.Name, v),
		})
	}
	return l, nil
}

// Check 对比解析图与锁定记录，返回全部漂移；无漂移返回 nil。
// 结果按组件排序，输出确定。
func Check(g *depgraph.Graph, lock *Lock) []Drift {
	locked := map[string]Entry{}
	for _, e := range lock.Entries {
		locked[e.Name+"@"+e.Version] = e
	}
	inGraph := map[string]bool{}
	var drifts []Drift
	for _, n := range g.Nodes {
		id := n.Name + "@" + n.Version.String()
		inGraph[id] = true
		e, ok := locked[id]
		if !ok {
			// 清单解析出了锁定记录中不存在的组件版本。
			drifts = append(drifts, Drift{
				Component: id,
				Reason:    "component resolved but not present in lock",
			})
			continue
		}
		_ = e
	}
	for _, e := range lock.Entries {
		id := e.Name + "@" + e.Version
		if !inGraph[id] {
			drifts = append(drifts, Drift{
				Component:  id,
				SourcePath: e.SourcePath,
				Reason:     "locked component no longer resolved from manifest",
			})
		}
	}
	sort.Slice(drifts, func(i, j int) bool { return drifts[i].Component < drifts[j].Component })
	return drifts
}

// VerifyArtifact 校验制品内容哈希与锁定记录一致。
// 不一致或记录缺失时返回 *Drift（调用方必须阻断）。
func VerifyArtifact(lock *Lock, name, version string, content []byte) *Drift {
	id := name + "@" + version
	for _, e := range lock.Entries {
		if e.Name+"@"+e.Version == id {
			h := sha256.Sum256(content)
			actual := "sha256:" + hex.EncodeToString(h[:])
			if actual != e.Digest {
				return &Drift{
					Component:  id,
					SourcePath: e.SourcePath,
					Reason:     fmt.Sprintf("artifact digest %s != locked %s", actual, e.Digest),
				}
			}
			return nil
		}
	}
	return &Drift{Component: id, Reason: "no lock entry for artifact"}
}
