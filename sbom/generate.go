package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

// ArtifactDigest 提供组件内容摘要的查询。
type ArtifactDigest func(name, version string) (string, error)

// Generate 从解析图生成 SBOM。
//
// 可复现保证：组件与依赖列表全部排序；序列号由内容哈希派生；
// 不含时间戳、随机数、map 迭代等任何运行时不确定因素。
func Generate(g *depgraph.Graph, digestOf ArtifactDigest, spec SpecVersion) (*Document, error) {
	if spec != Spec10 && spec != Spec11 {
		return nil, fmt.Errorf("sbom: unsupported spec %q", spec)
	}
	doc := &Document{Spec: spec, Tool: "sbomprov"}
	for _, n := range g.Nodes { // g.Nodes 已按 (name,version) 排序
		d, err := digestOf(n.Name, n.Version.String())
		if err != nil {
			return nil, fmt.Errorf("sbom: digest for %s@%s: %w", n.Name, n.Version, err)
		}
		c := Component{
			Name:    n.Name,
			Version: n.Version.String(),
			Digest:  d,
		}
		if spec == Spec11 {
			for _, e := range n.Deps { // 边已排序
				c.DependsOn = append(c.DependsOn, e.To.Name+"@"+e.To.Version.String())
			}
			c.SourcePath = "local://" + n.Name + "/" + n.Version.String()
		}
		doc.Components = append(doc.Components, c)
	}
	doc.Serial = serialOf(doc)
	return doc, nil
}

// serialOf 由内容派生确定性序列号（URN 形式）。
func serialOf(d *Document) string {
	h := sha256.New()
	h.Write([]byte(d.Spec))
	for _, c := range d.Components {
		h.Write([]byte(c.Name))
		h.Write([]byte{0})
		h.Write([]byte(c.Version))
		h.Write([]byte{0})
		h.Write([]byte(c.Digest))
		h.Write([]byte{0})
	}
	return "urn:sbomprov:" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Marshal 输出规范化 JSON：键序固定（结构体声明序）、缩进固定、
// 无随机字段，保证字节级可复现。
func Marshal(d *Document) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sortedComponents 返回按 (name,version) 排序的组件副本（供转换使用）。
func sortedComponents(cs []Component) []Component {
	out := append([]Component(nil), cs...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
