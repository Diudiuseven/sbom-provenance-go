package depgraph

import (
	"fmt"
	"sort"
)

// Options 控制解析行为。
type Options struct {
	Platform        string   // 目标平台，如 "linux/amd64"
	IncludeOptional []string // 显式启用的可选依赖名
}

// Resolve 解析清单为依赖图。
//
// 确定性保证：版本选择只依赖约束与可用版本集合（取满足约束的最高版本），
// 节点、边、根与循环报告全部按字典序排序，因此与清单中声明顺序、
// 遍历顺序无关，任意两次运行结果一致。
func Resolve(m *Manifest, opts Options) (*Graph, error) {
	// 1. 建立 name -> 已排序版本列表（升序）索引。
	avail := map[string][]Version{}
	compByID := map[NodeID]*Component{}
	for i := range m.Components {
		c := &m.Components[i]
		id := NodeID{Name: c.Name, Version: c.Version}
		if _, dup := compByID[id]; dup {
			return nil, fmt.Errorf("depgraph: duplicate component %s@%s", c.Name, c.Version)
		}
		compByID[id] = c
		avail[c.Name] = append(avail[c.Name], c.Version)
	}
	for name := range avail {
		vs := avail[name]
		sort.Slice(vs, func(i, j int) bool { return vs[i].Compare(vs[j]) < 0 })
		avail[name] = vs
	}

	optionalOn := map[string]bool{}
	for _, n := range opts.IncludeOptional {
		optionalOn[n] = true
	}
	keep := func(d Dependency) bool {
		if d.Optional && !optionalOn[d.Name] {
			return false
		}
		return platformMatch(d.Platforms, opts.Platform)
	}

	// select 选择满足约束的最高版本；结果与遍历顺序无关。
	selectVersion := func(d Dependency) (Version, error) {
		vs := avail[d.Name]
		for i := len(vs) - 1; i >= 0; i-- {
			if d.Constraint.SatisfiedBy(vs[i]) {
				return vs[i], nil
			}
		}
		return Version{}, fmt.Errorf("depgraph: no version of %q satisfies constraint %+v", d.Name, d.Constraint)
	}

	// 2. 记忆化展开：每个 name@version 节点只展开一次，多版本自然共存，
	//    循环引用因记忆化而终止。
	nodes := map[NodeID]*Node{}
	var expand func(id NodeID) error
	expand = func(id NodeID) error {
		if _, ok := nodes[id]; ok {
			return nil
		}
		c := compByID[id]
		n := &Node{Name: id.Name, Version: id.Version}
		nodes[id] = n // 先占位，切断递归
		for _, d := range c.Deps {
			if !keep(d) {
				continue
			}
			v, err := selectVersion(d)
			if err != nil {
				return err
			}
			to := NodeID{Name: d.Name, Version: v}
			n.Deps = append(n.Deps, Edge{To: to, Optional: d.Optional, Via: id})
			if err := expand(to); err != nil {
				return err
			}
		}
		sort.Slice(n.Deps, func(i, j int) bool { return lessID(n.Deps[i].To, n.Deps[j].To) })
		return nil
	}

	// 3. 解析根依赖。
	rootSet := map[NodeID]bool{}
	for _, d := range m.Roots {
		if !keep(d) {
			continue
		}
		v, err := selectVersion(d)
		if err != nil {
			return nil, err
		}
		rootSet[NodeID{Name: d.Name, Version: v}] = true
	}
	roots := sortedIDs(rootSet)
	for _, r := range roots {
		if err := expand(r); err != nil {
			return nil, err
		}
	}

	// 4. 输出：节点排序、循环检测（确定性 DFS）。
	g := &Graph{Roots: roots}
	for _, id := range sortedNodeIDs(nodes) {
		g.Nodes = append(g.Nodes, *nodes[id])
	}
	g.Cycles = findCycles(g)
	return g, nil
}

func platformMatch(platforms []string, target string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, p := range platforms {
		if p == target {
			return true
		}
	}
	return false
}

func lessID(a, b NodeID) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Version.Compare(b.Version) < 0
}

func sortedIDs(set map[NodeID]bool) []NodeID {
	out := make([]NodeID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return lessID(out[i], out[j]) })
	return out
}

func sortedNodeIDs(m map[NodeID]*Node) []NodeID {
	out := make([]NodeID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return lessID(out[i], out[j]) })
	return out
}

// findCycles 以确定性顺序做 DFS，报告全部简单循环（按起始节点规范化）。
func findCycles(g *Graph) [][]NodeID {
	adj := map[NodeID][]NodeID{}
	for _, n := range g.Nodes {
		from := NodeID{Name: n.Name, Version: n.Version}
		for _, e := range n.Deps {
			adj[from] = append(adj[from], e.To)
		}
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[NodeID]int{}
	var stack []NodeID
	seen := map[string]bool{}
	var cycles [][]NodeID
	var dfs func(u NodeID)
	dfs = func(u NodeID) {
		color[u] = gray
		stack = append(stack, u)
		for _, w := range adj[u] {
			switch color[w] {
			case gray:
				// 找到循环：截取栈中 w 之后的部分。
				idx := 0
				for i, s := range stack {
					if s == w {
						idx = i
						break
					}
				}
				cyc := append([]NodeID(nil), stack[idx:]...)
				key := cycleKey(cyc)
				if !seen[key] {
					seen[key] = true
					cycles = append(cycles, cyc)
				}
			case white:
				dfs(w)
			}
		}
		stack = stack[:len(stack)-1]
		color[u] = black
	}
	for _, n := range g.Nodes {
		id := NodeID{Name: n.Name, Version: n.Version}
		if color[id] == white {
			dfs(id)
		}
	}
	return cycles
}

// cycleKey 将循环按字典序最小起点规范化，保证去重与输出确定。
func cycleKey(cyc []NodeID) string {
	if len(cyc) == 0 {
		return ""
	}
	strs := make([]string, len(cyc))
	minI := 0
	for i, id := range cyc {
		strs[i] = id.Name + "@" + id.Version.String()
		if strs[i] < strs[minI] {
			minI = i
		}
	}
	key := ""
	for k := 0; k < len(strs); k++ {
		key += strs[(minI+k)%len(strs)] + ">"
	}
	return key
}
