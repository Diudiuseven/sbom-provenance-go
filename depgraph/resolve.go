package depgraph

import (
	"fmt"
	"sort"
	"strings"
)

// Node is a resolved component instance.
type Node struct {
	Name    string
	Version string
}

// String returns the canonical "name@version" form.
func (n Node) String() string { return n.Name + "@" + n.Version }

// Edge is a resolved dependency relation.
type Edge struct {
	From, To Node
	Optional bool
}

// Graph is the deterministic resolution result.
type Graph struct {
	Nodes []Node
	Edges []Edge
	// Cycles lists detected cycles as node sequences (canonical order).
	Cycles [][]Node
	// Skipped lists optional/platform deps not included, with reasons.
	Skipped []Skip
}

// Skip records a dependency that was not included.
type Skip struct {
	From   Node
	Name   string
	Reason string
}

// Options controls resolution.
type Options struct {
	// Platform is the target "os/arch"; empty matches everything.
	Platform string
}

// reqRef pairs a requirement with its referrer component name ("" = root).
type reqRef struct {
	from string
	req  Requirement
}

// Resolve deterministically selects versions and builds the dependency
// graph. The result is independent of manifest requirement ordering and of
// traversal order: selection always picks the maximum version satisfying
// all constraints when possible, otherwise splits into the minimal
// deterministic set of coexisting versions.
func Resolve(m *Manifest, opts Options) (*Graph, error) {
	if m == nil {
		return nil, fmt.Errorf("nil manifest")
	}
	// Seed requirements: roots plus explicit root-level requirements.
	seed := []reqRef{}
	for _, r := range m.Roots {
		seed = append(seed, reqRef{from: "", req: Requirement{Name: r, Constraint: "*"}})
	}
	for _, r := range m.Requirements {
		if r.From == "" {
			seed = append(seed, reqRef{from: "", req: r})
		}
	}

	resolved := map[string][]string{} // name -> selected versions (sorted asc)
	reqs := map[string][]reqRef{}
	for _, s := range seed {
		reqs[s.req.Name] = append(reqs[s.req.Name], s)
	}
	skips := map[string]Skip{}

	// Fixpoint: recompute selections until both the requirement sets and
	// the selected versions stop changing. Requirement sets grow
	// monotonically per round snapshot, so this terminates; a hard bound
	// guards against pathological oscillation.
	const maxRounds = 1024
	var prevSig string
	for round := 0; ; round++ {
		if round > maxRounds {
			return nil, fmt.Errorf("resolution did not converge after %d rounds", maxRounds)
		}
		changed := false
		for _, name := range sortedKeys(reqs) {
			sel, sk, err := selectVersions(m.Available[name], reqs[name], name)
			if err != nil {
				return nil, err
			}
			for _, s := range sk {
				skips[s.From.String()+"|"+s.Name+"|"+s.Reason] = s
			}
			if !equalStrings(resolved[name], sel) {
				resolved[name] = sel
				changed = true
			}
		}
		// Rebuild requirement sets from current selection.
		newReqs := map[string][]reqRef{}
		for _, s := range seed {
			newReqs[s.req.Name] = append(newReqs[s.req.Name], s)
		}
		for _, name := range sortedKeys(resolved) {
			if len(resolved[name]) == 0 {
				continue
			}
			for _, r := range m.Requirements {
				if r.From != name {
					continue
				}
				if !platformMatch(r.Platforms, opts.Platform) {
					for _, v := range resolved[name] {
						s := Skip{From: Node{Name: name, Version: v}, Name: r.Name, Reason: "platform_excluded"}
						skips[s.From.String()+"|"+s.Name+"|"+s.Reason] = s
					}
					continue
				}
				newReqs[r.Name] = append(newReqs[r.Name], reqRef{from: name, req: r})
			}
		}
		sig := reqsSignature(newReqs) + "|" + resolvedSignature(resolved)
		if !changed && sig == prevSig {
			reqs = newReqs
			break
		}
		prevSig = sig
		reqs = newReqs
	}

	// Materialize nodes.
	g := &Graph{}
	for _, name := range sortedKeys(resolved) {
		for _, v := range resolved[name] {
			g.Nodes = append(g.Nodes, Node{Name: name, Version: v})
		}
	}
	nodeSet := map[Node]bool{}
	for _, n := range g.Nodes {
		nodeSet[n] = true
	}

	// Bind every requirement to a concrete instance: the maximum selected
	// version satisfying its constraint.
	edgeSet := map[string]Edge{}
	for _, name := range sortedKeys(reqs) {
		versions := resolved[name]
		if len(versions) == 0 {
			continue
		}
		for _, rr := range reqs[name] {
			to, ok := bindVersion(versions, rr.req.Constraint)
			if !ok {
				if rr.req.Optional {
					continue // already recorded as skipped
				}
				return nil, fmt.Errorf("no selected version of %s satisfies %q (required by %q)", name, rr.req.Constraint, rr.from)
			}
			toNode := Node{Name: name, Version: to}
			if rr.from == "" {
				continue // root edge: node is a root, no incoming edge
			}
			for _, fv := range resolved[rr.from] {
				fromNode := Node{Name: rr.from, Version: fv}
				if !nodeSet[fromNode] {
					continue
				}
				e := Edge{From: fromNode, To: toNode, Optional: rr.req.Optional}
				edgeSet[e.From.String()+"->"+e.To.String()] = e
			}
		}
	}
	for _, k := range sortedKeys(edgeSet) {
		g.Edges = append(g.Edges, edgeSet[k])
	}
	for _, k := range sortedKeys(skips) {
		g.Skipped = append(g.Skipped, skips[k])
	}
	g.Cycles = findCycles(g)
	return g, nil
}

// selectVersions picks the deterministic version set for one component.
// Strategy: if a single version satisfies every requirement, pick the
// maximum such version. Otherwise process requirements in canonical order,
// reusing an already-selected version when it satisfies the requirement and
// otherwise adding the maximum version satisfying that requirement —
// yielding the minimal deterministic set of coexisting versions.
func selectVersions(available []string, rs []reqRef, name string) ([]string, []Skip, error) {
	if len(available) == 0 {
		allOptional := len(rs) > 0
		var skips []Skip
		for _, rr := range rs {
			if !rr.req.Optional {
				allOptional = false
				break
			}
			skips = append(skips, Skip{From: Node{Name: rr.from}, Name: name, Reason: "optional_unsatisfiable"})
		}
		if allOptional {
			return nil, skips, nil
		}
		return nil, nil, fmt.Errorf("component %q is required but has no available versions", name)
	}
	cons := make([]constraint, 0, len(rs))
	for _, rr := range rs {
		c, err := parseConstraint(rr.req.Constraint)
		if err != nil {
			return nil, nil, fmt.Errorf("component %q: %w", name, err)
		}
		cons = append(cons, c)
	}
	// Fast path: one version satisfies all.
	var best string
	found := false
	for _, v := range available { // ascending; keep last match = max
		ok := true
		for _, c := range cons {
			if !c.matches(v) {
				ok = false
				break
			}
		}
		if ok {
			best, found = v, true
		}
	}
	if found {
		return []string{best}, nil, nil
	}
	// Split path: minimal deterministic set of coexisting versions.
	selected := []string{}
	var skips []Skip
	for i, rr := range rs {
		sat := false
		for _, v := range selected {
			if cons[i].matches(v) {
				sat = true
				break
			}
		}
		if sat {
			continue
		}
		// Pick max available satisfying this single requirement.
		chosen := ""
		ok := false
		for _, v := range available {
			if cons[i].matches(v) {
				chosen, ok = v, true
			}
		}
		if !ok {
			if rr.req.Optional {
				from := Node{Name: rr.from, Version: ""}
				skips = append(skips, Skip{From: from, Name: name, Reason: "optional_unsatisfiable"})
				continue
			}
			return nil, nil, fmt.Errorf("no available version of %s satisfies %q (required by %q)", name, rr.req.Constraint, rr.from)
		}
		selected = insertSorted(selected, chosen)
	}
	if len(selected) == 0 {
		// All requirements were optional and unsatisfiable: the component
		// is simply absent from the graph.
		return nil, skips, nil
	}
	return selected, skips, nil
}

// bindVersion returns the maximum selected version satisfying the
// constraint.
func bindVersion(selected []string, cs string) (string, bool) {
	c, err := parseConstraint(cs)
	if err != nil {
		return "", false
	}
	best := ""
	ok := false
	for _, v := range selected {
		if c.matches(v) {
			best, ok = v, true
		}
	}
	return best, ok
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

// findCycles reports strongly connected components of size > 1 and
// self-loops, each in canonical (lexicographically-rotated) order.
func findCycles(g *Graph) [][]Node {
	adj := map[Node][]Node{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	for n := range adj {
		sort.Slice(adj[n], func(i, j int) bool { return adj[n][i].String() < adj[n][j].String() })
	}
	// Tarjan SCC with deterministic visitation order.
	index := map[Node]int{}
	low := map[Node]int{}
	onStack := map[Node]bool{}
	var stack []Node
	counter := 0
	var sccs [][]Node
	var strongconnect func(n Node)
	strongconnect = func(n Node) {
		index[n] = counter
		low[n] = counter
		counter++
		stack = append(stack, n)
		onStack[n] = true
		for _, m := range adj[n] {
			if _, seen := index[m]; !seen {
				strongconnect(m)
				if low[m] < low[n] {
					low[n] = low[m]
				}
			} else if onStack[m] {
				if index[m] < low[n] {
					low[n] = index[m]
				}
			}
		}
		if low[n] == index[n] {
			var scc []Node
			for {
				m := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[m] = false
				scc = append(scc, m)
				if m == n {
					break
				}
			}
			if len(scc) > 1 {
				sccs = append(sccs, canonicalCycle(scc))
			}
		}
	}
	for _, n := range g.Nodes { // g.Nodes already sorted
		if _, seen := index[n]; !seen {
			strongconnect(n)
		}
	}
	// Self-loops.
	for _, e := range g.Edges {
		if e.From == e.To {
			sccs = append(sccs, []Node{e.From})
		}
	}
	sort.Slice(sccs, func(i, j int) bool { return cycleKey(sccs[i]) < cycleKey(sccs[j]) })
	return sccs
}

// canonicalCycle rotates a cycle so its lexicographically smallest node is
// first, then sorts members for a stable representation.
func canonicalCycle(scc []Node) []Node {
	out := append([]Node(nil), scc...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func cycleKey(c []Node) string {
	parts := make([]string, len(c))
	for i, n := range c {
		parts[i] = n.String()
	}
	return strings.Join(parts, ",")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func insertSorted(vs []string, v string) []string {
	i := sort.SearchStrings(vs, v)
	if i < len(vs) && vs[i] == v {
		return vs
	}
	vs = append(vs, "")
	copy(vs[i+1:], vs[i:])
	vs[i] = v
	return vs
}

func reqsSignature(reqs map[string][]reqRef) string {
	var b strings.Builder
	for _, name := range sortedKeys(reqs) {
		b.WriteString(name)
		b.WriteString(":")
		rs := append([]reqRef(nil), reqs[name]...)
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].from != rs[j].from {
				return rs[i].from < rs[j].from
			}
			return rs[i].req.Constraint < rs[j].req.Constraint
		})
		for _, r := range rs {
			fmt.Fprintf(&b, "%s|%s|%v;", r.from, r.req.Constraint, r.req.Optional)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func resolvedSignature(resolved map[string][]string) string {
	var b strings.Builder
	for _, name := range sortedKeys(resolved) {
		b.WriteString(name)
		b.WriteString("=")
		b.WriteString(strings.Join(resolved[name], ","))
		b.WriteString("\n")
	}
	return b.String()
}
