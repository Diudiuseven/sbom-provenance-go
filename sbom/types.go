// Package sbom generates reproducible software bills of materials from a
// resolved dependency graph and converts between spec versions.
package sbom

import (
	"sort"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

// SpecVersion identifies the SBOM specification version.
type SpecVersion string

const (
	// SpecV1 is the base spec: components, hashes, licenses, dependencies.
	SpecV1 SpecVersion = "1.0"
	// SpecV2 adds supplier and PURL metadata.
	SpecV2 SpecVersion = "2.0"
)

// Component is one SBOM entry.
type Component struct {
	Name     string
	Version  string
	PURL     string
	Hashes   map[string]string
	Licenses []string
	// Supplier is only representable in SpecV2.
	Supplier string
}

// Document is a spec-agnostic SBOM.
type Document struct {
	Spec       SpecVersion
	Components []Component
	// Dependencies as "name@version -> [name@version...]" adjacency.
	Dependencies map[string][]string
}

// FromGraph builds a Document from a resolved graph. Output is canonical:
// components sorted by (name, version), adjacency lists sorted.
func FromGraph(g *depgraph.Graph, spec SpecVersion) *Document {
	doc := &Document{
		Spec:         spec,
		Dependencies: map[string][]string{},
	}
	for _, n := range g.Nodes {
		doc.Components = append(doc.Components, Component{
			Name:    n.Name,
			Version: n.Version,
			PURL:    "pkg:generic/" + n.Name + "@" + n.Version,
		})
	}
	sort.Slice(doc.Components, func(i, j int) bool {
		a, b := doc.Components[i], doc.Components[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	adj := map[string]map[string]bool{}
	for _, e := range g.Edges {
		from, to := e.From.String(), e.To.String()
		if adj[from] == nil {
			adj[from] = map[string]bool{}
		}
		adj[from][to] = true
	}
	for from, set := range adj {
		list := make([]string, 0, len(set))
		for to := range set {
			list = append(list, to)
		}
		sort.Strings(list)
		doc.Dependencies[from] = list
	}
	return doc
}
