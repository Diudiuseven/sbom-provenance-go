// Package depgraph parses dependency manifests into a deterministic
// dependency graph. It handles multiple coexisting versions of the same
// component, circular references, optional dependencies and
// platform-conditional dependencies.
package depgraph

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Requirement is a single dependency edge declared in a manifest.
type Requirement struct {
	// From is the component declaring the dependency. Empty for roots.
	From string
	// Name is the depended-upon component name.
	Name string
	// Constraint is a semver-style constraint, e.g. ">=1.2.0 <2.0.0".
	Constraint string
	// Optional marks dependencies that may be skipped when unresolvable.
	Optional bool
	// Platforms restricts the dependency to GOOS/GOARCH pairs ("linux/amd64").
	// Empty means all platforms.
	Platforms []string
}

// Manifest is the parsed dependency declaration.
type Manifest struct {
	Roots        []string
	Requirements []Requirement
	// Available maps component name to the list of published versions.
	Available map[string][]string
}

// manifestJSON is the on-disk schema.
type manifestJSON struct {
	Roots        []string            `json:"roots"`
	Requirements []requirementJSON   `json:"requirements"`
	Available    map[string][]string `json:"available"`
}

type requirementJSON struct {
	From       string   `json:"from"`
	Name       string   `json:"name"`
	Constraint string   `json:"constraint"`
	Optional   bool     `json:"optional,omitempty"`
	Platforms  []string `json:"platforms,omitempty"`
}

// ParseManifest parses manifest bytes (JSON) into a Manifest. The result is
// canonicalized (sorted) so downstream resolution is independent of the
// declaration order in the input.
func ParseManifest(data []byte) (*Manifest, error) {
	var mj manifestJSON
	if err := json.Unmarshal(data, &mj); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	m := &Manifest{
		Roots:     append([]string(nil), mj.Roots...),
		Available: map[string][]string{},
	}
	for name, vers := range mj.Available {
		if len(vers) == 0 {
			return nil, fmt.Errorf("component %q has no available versions", name)
		}
		vs := append([]string(nil), vers...)
		var err error
		vs, err = sortVersions(vs)
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", name, err)
		}
		m.Available[name] = vs
	}
	for _, r := range mj.Requirements {
		if r.Name == "" {
			return nil, fmt.Errorf("requirement with empty name")
		}
		if _, err := parseConstraint(r.Constraint); err != nil {
			return nil, fmt.Errorf("requirement %s -> %s: %w", r.From, r.Name, err)
		}
		plats := append([]string(nil), r.Platforms...)
		sort.Strings(plats)
		m.Requirements = append(m.Requirements, Requirement{
			From:       r.From,
			Name:       r.Name,
			Constraint: r.Constraint,
			Optional:   r.Optional,
			Platforms:  plats,
		})
	}
	// Canonical ordering: by From, then Name, then Constraint.
	sort.Slice(m.Requirements, func(i, j int) bool {
		a, b := m.Requirements[i], m.Requirements[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Constraint < b.Constraint
	})
	roots := append([]string(nil), mj.Roots...)
	sort.Strings(roots)
	m.Roots = roots
	return m, nil
}
