// Package lockfile pins resolved dependencies and detects drift between the
// manifest, the lock record and artifact content hashes.
package lockfile

import (
	"fmt"
	"sort"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

// Entry pins one component.
type Entry struct {
	Name    string
	Version string
	// Digest is "sha256:<hex>" of the artifact content.
	Digest string
}

// Lock is a set of pinned entries.
type Lock struct {
	Entries []Entry
}

// Pin builds a deterministic lock from a resolved graph and artifact
// digests keyed by "name@version". Entries are sorted by (name, version).
func Pin(g *depgraph.Graph, digests map[string]string) *Lock {
	l := &Lock{}
	for _, n := range g.Nodes {
		key := n.String()
		l.Entries = append(l.Entries, Entry{
			Name:    n.Name,
			Version: n.Version,
			Digest:  digests[key],
		})
	}
	sort.Slice(l.Entries, func(i, j int) bool {
		a, b := l.Entries[i], l.Entries[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return l
}

// Drift describes one detected inconsistency.
type Drift struct {
	Component string
	// Path is the source path where the drift was observed:
	// "manifest" (resolution disagrees with the lock), "lockfile"
	// (lock records something the manifest no longer produces) or
	// "artifact" (content hash mismatch).
	Path   string
	Detail string
}

func (d Drift) String() string {
	return fmt.Sprintf("%s [%s]: %s", d.Component, d.Path, d.Detail)
}

// Check verifies the graph and artifact digests against the lock. Any
// mismatch blocks and reports the drifted component and source path.
// The result is sorted by (component, path) for determinism; an empty
// result means no drift.
func Check(l *Lock, g *depgraph.Graph, digests map[string]string) []Drift {
	locked := map[string]Entry{}
	for _, e := range l.Entries {
		locked[e.Name+"@"+e.Version] = e
	}
	var drifts []Drift
	seen := map[string]bool{}
	for _, n := range g.Nodes {
		key := n.String()
		seen[key] = true
		e, ok := locked[key]
		if !ok {
			// Same name at a different version is a version drift;
			// otherwise the component is entirely new.
			detail := fmt.Sprintf("resolved %s is not recorded in the lockfile", key)
			for _, le := range l.Entries {
				if le.Name == n.Name {
					detail = fmt.Sprintf("manifest resolves %s to %s but lockfile pins %s", n.Name, n.Version, le.Version)
					break
				}
			}
			drifts = append(drifts, Drift{Component: key, Path: "manifest", Detail: detail})
			continue
		}
		got := digests[key]
		if got == "" {
			drifts = append(drifts, Drift{Component: key, Path: "artifact", Detail: "artifact content missing; cannot verify pinned digest"})
			continue
		}
		if e.Digest != got {
			drifts = append(drifts, Drift{
				Component: key,
				Path:      "artifact",
				Detail:    fmt.Sprintf("content digest %s does not match pinned %s", got, e.Digest),
			})
		}
	}
	for _, e := range l.Entries {
		key := e.Name + "@" + e.Version
		if !seen[key] {
			drifts = append(drifts, Drift{
				Component: key,
				Path:      "lockfile",
				Detail:    "locked component is no longer produced by the manifest",
			})
		}
	}
	sort.Slice(drifts, func(i, j int) bool {
		if drifts[i].Component != drifts[j].Component {
			return drifts[i].Component < drifts[j].Component
		}
		return drifts[i].Path < drifts[j].Path
	})
	return drifts
}
