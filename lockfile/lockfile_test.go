package lockfile

import (
	"testing"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

func graph() *depgraph.Graph {
	return &depgraph.Graph{Nodes: []depgraph.Node{
		{Name: "app", Version: "1.0.0"},
		{Name: "liba", Version: "1.2.0"},
	}}
}

func digests() map[string]string {
	return map[string]string{
		"app@1.0.0":  "sha256:aaa",
		"liba@1.2.0": "sha256:bbb",
	}
}

func TestPinAndCleanCheck(t *testing.T) {
	l := Pin(graph(), digests())
	if len(l.Entries) != 2 || l.Entries[0].Name != "app" {
		t.Fatalf("pin not deterministic/sorted: %+v", l.Entries)
	}
	if d := Check(l, graph(), digests()); len(d) != 0 {
		t.Fatalf("unexpected drift: %+v", d)
	}
}

func TestDriftDetection(t *testing.T) {
	l := Pin(graph(), digests())

	// Version drift: manifest now resolves liba to 1.3.0.
	g2 := &depgraph.Graph{Nodes: []depgraph.Node{
		{Name: "app", Version: "1.0.0"},
		{Name: "liba", Version: "1.3.0"},
	}}
	d := Check(l, g2, map[string]string{"app@1.0.0": "sha256:aaa", "liba@1.3.0": "sha256:ccc"})
	var paths []string
	for _, x := range d {
		paths = append(paths, x.Component+"|"+x.Path)
	}
	// Expect: liba@1.3.0 drift at "manifest", liba@1.2.0 drift at "lockfile".
	found := map[string]bool{}
	for _, p := range paths {
		found[p] = true
	}
	if !found["liba@1.3.0|manifest"] || !found["liba@1.2.0|lockfile"] {
		t.Fatalf("version drift not reported with paths: %v", paths)
	}

	// Content drift: artifact hash changed.
	d = Check(l, graph(), map[string]string{"app@1.0.0": "sha256:aaa", "liba@1.2.0": "sha256:FORGED"})
	if len(d) != 1 || d[0].Component != "liba@1.2.0" || d[0].Path != "artifact" {
		t.Fatalf("content drift not reported: %+v", d)
	}
}
