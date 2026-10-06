package depgraph

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"
)

func testManifest() *Manifest {
	return &Manifest{
		Roots: []string{"app"},
		Requirements: []Requirement{
			{From: "", Name: "app", Constraint: ">=1.0.0"},
			{From: "app", Name: "liba", Constraint: ">=1.0.0 <2.0.0"},
			{From: "app", Name: "libb", Constraint: ">=1.5.0"},
			{From: "liba", Name: "libb", Constraint: "<1.5.0"}, // forces libb split
			{From: "libb", Name: "libc", Constraint: "^1.0.0"},
			{From: "libc", Name: "liba", Constraint: ">=1.0.0"}, // cycle liba->libb->libc->liba
			{From: "app", Name: "opt", Constraint: ">=9.9.9", Optional: true},
			{From: "app", Name: "plat", Constraint: "*", Platforms: []string{"windows/amd64"}},
		},
		Available: map[string][]string{
			"app":  {"1.0.0"},
			"liba": {"1.0.0", "1.2.0", "2.0.0"},
			"libb": {"1.0.0", "1.4.0", "1.6.0"},
			"libc": {"1.0.0", "1.1.0"},
			"opt":  {"1.0.0"},
			"plat": {"1.0.0"},
		},
	}
}

func TestResolveMultiVersionAndCycle(t *testing.T) {
	g, err := Resolve(testManifest(), Options{Platform: "linux/amd64"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// libb must be split into 1.4.0 (for liba) and 1.6.0 (for app).
	var libb []string
	for _, n := range g.Nodes {
		if n.Name == "libb" {
			libb = append(libb, n.Version)
		}
	}
	if !reflect.DeepEqual(libb, []string{"1.4.0", "1.6.0"}) {
		t.Fatalf("libb versions = %v, want [1.4.0 1.6.0]", libb)
	}
	// liba pinned to 1.x by app constraint.
	for _, n := range g.Nodes {
		if n.Name == "liba" && n.Version != "1.2.0" {
			t.Fatalf("liba version = %v, want 1.2.0", n.Version)
		}
	}
	if len(g.Cycles) == 0 {
		t.Fatalf("expected cycle detection, got none")
	}
	// Optional unsatisfiable dep skipped with reason.
	foundSkip := false
	for _, s := range g.Skipped {
		if s.Name == "opt" && s.Reason == "optional_unsatisfiable" {
			foundSkip = true
		}
		if s.Name == "plat" && s.Reason == "platform_excluded" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("expected skips for opt/plat, got %+v", g.Skipped)
	}
}

func TestResolveDeterministicUnderShuffle(t *testing.T) {
	base, err := Resolve(testManifest(), Options{Platform: "linux/amd64"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 20; i++ {
		m := testManifest()
		rng.Shuffle(len(m.Requirements), func(a, b int) {
			m.Requirements[a], m.Requirements[b] = m.Requirements[b], m.Requirements[a]
		})
		g, err := Resolve(m, Options{Platform: "linux/amd64"})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !reflect.DeepEqual(base, g) {
			t.Fatalf("nondeterministic result:\nbase=%+v\ngot =%+v", base, g)
		}
	}
}

func TestParseManifestCanonicalizes(t *testing.T) {
	m1 := testManifest()
	data1, _ := json.Marshal(m1)
	m2 := testManifest()
	for i, j := 0, len(m2.Requirements)-1; i < j; i, j = i+1, j-1 {
		m2.Requirements[i], m2.Requirements[j] = m2.Requirements[j], m2.Requirements[i]
	}
	data2, _ := json.Marshal(m2)
	p1, err := ParseManifest(data1)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParseManifest(data2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p1, p2) {
		t.Fatalf("parse not canonical:\n%+v\n%+v", p1, p2)
	}
}
