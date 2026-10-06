package depgraph

import (
	"reflect"
	"testing"
)

func v(major, minor, patch int) Version { return Version{major, minor, patch} }

func exact(s string) Constraint {
	vv, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return Constraint{Exact: &vv}
}

func TestMultiVersionCoexist(t *testing.T) {
	m := &Manifest{
		Roots: []Dependency{
			{Name: "a", Constraint: exact("1.0.0")},
			{Name: "b", Constraint: exact("1.0.0")},
		},
		Components: []Component{
			{Name: "a", Version: v(1, 0, 0), Deps: []Dependency{{Name: "shared", Constraint: exact("1.0.0")}}},
			{Name: "b", Version: v(1, 0, 0), Deps: []Dependency{{Name: "shared", Constraint: exact("2.0.0")}}},
			{Name: "shared", Version: v(1, 0, 0)},
			{Name: "shared", Version: v(2, 0, 0)},
		},
	}
	g, err := Resolve(m, Options{Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range g.Nodes {
		got = append(got, n.Name+"@"+n.Version.String())
	}
	want := []string{"a@1.0.0", "b@1.0.0", "shared@1.0.0", "shared@2.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nodes = %v, want %v", got, want)
	}
}

func TestCycleTerminates(t *testing.T) {
	m := &Manifest{
		Roots: []Dependency{{Name: "a", Constraint: exact("1.0.0")}},
		Components: []Component{
			{Name: "a", Version: v(1, 0, 0), Deps: []Dependency{{Name: "b", Constraint: exact("1.0.0")}}},
			{Name: "b", Version: v(1, 0, 0), Deps: []Dependency{{Name: "a", Constraint: exact("1.0.0")}}},
		},
	}
	g, err := Resolve(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(g.Nodes))
	}
	if len(g.Cycles) != 1 {
		t.Fatalf("cycles = %v, want 1 cycle", g.Cycles)
	}
}

func TestOptionalAndPlatform(t *testing.T) {
	m := &Manifest{
		Roots: []Dependency{{Name: "app", Constraint: exact("1.0.0")}},
		Components: []Component{
			{Name: "app", Version: v(1, 0, 0), Deps: []Dependency{
				{Name: "opt", Constraint: exact("1.0.0"), Optional: true},
				{Name: "winonly", Constraint: exact("1.0.0"), Platforms: []string{"windows/amd64"}},
				{Name: "linonly", Constraint: exact("1.0.0"), Platforms: []string{"linux/amd64"}},
			}},
			{Name: "opt", Version: v(1, 0, 0)},
			{Name: "winonly", Version: v(1, 0, 0)},
			{Name: "linonly", Version: v(1, 0, 0)},
		},
	}
	g, err := Resolve(m, Options{Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 { // app + linonly
		t.Fatalf("nodes = %v, want app+linonly", g.Nodes)
	}
	g2, err := Resolve(m, Options{Platform: "linux/amd64", IncludeOptional: []string{"opt"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g2.Nodes) != 3 {
		t.Fatalf("nodes = %v, want app+linonly+opt", g2.Nodes)
	}
}

func TestDeterministicAcrossOrder(t *testing.T) {
	comps := []Component{
		{Name: "a", Version: v(1, 0, 0), Deps: []Dependency{{Name: "c", Constraint: Constraint{Min: v(1, 0, 0)}}}},
		{Name: "b", Version: v(1, 0, 0), Deps: []Dependency{{Name: "c", Constraint: Constraint{Min: v(1, 0, 0), Max: v(2, 0, 0), HasMax: true}}}},
		{Name: "c", Version: v(1, 0, 0)},
		{Name: "c", Version: v(1, 5, 0)},
		{Name: "c", Version: v(2, 1, 0)},
	}
	roots := []Dependency{{Name: "a", Constraint: exact("1.0.0")}, {Name: "b", Constraint: exact("1.0.0")}}
	g1, err := Resolve(&Manifest{Roots: roots, Components: comps}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// 反转声明顺序，结果必须一致。
	rc := make([]Component, len(comps))
	for i, c := range comps {
		rc[len(comps)-1-i] = c
	}
	rr := []Dependency{roots[1], roots[0]}
	g2, err := Resolve(&Manifest{Roots: rr, Components: rc}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g1, g2) {
		t.Fatalf("non-deterministic:\n%+v\n%+v", g1, g2)
	}
	// a 应选 c@2.1.0（最高满足），b 应选 c@1.5.0（上界约束）。
	sel := map[string]string{}
	for _, n := range g1.Nodes {
		for _, e := range n.Deps {
			sel[n.Name] = e.To.Name + "@" + e.To.Version.String()
		}
	}
	if sel["a"] != "c@2.1.0" || sel["b"] != "c@1.5.0" {
		t.Fatalf("selection = %v", sel)
	}
}
