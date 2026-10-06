package sbom

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

func testGraph(t *testing.T) *depgraph.Graph {
	t.Helper()
	ex := func(s string) depgraph.Constraint {
		v, _ := depgraph.ParseVersion(s)
		return depgraph.Constraint{Exact: &v}
	}
	m := &depgraph.Manifest{
		Roots: []depgraph.Dependency{{Name: "app", Constraint: ex("1.0.0")}},
		Components: []depgraph.Component{
			{Name: "app", Version: depgraph.Version{Major: 1, Minor: 0, Patch: 0}, Deps: []depgraph.Dependency{
				{Name: "liba", Constraint: ex("1.2.0")},
				{Name: "libb", Constraint: ex("2.0.0")},
			}},
			{Name: "liba", Version: depgraph.Version{Major: 1, Minor: 2, Patch: 0}},
			{Name: "libb", Version: depgraph.Version{Major: 2, Minor: 0, Patch: 0}},
		},
	}
	g, err := depgraph.Resolve(m, depgraph.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func digestOf(name, version string) (string, error) {
	return fmt.Sprintf("sha256:%064x", len(name)+len(version)), nil
}

func TestReproducible(t *testing.T) {
	g := testGraph(t)
	d1, err := Generate(g, digestOf, Spec11)
	if err != nil {
		t.Fatal(err)
	}
	// 多次运行结果必须字节级一致（无时间戳/随机化）。
	for i := 0; i < 5; i++ {
		d2, err := Generate(g, digestOf, Spec11)
		if err != nil {
			t.Fatal(err)
		}
		b1, _ := Marshal(d1)
		b2, _ := Marshal(d2)
		if !bytes.Equal(b1, b2) {
			t.Fatalf("run %d not reproducible:\n%s\n%s", i, b1, b2)
		}
	}
}

func TestConvertLossReported(t *testing.T) {
	g := testGraph(t)
	d, err := Generate(g, digestOf, Spec11)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Convert(d, Spec10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Losses) == 0 {
		t.Fatal("downgrade 1.1->1.0 must report losses")
	}
	for _, c := range res.Document.Components {
		if len(c.DependsOn) != 0 || c.SourcePath != "" {
			t.Fatalf("1.0 doc must not carry 1.1 fields: %+v", c)
		}
	}
	// 升级无损。
	res2, err := Convert(res.Document, Spec11)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Losses) != 0 {
		t.Fatalf("upgrade must be lossless, got %v", res2.Losses)
	}
}
