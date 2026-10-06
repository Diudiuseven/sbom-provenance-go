package lockfile

import (
	"testing"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

func graph(t *testing.T, rootVer string) *depgraph.Graph {
	t.Helper()
	ex := func(s string) depgraph.Constraint {
		v, _ := depgraph.ParseVersion(s)
		return depgraph.Constraint{Exact: &v}
	}
	rv, _ := depgraph.ParseVersion(rootVer)
	comps := []depgraph.Component{{Name: "lib", Version: rv}}
	if rootVer != "1.0.0" {
		comps = append(comps, depgraph.Component{Name: "lib", Version: depgraph.Version{Major: 1, Minor: 0, Patch: 0}})
	}
	m := &depgraph.Manifest{
		Roots:      []depgraph.Dependency{{Name: "lib", Constraint: ex(rootVer)}},
		Components: comps,
	}
	g, err := depgraph.Resolve(m, depgraph.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func digestOf(name, version string) (string, error) {
	return "sha256:locked-" + name + "-" + version, nil
}
func sourceOf(name, version string) string { return "local://" + name + "/" + version }

func TestNoDrift(t *testing.T) {
	g := graph(t, "1.0.0")
	lock, err := FromGraph(g, digestOf, sourceOf)
	if err != nil {
		t.Fatal(err)
	}
	if d := Check(g, lock); len(d) != 0 {
		t.Fatalf("unexpected drift: %v", d)
	}
}

func TestVersionDrift(t *testing.T) {
	g1 := graph(t, "1.0.0")
	lock, _ := FromGraph(g1, digestOf, sourceOf)
	// 清单改为锁定外的版本 -> 必须报告漂移并指出组件。
	g2 := graph(t, "1.0.0")
	g2.Nodes[0].Version = depgraph.Version{Major: 2, Minor: 0, Patch: 0}
	drifts := Check(g2, lock)
	if len(drifts) != 2 { // 新版本未锁定 + 旧版本不再被解析
		t.Fatalf("drifts = %v", drifts)
	}
	if drifts[0].Component == "" || drifts[1].Component == "" {
		t.Fatalf("drift must name component: %v", drifts)
	}
}

func TestArtifactDrift(t *testing.T) {
	lock := &Lock{Entries: []Entry{{
		Name: "lib", Version: "1.0.0",
		Digest:     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		SourcePath: "local://lib/1.0.0",
	}}}
	d := VerifyArtifact(lock, "lib", "1.0.0", []byte("real content"))
	if d == nil {
		t.Fatal("hash mismatch must be reported")
	}
	if d.SourcePath != "local://lib/1.0.0" {
		t.Fatalf("drift must carry source path: %+v", d)
	}
	if d2 := VerifyArtifact(lock, "ghost", "9.9.9", nil); d2 == nil {
		t.Fatal("missing lock entry must be reported")
	}
}
