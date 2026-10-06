// Package integration 端到端测试：清单解析 -> 锁定 -> SBOM -> 信任材料 -> 批量校验。
package integration

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/cache"
	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
	"github.com/Diudiuseven/sbom-provenance-go/keys"
	"github.com/Diudiuseven/sbom-provenance-go/lockfile"
	"github.com/Diudiuseven/sbom-provenance-go/provenance"
	"github.com/Diudiuseven/sbom-provenance-go/sbom"
	"github.com/Diudiuseven/sbom-provenance-go/tlog"
	"github.com/Diudiuseven/sbom-provenance-go/verify"
)

func ex(s string) depgraph.Constraint {
	v, _ := depgraph.ParseVersion(s)
	return depgraph.Constraint{Exact: &v}
}

func TestEndToEnd(t *testing.T) {
	// 1. 清单解析（含多版本共存）。
	m := &depgraph.Manifest{
		Roots: []depgraph.Dependency{{Name: "app", Constraint: ex("1.0.0")}},
		Components: []depgraph.Component{
			{Name: "app", Version: depgraph.Version{Major: 1}, Deps: []depgraph.Dependency{
				{Name: "lib", Constraint: ex("1.0.0")},
				{Name: "lib", Constraint: ex("2.0.0")},
			}},
			{Name: "lib", Version: depgraph.Version{Major: 1}},
			{Name: "lib", Version: depgraph.Version{Major: 2}},
		},
	}
	g, err := depgraph.Resolve(m, depgraph.Options{Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 3 {
		t.Fatalf("nodes = %v", g.Nodes)
	}

	// 2. 依赖固定 + 漂移检测（无漂移）。
	artifacts := map[string][]byte{}
	digestOf := func(name, version string) (string, error) {
		content := []byte(fmt.Sprintf("artifact-%s-%s", name, version))
		artifacts[name+"@"+version] = content
		return provenance.DigestOf(content), nil
	}
	lock, err := lockfile.FromGraph(g, digestOf, func(n, v string) string { return "local://" + n + "/" + v })
	if err != nil {
		t.Fatal(err)
	}
	if drifts := lockfile.Check(g, lock); len(drifts) != 0 {
		t.Fatalf("unexpected drift: %v", drifts)
	}

	// 3. SBOM 生成（两次运行字节级一致）。
	doc1, err := sbom.Generate(g, digestOf, sbom.Spec11)
	if err != nil {
		t.Fatal(err)
	}
	doc2, _ := sbom.Generate(g, digestOf, sbom.Spec11)
	b1, _ := sbom.Marshal(doc1)
	b2, _ := sbom.Marshal(doc2)
	if !reflect.DeepEqual(b1, b2) {
		t.Fatal("SBOM not reproducible")
	}

	// 4. 本地生成信任材料并批量校验。
	ks := keys.NewStore()
	now := time.Now()
	priv, _ := ks.Generate("root", now.Add(-time.Minute), now.Add(time.Hour))
	lg, _ := tlog.Open("")
	var mats []*provenance.Materials
	for _, e := range lock.Entries {
		id := e.Name + "@" + e.Version
		content := artifacts[id]
		if d := lockfile.VerifyArtifact(lock, e.Name, e.Version, content); d != nil {
			t.Fatalf("artifact drift: %v", d)
		}
		digest := provenance.DigestOf(content)
		idx, _ := lg.Append(tlog.Entry{ArtifactDigest: digest, Component: id})
		proof, _ := lg.ProveInclusion(idx)
		mats = append(mats, &provenance.Materials{
			Component:      id,
			Artifact:       content,
			ExpectedDigest: digest,
			Signature:      ed25519.Sign(priv, []byte(digest)),
			KeyID:          "root",
			Attestation:    &provenance.Attestation{SubjectComponent: id, SubjectDigest: digest, BuilderID: "local"},
			Inclusion:      proof,
			LogEntry:       tlog.Entry{ArtifactDigest: digest, Component: id},
		})
	}
	pv := &provenance.Verifier{Keys: ks, Log: lg, Now: func() time.Time { return now }}
	batch := &verify.Batch{Prov: pv, Cache: cache.New(), Workers: 4, Timeout: 2 * time.Second}
	sum := batch.Run(mats)
	if len(sum.Passed) != 3 || len(sum.Failed) != 0 || len(sum.Skipped) != 0 {
		t.Fatalf("summary = %+v", sum)
	}

	// 5. 不同并发度下结果必须一致。
	batch2 := &verify.Batch{Prov: pv, Cache: cache.New(), Workers: 1, Timeout: 2 * time.Second}
	sum2 := batch2.Run(mats)
	if !reflect.DeepEqual(sum, sum2) {
		t.Fatalf("concurrency changed result:\n%+v\n%+v", sum, sum2)
	}
}
