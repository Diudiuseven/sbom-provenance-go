package sbom

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
)

func testGraph() *depgraph.Graph {
	return &depgraph.Graph{
		Nodes: []depgraph.Node{
			{Name: "app", Version: "1.0.0"},
			{Name: "liba", Version: "1.2.0"},
			{Name: "libb", Version: "1.4.0"},
			{Name: "libb", Version: "1.6.0"},
		},
		Edges: []depgraph.Edge{
			{From: depgraph.Node{Name: "app", Version: "1.0.0"}, To: depgraph.Node{Name: "liba", Version: "1.2.0"}},
			{From: depgraph.Node{Name: "app", Version: "1.0.0"}, To: depgraph.Node{Name: "libb", Version: "1.6.0"}},
			{From: depgraph.Node{Name: "liba", Version: "1.2.0"}, To: depgraph.Node{Name: "libb", Version: "1.4.0"}},
		},
	}
}

// The same graph must serialize byte-identically across runs, goroutine
// scheduling and edge insertion order.
func TestReproducibleOutput(t *testing.T) {
	g := testGraph()
	want, err := Marshal(FromGraph(g, SpecV1))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			g2 := testGraph()
			rng.Shuffle(len(g2.Edges), func(a, b int) { g2.Edges[a], g2.Edges[b] = g2.Edges[b], g2.Edges[a] })
			got, err := Marshal(FromGraph(g2, SpecV1))
			if err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(want, got) {
				t.Errorf("non-reproducible output:\n%s\nvs\n%s", want, got)
			}
		}(int64(i))
	}
	wg.Wait()
}

// Digests must match for identical docs and differ for different specs.
func TestDigestStability(t *testing.T) {
	d1, _ := Digest(FromGraph(testGraph(), SpecV1))
	d2, _ := Digest(FromGraph(testGraph(), SpecV1))
	if d1 != d2 {
		t.Fatal("digest not stable")
	}
	d3, _ := Digest(FromGraph(testGraph(), SpecV2))
	if d1 == d3 {
		t.Fatal("different specs produced identical digests")
	}
}

func TestConvertV2ToV1ReportsLoss(t *testing.T) {
	doc := FromGraph(testGraph(), SpecV2)
	doc.Components[0].Supplier = "Example Corp"
	out, losses, err := Convert(doc, SpecV1)
	if err != nil {
		t.Fatal(err)
	}
	if len(losses) != 1 || losses[0].Field != "supplier" || losses[0].Subject != "app@1.0.0" {
		t.Fatalf("expected one supplier loss for app@1.0.0, got %+v", losses)
	}
	if out.Components[0].Supplier != "" {
		t.Fatal("supplier must be dropped in v1")
	}
}

func TestConvertV1ToV2Lossless(t *testing.T) {
	doc := FromGraph(testGraph(), SpecV1)
	_, losses, err := Convert(doc, SpecV2)
	if err != nil {
		t.Fatal(err)
	}
	if len(losses) != 0 {
		t.Fatalf("v1->v2 must be lossless, got %+v", losses)
	}
	if _, _, err := Convert(doc, "9.9"); err == nil {
		t.Fatal("unsupported spec must error")
	}
}
