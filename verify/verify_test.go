package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/lockfile"
	"github.com/Diudiuseven/sbom-provenance-go/provenance"
	"github.com/Diudiuseven/sbom-provenance-go/tlog"
)

type fixture struct {
	store   *TrustStore
	log     *tlog.Log
	signKey ed25519.PrivateKey
	attKey  ed25519.PrivateKey
}

// TrustStore alias for brevity.
type TrustStore = provenance.TrustStore

func newFixture(t *testing.T) *fixture {
	t.Helper()
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	attPub, attPriv, _ := ed25519.GenerateKey(rand.Reader)
	l, err := tlog.Open(filepath.Join(t.TempDir(), "log.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		store: &provenance.TrustStore{Keys: map[string]provenance.KeyInfo{
			"sign-1": {ID: "sign-1", Public: signPub},
			"att-1":  {ID: "att-1", Public: attPub},
		}},
		log:     l,
		signKey: signPriv,
		attKey:  attPriv,
	}
}

func (f *fixture) artifact(t *testing.T, name, version string, content []byte) *provenance.Artifact {
	t.Helper()
	a := &provenance.Artifact{Name: name, Version: version, Content: content, SignerKeyID: "sign-1"}
	a.Signature = ed25519.Sign(f.signKey, content)
	at := &provenance.Attestation{
		SubjectName:    name,
		SubjectVersion: version,
		SubjectDigest:  provenance.ContentDigest(content),
		Predicate:      "build-v1",
		SignerKeyID:    "att-1",
	}
	// Sign the canonical payload the same way the verifier reconstructs it.
	at.Signature = ed25519.Sign(f.attKey, []byte(at.SubjectName+"\x00"+at.SubjectVersion+"\x00"+at.SubjectDigest+"\x00"+at.Predicate))
	a.Attestation = at
	idx, err := f.log.Append(content)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.log.InclusionProof(idx)
	if err != nil {
		t.Fatal(err)
	}
	a.InclusionProof = &provenance.InclusionProof{
		LogID:         "local",
		LeafIndex:     idx,
		TreeSize:      f.log.Size(),
		RootHash:      f.log.Root(),
		SiblingHashes: proof,
	}
	return a
}

func TestBatchMixedOutcomes(t *testing.T) {
	f := newFixture(t)
	v := provenance.NewVerifier(f.store)
	b := New(v, Options{Concurrency: 8})

	good := f.artifact(t, "good", "1.0.0", []byte("good-content"))
	bad := f.artifact(t, "bad", "1.0.0", []byte("bad-content"))
	bad.Signature[0] ^= 0xff

	s := b.VerifyAll([]*provenance.Artifact{good, bad, nil})
	if len(s.Passed) != 1 || s.Passed[0].Name != "good" {
		t.Fatalf("passed = %+v", s.Passed)
	}
	if len(s.Failed) != 1 || s.Failed[0].Reason != string(provenance.ReasonBadSignature) {
		t.Fatalf("failed = %+v", s.Failed)
	}
	if len(s.Skipped) != 1 || s.Skipped[0].Reason != ReasonMissingArtifact {
		t.Fatalf("skipped = %+v", s.Skipped)
	}
	if s.OK() {
		t.Fatal("summary must not be OK with failures")
	}
}

func TestDriftBlocks(t *testing.T) {
	f := newFixture(t)
	v := provenance.NewVerifier(f.store)
	a := f.artifact(t, "liba", "1.0.0", []byte("real-content"))

	lock := &lockfile.Lock{Entries: []lockfile.Entry{
		{Name: "liba", Version: "1.0.0", Digest: provenance.ContentDigest([]byte("real-content"))},
	}}
	b := New(v, Options{Lock: lock})
	s := b.VerifyAll([]*provenance.Artifact{a})
	if !s.OK() {
		t.Fatalf("matching lock must pass: %+v", s.Failed)
	}

	// Tampered content: digest no longer matches the pin.
	tampered := f.artifact(t, "liba", "1.0.0", []byte("forged-content"))
	s = b.VerifyAll([]*provenance.Artifact{tampered})
	if len(s.Failed) != 1 || s.Failed[0].Reason != ReasonDrift {
		t.Fatalf("drift must block: %+v", s)
	}

	// Unpinned component is skipped with a reason.
	other := f.artifact(t, "other", "1.0.0", []byte("other"))
	s = b.VerifyAll([]*provenance.Artifact{other})
	if len(s.Skipped) != 1 || s.Skipped[0].Reason != ReasonNotInLock {
		t.Fatalf("unpinned must skip with reason: %+v", s)
	}
}

func TestCacheInvalidationOnRotation(t *testing.T) {
	f := newFixture(t)
	v := provenance.NewVerifier(f.store)
	cache := NewCache()
	a := f.artifact(t, "liba", "1.0.0", []byte("content"))
	lock := &lockfile.Lock{Entries: []lockfile.Entry{
		{Name: "liba", Version: "1.0.0", Digest: provenance.ContentDigest(a.Content)},
	}}
	b := New(v, Options{Lock: lock, Cache: cache})

	if s := b.VerifyAll([]*provenance.Artifact{a}); !s.OK() {
		t.Fatalf("first run: %+v", s.Failed)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache entries = %d, want 1", cache.Len())
	}
	if _, ok := cache.LookupDigest("liba@1.0.0"); !ok {
		t.Fatal("digest must be cached")
	}

	// Rotate the signing key: cache entry must be invalidated.
	cache.InvalidateKey("sign-1")
	if _, ok := cache.LookupDigest("liba@1.0.0"); ok {
		t.Fatal("rotation of involved key must invalidate the entry")
	}
	if cache.Len() != 0 {
		t.Fatalf("cache entries after rotation = %d, want 0", cache.Len())
	}

	// Revoking the key in the trust store must make verification fail even
	// with a warm cache.
	k := f.store.Keys["sign-1"]
	k.Revoked = true
	f.store.Keys["sign-1"] = k
	s := b.VerifyAll([]*provenance.Artifact{a})
	if len(s.Failed) != 1 || s.Failed[0].Reason != string(provenance.ReasonRevokedKey) {
		t.Fatalf("revoked key must be rejected: %+v", s)
	}
}

func TestConcurrentVerificationIsolatesFailures(t *testing.T) {
	f := newFixture(t)
	v := provenance.NewVerifier(f.store)
	b := New(v, Options{Concurrency: 16})

	var arts []*provenance.Artifact
	for i := 0; i < 50; i++ {
		name := string(rune('a'+i%26)) + string(rune('a'+i/26))
		a := f.artifact(t, name, "1.0.0", []byte("content-"+name))
		if i%5 == 0 {
			a.Signature[0] ^= 0xff // corrupt every fifth
		}
		arts = append(arts, a)
	}
	s := b.VerifyAll(arts)
	if len(s.Passed)+len(s.Failed)+len(s.Skipped) != 50 {
		t.Fatalf("lost results: %d+%d+%d", len(s.Passed), len(s.Failed), len(s.Skipped))
	}
	if len(s.Failed) != 10 {
		t.Fatalf("failed = %d, want 10", len(s.Failed))
	}
	// Results must be sorted deterministically.
	for i := 1; i < len(s.Passed); i++ {
		if s.Passed[i-1].Name > s.Passed[i].Name {
			t.Fatal("passed results not sorted")
		}
	}
}

func TestTimeoutIsolatesSlowComponent(t *testing.T) {
	f := newFixture(t)
	v := provenance.NewVerifier(f.store)
	b := New(v, Options{Concurrency: 4, PerItemTimeout: 50 * time.Millisecond})

	good := f.artifact(t, "good", "1.0.0", []byte("good"))
	slow := f.artifact(t, "slow", "1.0.0", []byte("slow"))
	// A pathological artifact whose signature check loops forever is not
	// constructible here; instead simulate slowness via a huge batch and a
	// tiny timeout on a verifier whose Now function sleeps.
	slowV := provenance.NewVerifier(f.store)
	slowV.Now = func() time.Time { time.Sleep(200 * time.Millisecond); return time.Now() }
	bSlow := New(slowV, Options{Concurrency: 4, PerItemTimeout: 50 * time.Millisecond})

	start := time.Now()
	s := bSlow.VerifyAll([]*provenance.Artifact{slow})
	if len(s.Failed) != 1 || s.Failed[0].Reason != ReasonTimeout {
		t.Fatalf("slow component must time out: %+v", s)
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Fatal("timeout did not bound the slow component")
	}
	// The fast verifier still passes the good artifact.
	if s := b.VerifyAll([]*provenance.Artifact{good}); !s.OK() {
		t.Fatalf("good artifact must pass: %+v", s.Failed)
	}
}
