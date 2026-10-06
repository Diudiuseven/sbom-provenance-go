package verify

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/cache"
	"github.com/Diudiuseven/sbom-provenance-go/keys"
	"github.com/Diudiuseven/sbom-provenance-go/provenance"
	"github.com/Diudiuseven/sbom-provenance-go/tlog"
)

type fixture struct {
	batch *Batch
	ks    *keys.Store
	priv  ed25519.PrivateKey
	log   *tlog.Log
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ks := keys.NewStore()
	now := time.Now()
	priv, _ := ks.Generate("k1", now.Add(-time.Hour), now.Add(time.Hour))
	lg, _ := tlog.Open("")
	v := &provenance.Verifier{Keys: ks, Log: lg, Now: func() time.Time { return now }}
	return &fixture{
		batch: &Batch{Prov: v, Cache: cache.New(), Workers: 8, Timeout: 300 * time.Millisecond},
		ks:    ks, priv: priv, log: lg, now: now,
	}
}

func (f *fixture) materials(t *testing.T, name string, artifact []byte) *provenance.Materials {
	t.Helper()
	digest := provenance.DigestOf(artifact)
	idx, _ := f.log.Append(tlog.Entry{ArtifactDigest: digest, Component: name})
	proof, _ := f.log.ProveInclusion(idx)
	return &provenance.Materials{
		Component:      name,
		Artifact:       artifact,
		ExpectedDigest: digest,
		Signature:      ed25519.Sign(f.priv, []byte(digest)),
		KeyID:          "k1",
		Attestation:    &provenance.Attestation{SubjectComponent: name, SubjectDigest: digest, BuilderID: "b"},
		Inclusion:      proof,
		LogEntry:       tlog.Entry{ArtifactDigest: digest, Component: name},
	}
}

func TestBatchConcurrentMixed(t *testing.T) {
	f := newFixture(t)
	var mats []*provenance.Materials
	// 5 个正常。
	for i := 0; i < 5; i++ {
		mats = append(mats, f.materials(t, fmt.Sprintf("ok-%d@1.0.0", i), []byte(fmt.Sprintf("a%d", i))))
	}
	// 1 个签名失败。
	bad := f.materials(t, "bad-sig@1.0.0", []byte("x"))
	bad.Signature[0] ^= 0xff
	mats = append(mats, bad)
	// 1 个材料不完整 -> 跳过并说明原因。
	incomplete := f.materials(t, "incomplete@1.0.0", []byte("y"))
	incomplete.Inclusion = nil
	mats = append(mats, incomplete)
	// 1 个慢组件 -> 超时跳过，不得阻塞其余。
	slow := f.materials(t, "slow@1.0.0", []byte("z"))
	mats = append(mats, slow)
	f.batch.BeforeVerify = func(c string) {
		if c == "slow@1.0.0" {
			time.Sleep(2 * time.Second)
		}
	}

	start := time.Now()
	sum := f.batch.Run(mats)
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("slow component blocked the batch: %v", elapsed)
	}
	if len(sum.Passed) != 5 {
		t.Fatalf("passed = %v", sum.Passed)
	}
	if len(sum.Failed) != 1 || sum.Failed[0].Component != "bad-sig@1.0.0" {
		t.Fatalf("failed = %+v", sum.Failed)
	}
	if sum.Failed[0].Failure.Kind != provenance.FailSignature {
		t.Fatalf("failure kind = %s", sum.Failed[0].Failure.Kind)
	}
	if len(sum.Skipped) != 2 {
		t.Fatalf("skipped = %+v", sum.Skipped)
	}
	reasons := map[string]string{}
	for _, s := range sum.Skipped {
		if s.SkipReason == "" {
			t.Fatalf("skipped component %s must carry a reason", s.Component)
		}
		reasons[s.Component] = s.SkipReason
	}
	if _, ok := reasons["incomplete@1.0.0"]; !ok {
		t.Fatalf("incomplete component not skipped: %+v", sum.Skipped)
	}
	if _, ok := reasons["slow@1.0.0"]; !ok {
		t.Fatalf("slow component not skipped: %+v", sum.Skipped)
	}
}

func TestKeyRotationInvalidatesCacheAndRejects(t *testing.T) {
	f := newFixture(t)
	m := f.materials(t, "a@1.0.0", []byte("a"))
	if sum := f.batch.Run([]*provenance.Materials{m}); len(sum.Passed) != 1 {
		t.Fatalf("initial run should pass: %+v", sum)
	}
	if _, ok := f.batch.Cache.Get("a@1.0.0"); !ok {
		t.Fatal("cache should hold derived digest after run")
	}
	// 密钥轮换：旧钥吊销，缓存必须失效，旧签名不再被接受。
	if _, err := f.ks.Rotate("k1", "k2", f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.batch.Cache.InvalidateKeys()
	if _, ok := f.batch.Cache.Get("a@1.0.0"); ok {
		t.Fatal("cache entry must be invalidated after key rotation")
	}
	sum := f.batch.Run([]*provenance.Materials{m})
	if len(sum.Failed) != 1 || sum.Failed[0].Failure.Kind != provenance.FailSignature {
		t.Fatalf("rotated key must reject old signature: %+v", sum)
	}
}
