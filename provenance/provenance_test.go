package provenance

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/keys"
	"github.com/Diudiuseven/sbom-provenance-go/tlog"
)

type fixture struct {
	v    *Verifier
	log  *tlog.Log
	priv ed25519.PrivateKey
	ks   *keys.Store
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ks := keys.NewStore()
	now := time.Now()
	priv, err := ks.Generate("k1", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	lg, _ := tlog.Open("")
	return &fixture{v: &Verifier{Keys: ks, Log: lg, Now: func() time.Time { return now }}, log: lg, priv: priv, ks: ks, now: now}
}

// goodMaterials 构造一套完整合法的信任材料。
func (f *fixture) goodMaterials(t *testing.T, component string, artifact []byte) *Materials {
	t.Helper()
	digest := DigestOf(artifact)
	sig := ed25519.Sign(f.priv, []byte(digest))
	idx, err := f.log.Append(tlog.Entry{ArtifactDigest: digest, Component: component})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.log.ProveInclusion(idx)
	if err != nil {
		t.Fatal(err)
	}
	return &Materials{
		Component:      component,
		Artifact:       artifact,
		ExpectedDigest: digest,
		Signature:      sig,
		KeyID:          "k1",
		Attestation:    &Attestation{SubjectComponent: component, SubjectDigest: digest, BuilderID: "local-builder"},
		Inclusion:      proof,
		LogEntry:       tlog.Entry{ArtifactDigest: digest, Component: component},
	}
}

func TestVerifyPass(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	if err := f.v.Verify(m); err != nil {
		t.Fatalf("good materials must pass: %v", err)
	}
}

func mustFailKind(t *testing.T, err error, kind FailureKind) {
	t.Helper()
	f, ok := IsFailure(err)
	if !ok {
		t.Fatalf("expected *Failure, got %v", err)
	}
	if f.Kind != kind {
		t.Fatalf("kind = %s, want %s (err=%v)", f.Kind, kind, err)
	}
}

func TestDigestFailure(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	m.Artifact = []byte("tampered")
	mustFailKind(t, f.v.Verify(m), FailDigest)
}

func TestSignatureFailure(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	m.Signature[0] ^= 0xff
	mustFailKind(t, f.v.Verify(m), FailSignature)
}

func TestSignatureRevokedKey(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	if err := f.ks.Revoke("k1"); err != nil {
		t.Fatal(err)
	}
	mustFailKind(t, f.v.Verify(m), FailSignature)
}

func TestSignatureExpiredKey(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	f.v.Now = func() time.Time { return f.now.Add(2 * time.Hour) }
	mustFailKind(t, f.v.Verify(m), FailSignature)
}

func TestAttestationFailure(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	m.Attestation.SubjectDigest = "sha256:deadbeef"
	mustFailKind(t, f.v.Verify(m), FailAttestation)
}

func TestInclusionFailure(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	// 篡改包含证明（伪造根哈希）必须失败。
	m.Inclusion.RootHash = "00" + m.Inclusion.RootHash[2:]
	mustFailKind(t, f.v.Verify(m), FailInclusion)
}

func TestInclusionStaleProofStillValid(t *testing.T) {
	f := newFixture(t)
	m := f.goodMaterials(t, "a@1.0.0", []byte("artifact-a"))
	// 日志继续增长后，旧树大小的证明仍应有效（只追加语义）。
	f.log.Append(tlog.Entry{ArtifactDigest: "sha256:abc", Component: "b@1.0.0"})
	if err := f.v.Verify(m); err != nil {
		t.Fatalf("stale-but-valid proof must pass: %v", err)
	}
}
