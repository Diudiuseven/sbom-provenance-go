package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/tlog"
)

type fixture struct {
	store   *TrustStore
	log     *tlog.Log
	signKey ed25519.PrivateKey
	attKey  ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	attPub, attPriv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{
		store: &TrustStore{Keys: map[string]KeyInfo{
			"sign-1": {ID: "sign-1", Public: signPub},
			"att-1":  {ID: "att-1", Public: attPub},
		}},
		signKey: signPriv,
		attKey:  attPriv,
	}
	l, err := tlog.Open(filepath.Join(t.TempDir(), "log.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.log = l
	return f
}

// goodArtifact builds a fully valid artifact.
func (f *fixture) goodArtifact(t *testing.T, name, version string, content []byte) *Artifact {
	t.Helper()
	a := &Artifact{
		Name:        name,
		Version:     version,
		Content:     content,
		SignerKeyID: "sign-1",
	}
	a.Signature = ed25519.Sign(f.signKey, content)
	at := &Attestation{
		SubjectName:    name,
		SubjectVersion: version,
		SubjectDigest:  ContentDigest(content),
		Predicate:      "build-v1",
		SignerKeyID:    "att-1",
	}
	at.Signature = ed25519.Sign(f.attKey, attestationPayload(at))
	a.Attestation = at
	idx, err := f.log.Append(content)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.log.InclusionProof(idx)
	if err != nil {
		t.Fatal(err)
	}
	a.InclusionProof = &InclusionProof{
		LogID:         "local",
		LeafIndex:     idx,
		TreeSize:      f.log.Size(),
		RootHash:      f.log.Root(),
		SiblingHashes: proof,
	}
	return a
}

func reasonOf(err error) FailureReason {
	t := err
	if pe, ok := t.(*Error); ok {
		return pe.Reason
	}
	return "not-a-provenance-error"
}

func TestGoodArtifactPasses(t *testing.T) {
	f := newFixture(t)
	v := NewVerifier(f.store)
	a := f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	if err := v.Verify(a); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
}

func TestSignatureFailures(t *testing.T) {
	f := newFixture(t)
	v := NewVerifier(f.store)

	a := f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	a.Signature = nil
	if err := v.Verify(a); reasonOf(err) != ReasonMissingSignature {
		t.Fatalf("got %v, want missing_signature", err)
	}

	a = f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	a.Signature = append([]byte(nil), a.Signature...)
	a.Signature[0] ^= 0xff
	if err := v.Verify(a); reasonOf(err) != ReasonBadSignature {
		t.Fatalf("got %v, want bad_signature", err)
	}

	a = f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	a.SignerKeyID = "ghost"
	if err := v.Verify(a); reasonOf(err) != ReasonUnknownSigner {
		t.Fatalf("got %v, want unknown_signer", err)
	}
}

func TestKeyLifecycle(t *testing.T) {
	f := newFixture(t)
	a := f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))

	// Revoked key must be rejected.
	k := f.store.Keys["sign-1"]
	k.Revoked = true
	f.store.Keys["sign-1"] = k
	v := NewVerifier(f.store)
	if err := v.Verify(a); reasonOf(err) != ReasonRevokedKey {
		t.Fatalf("got %v, want revoked_key", err)
	}

	// Expired key must be rejected.
	k.Revoked = false
	k.NotAfter = 1000
	f.store.Keys["sign-1"] = k
	v.Now = func() time.Time { return time.Unix(2000, 0) }
	if err := v.Verify(a); reasonOf(err) != ReasonExpiredKey {
		t.Fatalf("got %v, want expired_key", err)
	}

	// Before expiry the same artifact verifies.
	v.Now = func() time.Time { return time.Unix(500, 0) }
	if err := v.Verify(a); err != nil {
		t.Fatalf("valid window rejected: %v", err)
	}
}

func TestAttestationFailures(t *testing.T) {
	f := newFixture(t)
	v := NewVerifier(f.store)

	a := f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	a.Attestation = nil
	if err := v.Verify(a); reasonOf(err) != ReasonMissingAttestation {
		t.Fatalf("got %v, want missing_attestation", err)
	}

	a = f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	a.Attestation.SubjectDigest = "sha256:deadbeef"
	if err := v.Verify(a); reasonOf(err) != ReasonAttestationMismatch {
		t.Fatalf("got %v, want attestation_subject_mismatch", err)
	}

	a = f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	a.Attestation.Signature = append([]byte(nil), a.Attestation.Signature...)
	a.Attestation.Signature[0] ^= 0xff
	if err := v.Verify(a); reasonOf(err) != ReasonBadAttestation {
		t.Fatalf("got %v, want bad_attestation", err)
	}
}

func TestInclusionFailures(t *testing.T) {
	f := newFixture(t)
	v := NewVerifier(f.store)

	a := f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	a.InclusionProof = nil
	if err := v.Verify(a); reasonOf(err) != ReasonMissingInclusion {
		t.Fatalf("got %v, want missing_inclusion_proof", err)
	}

	// Proof from a different artifact must not verify.
	a = f.goodArtifact(t, "liba", "1.0.0", []byte("payload-a"))
	b := f.goodArtifact(t, "libb", "2.0.0", []byte("payload-b"))
	a.InclusionProof = b.InclusionProof
	if err := v.Verify(a); reasonOf(err) != ReasonBadInclusion {
		t.Fatalf("got %v, want bad_inclusion_proof", err)
	}
}
