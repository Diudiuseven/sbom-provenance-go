package provenance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/tlog"
)

// Verifier checks artifact provenance against a local trust store.
type Verifier struct {
	Store *TrustStore
	// Now supplies the current time for key validity checks.
	Now func() time.Time
}

// NewVerifier builds a Verifier with the given trust store.
func NewVerifier(store *TrustStore) *Verifier {
	return &Verifier{Store: store, Now: time.Now}
}

// Verify runs all provenance checks for one artifact: signature,
// attestation and transparency-log inclusion. Any failing check returns a
// distinguishable *Error; nothing is silently skipped or downgraded.
func (v *Verifier) Verify(a *Artifact) error {
	if err := v.VerifySignature(a); err != nil {
		return err
	}
	if err := v.VerifyAttestation(a); err != nil {
		return err
	}
	return v.VerifyInclusion(a)
}

// checkKey resolves a key ID and enforces lifecycle constraints.
func (v *Verifier) checkKey(keyID string) (KeyInfo, error) {
	k, ok := v.Store.Keys[keyID]
	if !ok {
		return KeyInfo{}, &Error{Reason: ReasonUnknownSigner, Detail: fmt.Sprintf("key %q not in trust store", keyID)}
	}
	if k.Revoked {
		return KeyInfo{}, &Error{Reason: ReasonRevokedKey, Detail: fmt.Sprintf("key %q is revoked", keyID)}
	}
	now := v.Now().Unix()
	if k.NotBefore != 0 && now < k.NotBefore {
		return KeyInfo{}, &Error{Reason: ReasonExpiredKey, Detail: fmt.Sprintf("key %q not valid before %d (now %d)", keyID, k.NotBefore, now)}
	}
	if k.NotAfter != 0 && now > k.NotAfter {
		return KeyInfo{}, &Error{Reason: ReasonExpiredKey, Detail: fmt.Sprintf("key %q expired at %d (now %d)", keyID, k.NotAfter, now)}
	}
	return k, nil
}

// ContentDigest returns the canonical "sha256:<hex>" digest of content.
func ContentDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifySignature checks only the artifact signature.
func (v *Verifier) VerifySignature(a *Artifact) error {
	if len(a.Signature) == 0 {
		return &Error{Reason: ReasonMissingSignature, Detail: fmt.Sprintf("%s@%s has no signature", a.Name, a.Version)}
	}
	k, err := v.checkKey(a.SignerKeyID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(k.Public, a.Content, a.Signature) {
		return &Error{Reason: ReasonBadSignature, Detail: fmt.Sprintf("%s@%s signature does not verify with key %q", a.Name, a.Version, a.SignerKeyID)}
	}
	return nil
}

// attestationPayload is the canonical signed bytes of an attestation.
func attestationPayload(at *Attestation) []byte {
	return []byte(at.SubjectName + "\x00" + at.SubjectVersion + "\x00" + at.SubjectDigest + "\x00" + at.Predicate)
}

// VerifyAttestation checks only the authenticity attestation.
func (v *Verifier) VerifyAttestation(a *Artifact) error {
	at := a.Attestation
	if at == nil {
		return &Error{Reason: ReasonMissingAttestation, Detail: fmt.Sprintf("%s@%s has no attestation", a.Name, a.Version)}
	}
	want := ContentDigest(a.Content)
	if at.SubjectName != a.Name || at.SubjectVersion != a.Version || at.SubjectDigest != want {
		return &Error{Reason: ReasonAttestationMismatch, Detail: fmt.Sprintf("attestation subject (%s@%s %s) does not match artifact (%s@%s %s)", at.SubjectName, at.SubjectVersion, at.SubjectDigest, a.Name, a.Version, want)}
	}
	k, err := v.checkKey(at.SignerKeyID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(k.Public, attestationPayload(at), at.Signature) {
		return &Error{Reason: ReasonBadAttestation, Detail: fmt.Sprintf("%s@%s attestation signature invalid", a.Name, a.Version)}
	}
	return nil
}

// VerifyInclusion checks only the transparency-log inclusion proof. The
// artifact content digest must be committed as a log leaf whose Merkle
// audit path recomputes to the recorded signed tree head.
func (v *Verifier) VerifyInclusion(a *Artifact) error {
	p := a.InclusionProof
	if p == nil {
		return &Error{Reason: ReasonMissingInclusion, Detail: fmt.Sprintf("%s@%s has no inclusion proof", a.Name, a.Version)}
	}
	if p.LeafIndex >= p.TreeSize {
		return &Error{Reason: ReasonBadInclusion, Detail: fmt.Sprintf("leaf index %d out of range for tree size %d", p.LeafIndex, p.TreeSize)}
	}
	if !tlog.VerifyInclusion(a.Content, p.LeafIndex, p.TreeSize, p.SiblingHashes, p.RootHash) {
		return &Error{Reason: ReasonBadInclusion, Detail: fmt.Sprintf("%s@%s audit path does not recompute to the logged root", a.Name, a.Version)}
	}
	return nil
}
