// Package provenance verifies artifact provenance: signatures, attestations
// and transparency-log inclusion proofs. All trust material is local; no
// external service is contacted.
package provenance

import "crypto/ed25519"

// Artifact is a fetched dependency artifact with its trust material.
type Artifact struct {
	Name    string
	Version string
	// Content is the raw artifact bytes.
	Content []byte
	// Signature over Content by an authorized key.
	Signature []byte
	// SignerKeyID identifies the signing key.
	SignerKeyID string
	// Attestation is a signed authenticity statement (in-toto-like).
	Attestation *Attestation
	// InclusionProof places the artifact digest in the transparency log.
	InclusionProof *InclusionProof
}

// Attestation is an authenticity proof binding a subject digest to a
// predicate, signed by a trusted key.
type Attestation struct {
	SubjectName    string
	SubjectVersion string
	// SubjectDigest is "sha256:<hex>" of the artifact content.
	SubjectDigest string
	Predicate     string
	Signature     []byte
	SignerKeyID   string
}

// InclusionProof is a Merkle inclusion proof for a transparency log entry.
type InclusionProof struct {
	LogID     string
	LeafIndex uint64
	TreeSize  uint64
	// RootHash is the signed tree head the proof verifies against.
	RootHash  []byte
	// SiblingHashes is the Merkle audit path.
	SiblingHashes [][]byte
}

// FailureReason distinguishes verification failure causes.
type FailureReason string

const (
	ReasonOK                  FailureReason = ""
	ReasonMissingSignature    FailureReason = "missing_signature"
	ReasonBadSignature        FailureReason = "bad_signature"
	ReasonUnknownSigner       FailureReason = "unknown_signer"
	ReasonRevokedKey          FailureReason = "revoked_key"
	ReasonExpiredKey          FailureReason = "expired_key"
	ReasonMissingAttestation  FailureReason = "missing_attestation"
	ReasonBadAttestation      FailureReason = "bad_attestation"
	ReasonAttestationMismatch FailureReason = "attestation_subject_mismatch"
	ReasonMissingInclusion    FailureReason = "missing_inclusion_proof"
	ReasonBadInclusion        FailureReason = "bad_inclusion_proof"
)

// Error is a verification failure with a distinguishable reason.
type Error struct {
	Reason FailureReason
	Detail string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Detail }

// KeyInfo describes a trusted public key and its lifecycle.
type KeyInfo struct {
	ID        string
	Public    ed25519.PublicKey
	NotBefore int64
	NotAfter  int64
	Revoked   bool
}

// TrustStore is the local set of trusted keys.
type TrustStore struct {
	Keys map[string]KeyInfo
}
