package keys

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestGenerateAndVerify(t *testing.T) {
	s := NewStore()
	now := time.Now()
	priv, err := s.Generate("k1", now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte("msg"))
	if err := s.Verify("k1", []byte("msg"), sig, now); err != nil {
		t.Fatalf("valid signature must pass: %v", err)
	}
	if err := s.Verify("k1", []byte("other"), sig, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("bad message must fail: %v", err)
	}
	if err := s.Verify("ghost", []byte("msg"), sig, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown key must fail: %v", err)
	}
}

func TestExpiryAndNotYetValid(t *testing.T) {
	s := NewStore()
	now := time.Now()
	priv, _ := s.Generate("k1", now.Add(-time.Minute), now.Add(time.Minute))
	sig := ed25519.Sign(priv, []byte("msg"))
	if err := s.Verify("k1", []byte("msg"), sig, now.Add(2*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired key must be rejected: %v", err)
	}
	priv2, _ := s.Generate("k2", now.Add(time.Hour), now.Add(2*time.Hour))
	sig2 := ed25519.Sign(priv2, []byte("msg"))
	if err := s.Verify("k2", []byte("msg"), sig2, now); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("not-yet-valid key must be rejected: %v", err)
	}
}

func TestRevokeAndRotate(t *testing.T) {
	s := NewStore()
	now := time.Now()
	priv, _ := s.Generate("k1", now.Add(-time.Minute), now.Add(time.Hour))
	sig := ed25519.Sign(priv, []byte("msg"))
	if err := s.Revoke("k1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("k1", []byte("msg"), sig, now); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked key must be rejected: %v", err)
	}
	// 轮换：旧钥立即失效，新钥可用。
	privOld, _ := s.Generate("old", now.Add(-time.Minute), now.Add(time.Hour))
	sigOld := ed25519.Sign(privOld, []byte("msg"))
	privNew, err := s.Rotate("old", "new", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("old", []byte("msg"), sigOld, now); !errors.Is(err, ErrRevoked) {
		t.Fatalf("rotated-out key must be rejected: %v", err)
	}
	sigNew := ed25519.Sign(privNew, []byte("msg"))
	if err := s.Verify("new", []byte("msg"), sigNew, now); err != nil {
		t.Fatalf("new key must be accepted: %v", err)
	}
	if _, err := s.Rotate("ghost", "x", now, time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotating unknown key must fail: %v", err)
	}
}
