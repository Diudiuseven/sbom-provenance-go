// Package keys 管理签名密钥：本地生成、轮换、吊销与有效期判定。
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// Key 是一把带元数据的验证密钥。
type Key struct {
	ID        string
	Public    ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time // 过期后不得再被接受
	Revoked   bool      // 吊销后不得再被接受
}

// Store 是本地密钥库，支持轮换与吊销。
type Store struct {
	keys map[string]*Key
}

// NewStore 创建空密钥库。
func NewStore() *Store { return &Store{keys: map[string]*Key{}} }

var (
	// ErrNotFound 表示密钥不存在。
	ErrNotFound = errors.New("keys: key not found")
	// ErrRevoked 表示密钥已被吊销。
	ErrRevoked = errors.New("keys: key revoked")
	// ErrExpired 表示密钥已过期。
	ErrExpired = errors.New("keys: key expired")
	// ErrNotYetValid 表示密钥尚未生效。
	ErrNotYetValid = errors.New("keys: key not yet valid")
	// ErrBadSignature 表示签名不匹配。
	ErrBadSignature = errors.New("keys: bad signature")
)

// Generate 生成一把新密钥并入库（本地生成，无外部服务）。
func (s *Store) Generate(id string, notBefore, notAfter time.Time) (ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.keys[id] = &Key{ID: id, Public: pub, NotBefore: notBefore, NotAfter: notAfter}
	return priv, nil
}

// Add 直接加入一把已知公钥（用于测试或导入本地材料）。
func (s *Store) Add(k *Key) { s.keys[k.ID] = k }

// Revoke 吊销指定密钥。
func (s *Store) Revoke(id string) error {
	k, ok := s.keys[id]
	if !ok {
		return ErrNotFound
	}
	k.Revoked = true
	return nil
}

// Rotate 生成新密钥并将旧密钥立即吊销（轮换后旧钥不再被接受）。
func (s *Store) Rotate(oldID, newID string, now time.Time, validity time.Duration) (ed25519.PrivateKey, error) {
	if _, ok := s.keys[oldID]; !ok {
		return nil, ErrNotFound
	}
	priv, err := s.Generate(newID, now, now.Add(validity))
	if err != nil {
		return nil, err
	}
	s.keys[oldID].Revoked = true
	return priv, nil
}

// Get 返回密钥元数据。
func (s *Store) Get(id string) (*Key, error) {
	k, ok := s.keys[id]
	if !ok {
		return nil, ErrNotFound
	}
	return k, nil
}

// Verify 校验签名；密钥缺失、未生效、过期或吊销时返回可区分错误。
func (s *Store) Verify(keyID string, msg, sig []byte, now time.Time) error {
	k, ok := s.keys[keyID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, keyID)
	}
	if k.Revoked {
		return fmt.Errorf("%w: %s", ErrRevoked, keyID)
	}
	if now.Before(k.NotBefore) {
		return fmt.Errorf("%w: %s", ErrNotYetValid, keyID)
	}
	if now.After(k.NotAfter) {
		return fmt.Errorf("%w: %s", ErrExpired, keyID)
	}
	if !ed25519.Verify(k.Public, msg, sig) {
		return fmt.Errorf("%w: key %s", ErrBadSignature, keyID)
	}
	return nil
}
