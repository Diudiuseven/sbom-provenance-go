package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// provenance_DigestOf 由组件坐标派生确定性摘要（演示用）。
func provenance_DigestOf(name, version string) string {
	h := sha256.Sum256([]byte(name + "@" + version))
	return "sha256:" + hex.EncodeToString(h[:])
}
