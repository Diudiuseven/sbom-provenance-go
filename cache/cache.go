// Package cache 提供校验辅助缓存。
//
// 语义约束：
//   - 缓存只保存非密码学的派生数据（如制品摘要），
//     缓存命中不得跳过任何签名或证明校验；
//   - 密钥轮换或吊销后必须调用 InvalidateKeys，
//     旧纪元的全部条目立即失效。
package cache

import "sync"

// Cache 是并发安全的结果缓存。
type Cache struct {
	mu      sync.Mutex
	entries map[string]Entry
	epoch   int // 密钥纪元：轮换/吊销时递增，旧纪元条目全部失效
}

// Entry 是一条缓存记录。
type Entry struct {
	KeyEpoch int
	// 仅缓存非密码学的派生数据（如制品摘要、清单解析结果）。
	// 签名与证明校验在任何情况下都必须重新执行。
	Digest string
}

// New 创建缓存。
func New() *Cache { return &Cache{entries: map[string]Entry{}} }

// Get 查询缓存；纪元不匹配的条目视为未命中并清除。
func (c *Cache) Get(key string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return Entry{}, false
	}
	if e.KeyEpoch != c.epoch {
		delete(c.entries, key)
		return Entry{}, false
	}
	return e, true
}

// Put 以当前纪元写入缓存。
func (c *Cache) Put(key string, e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.KeyEpoch = c.epoch
	c.entries[key] = e
}

// InvalidateKeys 密钥轮换或吊销后调用：递增纪元，使全部旧条目失效。
func (c *Cache) InvalidateKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	c.entries = map[string]Entry{}
}

// Epoch 返回当前密钥纪元（供测试与诊断）。
func (c *Cache) Epoch() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}
