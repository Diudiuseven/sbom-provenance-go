package verify

import "sync"

// Cache memoizes derived, non-cryptographic results of verification
// (currently the artifact content digest). A cache hit never skips
// signature, attestation or inclusion-proof verification: those checks
// always run. Entries record the epoch of every key involved in the
// verification, so key rotation or revocation invalidates exactly the
// affected entries.
type Cache struct {
	mu       sync.RWMutex
	entries  map[string]cacheEntry
	keyEpoch map[string]uint64
}

type cacheEntry struct {
	digest string
	// keyEpochs snapshots the epoch of every key involved when the entry
	// was stored. A mismatch on any key invalidates the entry.
	keyEpochs map[string]uint64
}

// NewCache builds an empty cache.
func NewCache() *Cache {
	return &Cache{entries: map[string]cacheEntry{}, keyEpoch: map[string]uint64{}}
}

// InvalidateKey bumps the epoch of keyID. Every entry that involved keyID
// is invalidated; unaffected entries survive.
func (c *Cache) InvalidateKey(keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyEpoch[keyID]++
	for k, e := range c.entries {
		if _, involved := e.keyEpochs[keyID]; involved {
			if e.keyEpochs[keyID] != c.keyEpoch[keyID] {
				delete(c.entries, k)
			}
		}
	}
}

// LookupDigest returns the cached content digest for id if present and
// still valid under the current key epochs.
func (c *Cache) LookupDigest(id string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[id]
	if !ok {
		return "", false
	}
	for keyID, epoch := range e.keyEpochs {
		if c.keyEpoch[keyID] != epoch {
			return "", false
		}
	}
	return e.digest, true
}

// StoreDigest records the content digest for id along with the key IDs
// involved in verifying the corresponding artifact.
func (c *Cache) StoreDigest(id, digest string, keyIDs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	epochs := map[string]uint64{}
	for _, k := range keyIDs {
		epochs[k] = c.keyEpoch[k]
	}
	c.entries[id] = cacheEntry{digest: digest, keyEpochs: epochs}
}

// Len reports the number of live entries (for tests and metrics).
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
