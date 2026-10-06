// Package verify orchestrates concurrent per-artifact provenance
// verification with caching, key-rotation-aware invalidation, failure
// isolation and batch summaries.
package verify

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/lockfile"
	"github.com/Diudiuseven/sbom-provenance-go/provenance"
)

// Status is the per-component outcome.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
)

// Skip and fail reasons reported by the batch layer itself (provenance
// failures reuse provenance.FailureReason values).
const (
	ReasonMissingArtifact = "missing_artifact"
	ReasonTimeout         = "timeout"
	ReasonPanic           = "panic"
	ReasonDrift           = "drift_detected"
	ReasonNotInLock       = "not_in_lock"
)

// Result is one component's outcome.
type Result struct {
	Name    string
	Version string
	Status  Status
	// Reason is set for failures (provenance.FailureReason or the batch
	// reasons above) and always for skips.
	Reason string
	Detail string
}

// Summary aggregates a batch run.
type Summary struct {
	Passed  []Result
	Failed  []Result
	Skipped []Result
}

// OK reports whether nothing failed.
func (s *Summary) OK() bool { return len(s.Failed) == 0 }

// Options tunes the batch verifier.
type Options struct {
	// Concurrency limits parallel verifications (<=0 means 4).
	Concurrency int
	// PerItemTimeout isolates slow components; <=0 disables the timeout.
	PerItemTimeout time.Duration
	// Lock, when non-nil, blocks artifacts whose content digest does not
	// match the pinned record before any provenance check runs.
	Lock *lockfile.Lock
	// Cache, when non-nil, memoizes content digests. Signature and proof
	// verification always run regardless of cache hits.
	Cache *Cache
}

// BatchVerifier verifies artifacts concurrently with caching.
type BatchVerifier struct {
	v    *provenance.Verifier
	opts Options
}

// New builds a BatchVerifier.
func New(v *provenance.Verifier, opts Options) *BatchVerifier {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	return &BatchVerifier{v: v, opts: opts}
}

// VerifyAll verifies every artifact; slow or failing items do not block
// others. Results are sorted by (name, version) for determinism.
func (b *BatchVerifier) VerifyAll(arts []*provenance.Artifact) *Summary {
	results := make([]Result, len(arts))
	sem := make(chan struct{}, b.opts.Concurrency)
	var wg sync.WaitGroup
	for i, a := range arts {
		wg.Add(1)
		go func(i int, a *provenance.Artifact) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = b.verifyOne(a)
		}(i, a)
	}
	wg.Wait()

	s := &Summary{}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Passed = append(s.Passed, r)
		case StatusFail:
			s.Failed = append(s.Failed, r)
		default:
			s.Skipped = append(s.Skipped, r)
		}
	}
	less := func(rs []Result) {
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].Name != rs[j].Name {
				return rs[i].Name < rs[j].Name
			}
			return rs[i].Version < rs[j].Version
		})
	}
	less(s.Passed)
	less(s.Failed)
	less(s.Skipped)
	return s
}

// verifyOne isolates a single artifact: nil input is skipped with a
// reason, panics are recovered into failures, and a configured timeout
// bounds the work.
func (b *BatchVerifier) verifyOne(a *provenance.Artifact) (res Result) {
	if a == nil {
		return Result{Status: StatusSkipped, Reason: ReasonMissingArtifact, Detail: "nil artifact in batch"}
	}
	res.Name, res.Version = a.Name, a.Version
	defer func() {
		if r := recover(); r != nil {
			res.Status = StatusFail
			res.Reason = ReasonPanic
			res.Detail = fmt.Sprintf("verification panicked: %v", r)
		}
	}()

	if b.opts.PerItemTimeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), b.opts.PerItemTimeout)
		defer cancel()
		done := make(chan Result, 1)
		go func() {
			done <- b.check(a)
		}()
		select {
		case r := <-done:
			return r
		case <-ctx.Done():
			res.Status = StatusFail
			res.Reason = ReasonTimeout
			res.Detail = fmt.Sprintf("verification exceeded %s", b.opts.PerItemTimeout)
			return res
		}
	}
	return b.check(a)
}

// check runs drift gating then full provenance verification.
func (b *BatchVerifier) check(a *provenance.Artifact) Result {
	res := Result{Name: a.Name, Version: a.Version}
	id := a.Name + "@" + a.Version

	// Drift gate: the artifact must be pinned and its content digest must
	// match the lock record.
	if b.opts.Lock != nil {
		var pinned *lockfile.Entry
		for i := range b.opts.Lock.Entries {
			e := &b.opts.Lock.Entries[i]
			if e.Name == a.Name && e.Version == a.Version {
				pinned = e
				break
			}
		}
		if pinned == nil {
			res.Status = StatusSkipped
			res.Reason = ReasonNotInLock
			res.Detail = id + " is not recorded in the lockfile"
			return res
		}
		digest := b.digestOf(id, a)
		if pinned.Digest != digest {
			res.Status = StatusFail
			res.Reason = ReasonDrift
			res.Detail = fmt.Sprintf("content digest %s does not match pinned %s", digest, pinned.Digest)
			return res
		}
	}

	if err := b.v.Verify(a); err != nil {
		res.Status = StatusFail
		if pe, ok := err.(*provenance.Error); ok {
			res.Reason = string(pe.Reason)
			res.Detail = pe.Detail
		} else {
			res.Reason = "error"
			res.Detail = err.Error()
		}
		return res
	}
	res.Status = StatusPass
	return res
}

// digestOf returns the artifact content digest, consulting the cache for
// the (non-cryptographic) hashing step only.
func (b *BatchVerifier) digestOf(id string, a *provenance.Artifact) string {
	if b.opts.Cache != nil {
		if d, ok := b.opts.Cache.LookupDigest(id); ok {
			return d
		}
	}
	d := provenance.ContentDigest(a.Content)
	if b.opts.Cache != nil {
		keyIDs := []string{a.SignerKeyID}
		if a.Attestation != nil {
			keyIDs = append(keyIDs, a.Attestation.SignerKeyID)
		}
		b.opts.Cache.StoreDigest(id, d, keyIDs)
	}
	return d
}
