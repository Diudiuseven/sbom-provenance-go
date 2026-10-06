// Package verify 编排批量并发校验：失败隔离、慢组件不阻塞、结果汇总。
package verify

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/cache"
	"github.com/Diudiuseven/sbom-provenance-go/provenance"
)

// Status 是单个组件的校验状态。
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
)

// Result 是单个组件的校验结果。
type Result struct {
	Component  string
	Status     Status
	Failure    *provenance.Failure // StatusFail 时非空
	SkipReason string              // StatusSkipped 时非空，必须说明具体原因
}

// Summary 是整批结果的可区分汇总。
type Summary struct {
	Passed  []string
	Failed  []Result
	Skipped []Result
}

// Batch 是批量校验器。
type Batch struct {
	Prov  *provenance.Verifier
	Cache *cache.Cache
	// Workers 为并发度；<=0 时取默认值 4。
	Workers int
	// Timeout 为单组件超时；慢组件超时后被跳过（说明原因），不阻塞其余组件。
	Timeout time.Duration
	// BeforeVerify 是测试钩子：在校验前调用，可模拟慢组件。
	BeforeVerify func(component string)
}

// Run 并发校验全部材料并返回汇总。
//
// 隔离语义：单个组件失败不影响其余组件；超时组件记为 skipped 并说明原因；
// 汇总中 pass/fail/skipped 可区分，且输出排序确定（按组件名）。
func (b *Batch) Run(mats []*provenance.Materials) *Summary {
	workers := b.Workers
	if workers <= 0 {
		workers = 4
	}
	timeout := b.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	results := make([]Result, len(mats))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, m := range mats {
		wg.Add(1)
		go func(i int, m *provenance.Materials) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = b.verifyOne(m, timeout)
		}(i, m)
	}
	wg.Wait()

	sum := &Summary{}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			sum.Passed = append(sum.Passed, r.Component)
		case StatusFail:
			sum.Failed = append(sum.Failed, r)
		default:
			sum.Skipped = append(sum.Skipped, r)
		}
	}
	sort.Strings(sum.Passed)
	sort.Slice(sum.Failed, func(i, j int) bool { return sum.Failed[i].Component < sum.Failed[j].Component })
	sort.Slice(sum.Skipped, func(i, j int) bool { return sum.Skipped[i].Component < sum.Skipped[j].Component })
	return sum
}

// verifyOne 校验单个组件，带超时隔离。
func (b *Batch) verifyOne(m *provenance.Materials, timeout time.Duration) Result {
	if m == nil {
		return Result{Status: StatusSkipped, SkipReason: "nil materials"}
	}
	r := Result{Component: m.Component}
	// 材料不完整：跳过并说明具体原因，而不是误判为失败。
	if m.Artifact == nil {
		r.Status = StatusSkipped
		r.SkipReason = "artifact content not available locally"
		return r
	}
	if m.Attestation == nil || m.Inclusion == nil {
		r.Status = StatusSkipped
		r.SkipReason = "trust materials incomplete (attestation or inclusion proof missing)"
		return r
	}

	// 缓存仅用于派生的制品摘要；签名与证明校验每次都执行。
	if b.Cache != nil {
		key := m.Component
		if e, ok := b.Cache.Get(key); !ok || e.Digest != m.ExpectedDigest {
			b.Cache.Put(key, cache.Entry{Digest: m.ExpectedDigest})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		if b.BeforeVerify != nil {
			b.BeforeVerify(m.Component)
		}
		done <- b.Prov.Verify(m)
	}()
	select {
	case err := <-done:
		if err == nil {
			r.Status = StatusPass
			return r
		}
		if f, ok := provenance.IsFailure(err); ok {
			r.Status = StatusFail
			r.Failure = f
			return r
		}
		r.Status = StatusFail
		r.Failure = &provenance.Failure{Kind: "internal", Detail: err.Error()}
		return r
	case <-ctx.Done():
		r.Status = StatusSkipped
		r.SkipReason = "verification timed out after " + timeout.String()
		return r
	}
}
