// Package provenance 对单个依赖制品做来源校验：
// 签名、真实性证明（attestation）、透明日志包含证明。
// 任一项不通过都返回可区分的 *Failure，绝不静默放行或降级。
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Diudiuseven/sbom-provenance-go/keys"
	"github.com/Diudiuseven/sbom-provenance-go/tlog"
)

// FailureKind 是可区分的失败原因类别。
type FailureKind string

const (
	FailSignature   FailureKind = "signature"   // 签名校验失败
	FailAttestation FailureKind = "attestation" // 真实性证明失败
	FailInclusion   FailureKind = "inclusion"   // 透明日志包含证明失败
	FailDigest      FailureKind = "digest"      // 制品哈希与记录不匹配
)

// Failure 描述一次校验失败，Kind 可区分原因。
type Failure struct {
	Kind   FailureKind
	Detail string
}

func (f *Failure) Error() string { return string(f.Kind) + ": " + f.Detail }

// Materials 是一个制品的全部信任材料（全部本地生成）。
type Materials struct {
	Component      string // name@version
	Artifact       []byte // 制品内容
	ExpectedDigest string // 记录中的 sha256:... 摘要
	Signature      []byte // 对制品摘要的签名
	KeyID          string
	Attestation    *Attestation
	Inclusion      *tlog.InclusionProof
	LogEntry       tlog.Entry
}

// Attestation 是简化的真实性证明：声明某制品摘要由某构建产生。
type Attestation struct {
	SubjectComponent string `json:"subjectComponent"`
	SubjectDigest    string `json:"subjectDigest"`
	BuilderID        string `json:"builderID"`
}

// Verifier 执行来源校验。
type Verifier struct {
	Keys *keys.Store
	Log  *tlog.Log
	// Now 提供当前时间（用于密钥有效期判定）；nil 时用真实时钟。
	Now func() time.Time
}

// DigestOf 计算制品内容的规范摘要。
func DigestOf(artifact []byte) string {
	h := sha256.Sum256(artifact)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Verify 校验一个制品的全部材料。校验顺序固定：摘要 -> 签名 ->
// 真实性证明 -> 包含证明；任一失败立即返回对应 *Failure。
func (v *Verifier) Verify(m *Materials) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	// 1. 制品内容哈希与记录比对。
	actual := DigestOf(m.Artifact)
	if actual != m.ExpectedDigest {
		return &Failure{Kind: FailDigest, Detail: fmt.Sprintf(
			"artifact digest %s != recorded %s", actual, m.ExpectedDigest)}
	}
	// 2. 签名：对制品摘要的签名必须由有效密钥签发。
	if len(m.Signature) == 0 {
		return &Failure{Kind: FailSignature, Detail: "missing signature"}
	}
	if err := v.Keys.Verify(m.KeyID, []byte(m.ExpectedDigest), m.Signature, now); err != nil {
		return &Failure{Kind: FailSignature, Detail: err.Error()}
	}
	// 3. 真实性证明：主题必须与制品一致。
	if m.Attestation == nil {
		return &Failure{Kind: FailAttestation, Detail: "missing attestation"}
	}
	if m.Attestation.SubjectComponent != m.Component {
		return &Failure{Kind: FailAttestation, Detail: fmt.Sprintf(
			"attestation subject %q != component %q", m.Attestation.SubjectComponent, m.Component)}
	}
	if m.Attestation.SubjectDigest != m.ExpectedDigest {
		return &Failure{Kind: FailAttestation, Detail: fmt.Sprintf(
			"attestation digest %s != artifact digest %s", m.Attestation.SubjectDigest, m.ExpectedDigest)}
	}
	// 4. 透明日志包含证明：记录必须与制品一致且证明有效。
	if m.Inclusion == nil {
		return &Failure{Kind: FailInclusion, Detail: "missing inclusion proof"}
	}
	if m.LogEntry.Component != m.Component || m.LogEntry.ArtifactDigest != m.ExpectedDigest {
		return &Failure{Kind: FailInclusion, Detail: fmt.Sprintf(
			"log entry %+v does not match component %s digest %s", m.LogEntry, m.Component, m.ExpectedDigest)}
	}
	if err := tlog.VerifyInclusion(m.LogEntry, m.Inclusion); err != nil {
		return &Failure{Kind: FailInclusion, Detail: err.Error()}
	}
	// 包含证明的根必须与本地日志在证明树大小时的状态一致
	// （日志只追加，证明无需匹配最新根，但必须匹配其声明的历史位置）。
	root, err := v.Log.RootHashAt(m.Inclusion.TreeSize)
	if err != nil {
		return &Failure{Kind: FailInclusion, Detail: err.Error()}
	}
	if m.Inclusion.RootHash != root {
		return &Failure{Kind: FailInclusion, Detail: "proof root does not match local log at claimed tree size"}
	}
	return nil
}

// IsFailure 判定错误是否为 *Failure 并取出。
func IsFailure(err error) (*Failure, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}
