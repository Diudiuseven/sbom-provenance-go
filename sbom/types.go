// Package sbom 生成可复现的物料清单，并支持规范版本间转换。
package sbom

// SpecVersion 表示 SBOM 规范版本。
type SpecVersion string

const (
	// Spec10 为内部规范 1.0：仅含组件名、版本、哈希。
	Spec10 SpecVersion = "1.0"
	// Spec11 为内部规范 1.1：增加依赖关系与来源信息。
	Spec11 SpecVersion = "1.1"
)

// Component 是 SBOM 中的一个组件条目。。即一条物料。
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"` // sha256:...
	// 以下字段仅 Spec11 输出。
	DependsOn  []string `json:"dependsOn,omitempty"` // "name@version"
	SourcePath string   `json:"sourcePath,omitempty"`
}

// Document 是一份物料清单。
type Document struct {
	Spec       SpecVersion `json:"spec"`
	Tool       string      `json:"tool"`
	Serial     string      `json:"serial"` // 由内容派生，保证可复现
	Components []Component `json:"components"`
}

// LossNote 描述一次规范的转换损失。
type LossNote struct {
	Field  string
	Reason string
}

// ConversionResult 是转换输出。
type ConversionResult struct {
	Document *Document
	Losses   []LossNote
}
