// Package depgraph 解析依赖清单并构建确定性的依赖图。
package depgraph

// Version 是一个简化的语义化版本。
type Version struct {
	Major, Minor, Patch int
}

// Constraint 描述对某组件的版本约束。
type Constraint struct {
	Min    Version  `json:"min"` // 含
	Max    Version  `json:"max"` // 不含；HasMax 为 false 时忽略
	HasMax bool     `json:"hasMax,omitempty"`
	Exact  *Version `json:"exact,omitempty"` // 精确版本，非空时优先
}

// Dependency 是清单中一条依赖边。
type Dependency struct {
	Name       string     `json:"name"`
	Constraint Constraint `json:"constraint"`
	Optional   bool       `json:"optional,omitempty"`  // 可选依赖，默认不纳入
	Platforms  []string   `json:"platforms,omitempty"` // 平台条件，空表示所有平台；任一匹配即生效
}

// Component 是清单中声明的一个可用组件版本。
type Component struct {
	Name    string       `json:"name"`
	Version Version      `json:"version"`
	Deps    []Dependency `json:"deps,omitempty"`
}

// Manifest 是输入的依赖清单。
type Manifest struct {
	Roots      []Dependency `json:"roots"`      // 顶层依赖
	Components []Component  `json:"components"` // 全部可用组件版本（本地“仓库”）
}

// Node 是解析后依赖图中的一个节点（name@version 唯一）。
type Node struct {
	Name    string
	Version Version
	Deps    []Edge
}

// Edge 是解析后的一条依赖边，含来源信息。
type Edge struct {
	To       NodeID
	Optional bool
	Via      NodeID // 引入该依赖的节点
}

// NodeID 唯一标识一个解析节点。
type NodeID struct {
	Name    string
	Version Version
}

// Graph 是解析结果。
type Graph struct {
	Nodes  []Node   // 确定性排序
	Roots  []NodeID // 确定性排序
	Cycles [][]NodeID
}
