package sbom

import "fmt"

// Convert 在规范版本之间转换文档，并报告语义损失。
//
// 1.0 -> 1.1：升级，无损失（新增字段以默认值补齐）。
// 1.1 -> 1.0：降级，DependsOn 与 SourcePath 被丢弃，逐组件报告损失。
func Convert(d *Document, target SpecVersion) (*ConversionResult, error) {
	if target != Spec10 && target != Spec11 {
		return nil, fmt.Errorf("sbom: unsupported target spec %q", target)
	}
	res := &ConversionResult{}
	out := &Document{
		Spec:       target,
		Tool:       d.Tool,
		Components: make([]Component, 0, len(d.Components)),
	}
	for _, c := range sortedComponents(d.Components) {
		nc := Component{Name: c.Name, Version: c.Version, Digest: c.Digest}
		if target == Spec11 {
			nc.DependsOn = append([]string(nil), c.DependsOn...)
			nc.SourcePath = c.SourcePath
		} else {
			if len(c.DependsOn) > 0 {
				res.Losses = append(res.Losses, LossNote{
					Field:  fmt.Sprintf("components[%s@%s].dependsOn", c.Name, c.Version),
					Reason: "spec 1.0 不表达依赖关系，依赖边被丢弃",
				})
			}
			if c.SourcePath != "" {
				res.Losses = append(res.Losses, LossNote{
					Field:  fmt.Sprintf("components[%s@%s].sourcePath", c.Name, c.Version),
					Reason: "spec 1.0 不表达来源路径，来源信息被丢弃",
				})
			}
		}
		out.Components = append(out.Components, nc)
	}
	out.Serial = serialOf(out)
	res.Document = out
	return res, nil
}
