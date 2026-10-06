// sbomprov 是命令行入口：解析依赖清单、生成可复现 SBOM、
// 规范转换、依赖固定与漂移检测、来源校验与透明日志增量校验。
// 全部材料本地生成，不访问任何外部服务。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Diudiuseven/sbom-provenance-go/depgraph"
	"github.com/Diudiuseven/sbom-provenance-go/lockfile"
	"github.com/Diudiuseven/sbom-provenance-go/sbom"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: sbomprov <command> [args]

commands:
  resolve  <manifest.json> [--platform P] [--optional a,b]  解析依赖图
  sbom     <manifest.json> [--spec 1.0|1.1]                 生成可复现 SBOM
  convert  <sbom.json> --to 1.0|1.1                         规范转换（报告语义损失）
  lock     <manifest.json>                                  生成锁定记录
  check    <manifest.json> <lock.json>                      漂移检测（不一致即阻断）`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "resolve":
		err = cmdResolve(os.Args[2:])
	case "sbom":
		err = cmdSBOM(os.Args[2:])
	case "convert":
		err = cmdConvert(os.Args[2:])
	case "lock":
		err = cmdLock(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadManifest(path string) (*depgraph.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m depgraph.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

func flagValue(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return def
}

func cmdResolve(args []string) error {
	if len(args) < 1 {
		usage()
	}
	m, err := loadManifest(args[0])
	if err != nil {
		return err
	}
	opts := depgraph.Options{Platform: flagValue(args, "--platform", "")}
	g, err := depgraph.Resolve(m, opts)
	if err != nil {
		return err
	}
	out := map[string]any{
		"nodes":  g.Nodes,
		"roots":  g.Roots,
		"cycles": g.Cycles,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// placeholderDigest 是 CLI 演示用的确定性摘要派生：
// 真实部署中由本地制品内容计算（见 provenance.DigestOf）。
func placeholderDigest(name, version string) (string, error) {
	return provenance_DigestOf(name, version), nil
}

func cmdSBOM(args []string) error {
	if len(args) < 1 {
		usage()
	}
	m, err := loadManifest(args[0])
	if err != nil {
		return err
	}
	g, err := depgraph.Resolve(m, depgraph.Options{Platform: flagValue(args, "--platform", "")})
	if err != nil {
		return err
	}
	spec := sbom.SpecVersion(flagValue(args, "--spec", string(sbom.Spec11)))
	doc, err := sbom.Generate(g, placeholderDigest, spec)
	if err != nil {
		return err
	}
	data, err := sbom.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

func cmdConvert(args []string) error {
	if len(args) < 1 {
		usage()
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var doc sbom.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	res, err := sbom.Convert(&doc, sbom.SpecVersion(flagValue(args, "--to", string(sbom.Spec10))))
	if err != nil {
		return err
	}
	for _, l := range res.Losses {
		fmt.Fprintf(os.Stderr, "loss: %s: %s\n", l.Field, l.Reason)
	}
	out, err := sbom.Marshal(res.Document)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

func cmdLock(args []string) error {
	if len(args) < 1 {
		usage()
	}
	m, err := loadManifest(args[0])
	if err != nil {
		return err
	}
	g, err := depgraph.Resolve(m, depgraph.Options{Platform: flagValue(args, "--platform", "")})
	if err != nil {
		return err
	}
	lock, err := lockfile.FromGraph(g, placeholderDigest,
		func(name, version string) string { return "local://" + name + "/" + version })
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(lock)
}

func cmdCheck(args []string) error {
	if len(args) < 2 {
		usage()
	}
	m, err := loadManifest(args[0])
	if err != nil {
		return err
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	var lock lockfile.Lock
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}
	g, err := depgraph.Resolve(m, depgraph.Options{Platform: flagValue(args, "--platform", "")})
	if err != nil {
		return err
	}
	drifts := lockfile.Check(g, &lock)
	if len(drifts) > 0 {
		for _, d := range drifts {
			fmt.Fprintln(os.Stderr, d.Error())
		}
		return fmt.Errorf("drift detected: %d component(s)", len(drifts))
	}
	fmt.Println("no drift")
	return nil
}
