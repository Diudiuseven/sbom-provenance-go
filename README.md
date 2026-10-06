# sbom-provenance-go

软件供应链物料清单（SBOM）生成与来源校验工具。依赖清单、制品与信任材料全部在
本地生成，校验过程不依赖任何外部服务。

## 架构

| 包 | 职责 |
|---|---|
| `depgraph` | 依赖清单解析：多版本共存、循环引用、可选依赖、平台条件依赖 |
| `sbom` | 可复现 SBOM 生成与规范版本转换（1.0 ↔ 1.1） |
| `keys` | 本地签名密钥：生成、轮换、吊销、有效期判定 |
| `tlog` | 本地只追加透明日志（Merkle 树）：包含证明、一致性证明、增量校验 |
| `provenance` | 单制品来源校验：摘要、签名、真实性证明、包含证明 |
| `lockfile` | 依赖固定与漂移检测 |
| `cache` | 校验辅助缓存（密钥纪元失效） |
| `verify` | 批量并发校验编排：失败隔离、超时跳过、结果汇总 |
| `cmd/sbomprov` | 命令行入口 |

## 校验语义

### 依赖解析（depgraph.Resolve）

- **版本选择**：对每个依赖约束，取满足约束的**最高**可用版本。选择只依赖约束
  与可用版本集合，与清单声明顺序、遍历顺序无关。
- **多版本共存**：节点以 `name@version` 为唯一标识，不同依赖方选中的不同版本
  在图中共存。
- **循环引用**：节点记忆化展开保证终止；解析后报告全部循环（`Graph.Cycles`）。
- **可选依赖**：默认不纳入，仅在 `Options.IncludeOptional` 显式启用时纳入。
- **平台条件依赖**：`Dependency.Platforms` 非空时，仅当目标平台
  （`Options.Platform`，如 `linux/amd64`）匹配其一才纳入。
- **确定性**：节点、边、根、循环报告全部按字典序排序，任意两次运行结果一致。

### SBOM 生成（sbom.Generate / sbom.Marshal）

- 相同输入与配置在任意一次运行输出**字节级一致**：组件与依赖列表预先排序，
  序列号由内容哈希派生（`urn:sbomprov:<hash>`），不含时间戳、随机数、map 迭
  代序等任何运行时因素；与并发度无关。
- **规范转换**（`sbom.Convert`）：
  - `1.0 → 1.1`：升级，无损（新增字段以默认值补齐）。
  - `1.1 → 1.0`：降级，`dependsOn` 与 `sourcePath` 被丢弃，逐组件以
    `LossNote{Field, Reason}` 明确报告语义损失。

### 来源校验（provenance.Verifier.Verify）

按固定顺序执行四项校验，**任一失败立即返回可区分的 `*Failure`，绝不静默放行
或降级**：

| 顺序 | 校验项 | 失败类别（FailureKind） |
|---|---|---|
| 1 | 制品内容哈希与记录摘要比对 | `digest` |
| 2 | 签名（ed25519，密钥须存在、未吊销、未过期、已生效） | `signature` |
| 3 | 真实性证明（attestation 主题组件与摘要须与制品一致） | `attestation` |
| 4 | 透明日志包含证明（记录匹配、Merkle 证明有效、证明根与本地日志在声明树大小时的状态一致） | `inclusion` |

包含证明无需匹配日志最新根：日志只追加，证明针对其声明的历史树大小
（`TreeSize`）校验即可。

### 漂移检测（lockfile）

- `lockfile.Check`：对比解析图与锁定记录。组件版本被解析但未锁定、或锁定组件
  不再被解析，都构成漂移，调用方必须阻断。
- `lockfile.VerifyArtifact`：制品内容哈希与锁定摘要不一致、或缺少锁定条目时
  返回 `*Drift`，其中携带组件标识与来源路径（`SourcePath`）。

### 透明日志增量校验（tlog.IncrementalVerifier）

- 日志本地模拟（JSON 文件持久化），可重启；检查点（`Checkpoint{Size,RootHash}`）
  持久化到磁盘，重启后已校验位置不丢失。
- `VerifyNew` 只处理上次检查点之后的新条目，**不重复计算**已校验部分：
  1. 日志变短 → 回滚，报 `ErrConsistency`；
  2. 检查点位置的根哈希变化 → 分叉，报 `ErrConsistency`；
  3. 校验 `旧大小 → 新大小` 的一致性证明（RFC 6962 风格）；
  4. 逐条校验新条目的包含证明；
  5. 推进并持久化检查点。

### 缓存与密钥生命周期（cache / keys）

- 缓存只保存非密码学的派生数据（制品摘要）；**缓存命中不跳过任何签名或证明
  校验**——密码学校验每次都完整执行。
- 密钥轮换（`keys.Store.Rotate`）或吊销（`Revoke`）后必须调用
  `cache.InvalidateKeys`：密钥纪元递增，全部旧条目立即失效。
- 过期（`ErrExpired`）、未生效（`ErrNotYetValid`）、已吊销（`ErrRevoked`）的
  密钥一律拒绝，错误可区分。

### 批量并发校验（verify.Batch）

- 单组件失败被隔离，不影响其余组件；慢组件超过 `Timeout` 后记为 `skipped`，
  不阻塞整批。
- 汇总 `Summary` 中 `Passed / Failed / Skipped` 三类可区分；`Skipped` 必须携
  带具体原因（材料缺失、制品不可用、超时等）。
- 汇总输出按组件名排序，与并发度（`Workers`）无关。

## 配置项

### depgraph.Options

| 字段 | 含义 | 默认 |
|---|---|---|
| `Platform` | 目标平台（如 `linux/amd64`），用于平台条件依赖 | 空（不匹配任何条件） |
| `IncludeOptional` | 显式启用的可选依赖名列表 | 空 |

### verify.Batch

| 字段 | 含义 | 默认 |
|---|---|---|
| `Workers` | 并发校验 worker 数 | 4 |
| `Timeout` | 单组件超时，超时记为 skipped | 5s |
| `Cache` | 辅助缓存；密钥轮换/吊销后需 `InvalidateKeys` | 可空 |

### provenance.Verifier

| 字段 | 含义 |
|---|---|
| `Keys` | 本地密钥库 |
| `Log` | 本地透明日志 |
| `Now` | 时钟（密钥有效期判定）；nil 用真实时钟，测试可注入固定时间 |

## CLI

```sh
sbomprov resolve  <manifest.json> [--platform P]   # 解析依赖图
sbomprov sbom     <manifest.json> [--spec 1.0|1.1] # 生成可复现 SBOM
sbomprov convert  <sbom.json> --to 1.0|1.1         # 规范转换（stderr 报告损失）
sbomprov lock     <manifest.json>                  # 生成锁定记录
sbomprov check    <manifest.json> <lock.json>      # 漂移检测（漂移时非零退出）
```

清单格式见 `depgraph.Manifest`：`roots` 为顶层依赖（含约束、可选标记、平台条
件），`components` 为本地可用组件版本全集。

## 测试

```sh
go test ./...
```

覆盖：多版本解析与确定性（`depgraph`）、输出可复现与转换损失（`sbom`）、签名
/证明/包含失败可区分（`provenance`）、日志回滚与分叉、重启增量校验（`tlog`）、
密钥轮换与缓存失效、并发校验与慢组件隔离（`verify`、`keys`）、端到端流水线
（`integration`）。
