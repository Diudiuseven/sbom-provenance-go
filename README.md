# sbom-provenance-go

本地化的软件供应链物料清单（SBOM）生成与来源校验工具链。依赖清单、制品
与信任材料全部在本地生成与校验，**不依赖任何外部服务**。

## 包结构

| 包 | 职责 |
|---|---|
| `depgraph` | 依赖清单解析与确定性版本选择 |
| `sbom` | 可复现 SBOM 生成与规范版本转换 |
| `provenance` | 制品签名、真实性证明、透明日志包含证明校验 |
| `tlog` | 本地模拟的只追加透明日志（RFC 6962 风格 Merkle 树） |
| `lockfile` | 依赖固定与漂移检测 |
| `verify` | 并发批量校验、缓存、失败隔离与汇总 |

## 校验语义

### 1. 依赖图解析（depgraph）

- 清单为 JSON：`roots`（根组件）、`requirements`（依赖边，含约束、
  `optional`、`platforms`）、`available`（组件名 → 已发布版本列表）。
- 版本选择策略**完全确定**：优先取满足全部约束的最大版本；无单一版本
  能同时满足时，按规范序贪心分裂出**最小共存版本集**（同一组件多版本
  共存）。解析在不动点迭代下收敛，与清单中声明顺序、遍历顺序无关。
- 循环引用：解析正常完成，Tarjan SCC 以规范序报告于 `Graph.Cycles`。
- 可选依赖不可满足、或平台（`GOOS/GOARCH`）不匹配时，记入
  `Graph.Skipped` 并附原因（`optional_unsatisfiable` /
  `platform_excluded`），不会静默丢弃。
- 非可选依赖不可满足时解析失败并返回错误。

### 2. SBOM 生成与转换（sbom）

- `sbom.Marshal` 输出**字节级可复现**：所有切片排序、map 键排序、序列号
  由内容哈希派生，不含时间戳与随机 UUID；不受遍历顺序、并发度与运行时
  随机化影响。
- 规范版本转换：`1.0 → 2.0` 无损（2.0 是超集）；`2.0 → 1.0` 丢弃
  `supplier` 字段，每个被丢弃的供应商都以 `Loss{Field, Subject, Detail}`
  明确报告。

### 3. 来源校验（provenance）

每个制品依次校验三项，**任一失败即返回可区分的 `*provenance.Error`，
不静默放行、不降级**：

| 校验项 | 失败原因（`FailureReason`） |
|---|---|
| 签名 | `missing_signature` / `bad_signature` / `unknown_signer` / `revoked_key` / `expired_key` |
| 真实性证明 | `missing_attestation` / `attestation_subject_mismatch` / `bad_attestation` |
| 包含证明 | `missing_inclusion_proof` / `bad_inclusion_proof` |

- 签名算法：Ed25519，密钥来自本地 `TrustStore`。
- 密钥生命周期：`Revoked` 一律拒绝；`NotBefore`/`NotAfter`（Unix 秒，0
  表示不限）之外的密钥视为过期拒绝。**过期或吊销的密钥不再被接受**。
- 证明主体必须绑定制品的 `name@version` 与内容摘要，否则
  `attestation_subject_mismatch`。
- 包含证明按 RFC 6962 §2.1.1 重算审计路径并与已记录的树头比对。

### 4. 依赖固定与漂移检测（lockfile）

- `Pin` 由解析图与制品摘要生成排序后的锁定记录。
- `Check` 比对解析图、锁定记录与制品内容摘要，任何不一致都阻断并返回
  `Drift{Component, Path, Detail}`：
  - `Path = "manifest"`：清单解析结果与锁定记录不一致（版本漂移/新增）；
  - `Path = "lockfile"`：锁定记录中的组件不再由清单产生；
  - `Path = "artifact"`：制品内容哈希与固定摘要不匹配。

### 5. 透明日志增量校验（tlog）

- 日志在本地文件模拟（写穿持久化 + 原子重命名），**可重启**，重启后树
  状态完整恢复。
- `Verifier` 把已校验位置（树大小 + 根哈希）持久化到状态文件；重启后
  **已校验位置不丢失、不重复计算**（日志未增长时 `Update` 是空操作）。
- 增量校验使用一致性证明（RFC 6962 §2.1.2/2.1.3）：
  - 日志收缩 → `ErrRollback`（回滚）；
  - 同大小不同根，或一致性证明无法连接已校验根与当前根 → `ErrFork`
    （分叉）；
  - 校验失败时已校验位置**不前进**。

### 6. 并发校验与缓存（verify）

- `BatchVerifier.VerifyAll` 以信号量限制并发（`Options.Concurrency`，
  默认 4），逐制品隔离：panic 恢复为失败，`Options.PerItemTimeout` 超时
  的慢组件标记为 `timeout` 失败，**不阻塞其余组件**。
- 缓存只记忆非密码学的派生结果（内容摘要）；**缓存命中不会跳过任何
  签名或证明校验**——密码学校验每次都完整执行。
- 每个缓存条目记录所涉密钥的纪元（epoch）；`Cache.InvalidateKey(keyID)`
  在密钥轮换或吊销时精确失效受影响条目，其余条目保留。
- 批量结果按 `pass / fail / skipped` 分类汇总（`Summary`），跳过必须
  携带原因：`missing_artifact`（空制品）、`not_in_lock`（未锁定）。
  结果按 `(name, version)` 排序，输出确定。

## 配置项

### `depgraph.Options`

| 字段 | 含义 | 默认 |
|---|---|---|
| `Platform` | 目标平台 `os/arch`，空表示匹配全部 | `""` |

### `verify.Options`

| 字段 | 含义 | 默认 |
|---|---|---|
| `Concurrency` | 并发校验上限（<=0 取 4） | `4` |
| `PerItemTimeout` | 单制品超时（<=0 不限制） | 不限 |
| `Lock` | 非空时启用漂移阻断 | `nil` |
| `Cache` | 非空时启用摘要缓存 | `nil` |

### `provenance.KeyInfo`

| 字段 | 含义 |
|---|---|
| `ID` | 密钥标识 |
| `Public` | Ed25519 公钥 |
| `NotBefore` / `NotAfter` | 有效期（Unix 秒，0 = 不限） |
| `Revoked` | 是否已吊销 |

## 测试

```sh
go test ./... -race -count=1
```

覆盖：多版本共存解析与乱序确定性、SBOM 输出可复现性与转换损失、签名
与证明各类失败、日志回滚/分叉与重启恢复、密钥轮换导致的缓存失效、
并发校验隔离与超时。
