# PMPFuzz 工程实验管线后续任务书

## 0. 任务性质与最高优先级边界

本任务的当前重点是 PMPFuzz 的工程实验管线：构建、配置、DUT 接入、覆盖率反馈、时间线、数据完整性、baseline 适配、统计聚合和作图。

开始工作前必须完整阅读并严格遵守仓库根目录的 `AGENTS.md`。以下限制不可协商：

1. 判断一次运行能否用于覆盖率实验，依据进程是否完成、case/result/timeline 是否齐全、数据契约是否通过验证。
2. 不得修改 `paper/` 下任何文件。`paper/` 当前是用户已有的未跟踪目录，必须保持原状。
3. Rocket、BOOM、XiangShan 是强制 DUT，不能静默删除。CVA6 必须完成工程接入尝试；只有 readiness 仍然失败、且保存了完整构建与 smoke 日志后，才允许在正式矩阵中标为工程排除。
4. 所有新功能和 bug 修复严格执行 TDD：先写会失败的定向测试并提交，再做最小修复，测试转绿后单独提交。
5. 不覆盖或删除历史实验产物。每次运行必须使用新的、可辨识的输出目录。
6. 不修改服务器上的 `Android`、`work`、`ida-hcli` 目录。

## 1. 当前状态与可信基线

本地仓库：

```text
D:\c_s\wjs\riscv-pmp-fuzz
```

当前分支：

```text
feature/engineering-only-evaluation-v4
```

Cascade RED 测试基线提交：

```text
479cb46 test: define Cascade engineering data contract
```

该分支相对远端同名分支领先 3 个提交：

```text
79e770b test: accept complete opaque nonpass rounds
be78450 fix: accept complete opaque nonpass rounds
479cb46 test: define Cascade engineering data contract
```

开始前执行：

```powershell
git status --short --branch
git log -8 --oneline --decorate
```

预期只有 `paper/` 显示为未跟踪；如有其他改动，先辨认来源，不得覆盖用户修改。

已经完成并通过测试的工作：

- 闭环 campaign 跨轮累计和无放回选择；
- guided 使用执行有效的真实覆盖率反馈；
- 权威 child timeline、case/result/timeline 对账和失败门控；
- 每个 case 的绝对单调完成时间；
- BB 与 BB+WB 调度来源记录；
- 普通 `nonpass` 对应的 CLI 返回码 1，在产物完整时视为工程完成，不再误判为基础设施失败；
- 标准数据产物：campaign、覆盖率时间线、事件时间线、阈值时间、AUC、开销、排除项、验证报告、数据字典和 SHA256 清单；
- 三个压缩实验的设计和四 DUT 要求。

关键设计文档：

```text
docs/PMPFUZZ_COMPACT_EVALUATION_DESIGN.md
configs/evaluation/compact_experiment_matrix.yaml
```

服务器：

```text
SSH host alias: dubhe
服务器工作树: /home/dubhe/wjs/riscv-pmp-fuzz-eval-v4
服务器分支: server/engineering-only-evaluation-v4
历史产物根: /home/dubhe/wjs/pmpfuzz-eval-artifacts
```

不要修改旧服务器仓库 `/home/dubhe/wjs/riscv-pmp-fuzz-eval`。服务器无法直接从私有 GitHub HTTPS 拉取时，使用 Git bundle 同步，不要改写旧工作树。

## 2. 总体执行顺序

必须按以下顺序推进，前一阶段未通过不得进入后一阶段：

1. 完成 Cascade adapter 的 TDD 修复。
2. 本地定向测试和全量单元测试。
3. 同步到服务器，在服务器重复定向测试和全量单元测试。
4. 运行 Spike 三轮短冒烟，验证闭环时间线和数据契约。
5. 完成四 DUT 的 clean/instrumented 构建清单和 SHA256 清单。
6. Rocket、BOOM、XiangShan 强制 readiness smoke；CVA6 尽力完成 readiness smoke。
7. 运行小规模 Pilot，冻结轮大小、并行度和时间上限。
8. 只有所有门槛通过后，启动实验 1 和实验 2 正式运行。
9. 聚合、验证并生成论文可用的时间—覆盖率数据和图，不修改论文正文。

## 3. Phase E：完成 Cascade baseline adapter

### 3.1 当前 RED 测试

文件：

```text
tests/test_cascade_adapter_engineering.py
```

当前有 5 个预期失败的测试：

1. adapter 必须声明 Rocket、BOOM、XiangShan、CVA6 四个 DUT；
2. CVA6 和 XiangShan 必须生成各自正确的模拟器命令；
3. Cascade 生成目录必须按 campaign 隔离且可复现；
4. 安全相关事件的归一化 ID 不能包含 case ID 或原始地址，多个事件属于同一 case 时必须共享同一个 `completion_seq`，另用 `event_index` 区分；
5. 每个 case 的 stdout/stderr 必须落盘，规范化事件时间线必须非空且与 case 完成序号一致。

先运行并保存 RED 结果：

```powershell
python -m unittest tests.test_cascade_adapter_engineering -v
```

不要删除或放宽这些测试来获得绿色结果。

### 3.2 需要修改的文件

主要文件：

```text
scripts/evaluation/baseline_adapters/cascade.py
```

必要时可以新增仅供 Cascade ELF 生成使用的辅助脚本，但必须放在：

```text
scripts/evaluation/baseline_adapters/
```

不要把临时脚本放入 `/tmp` 后假装成正式实现。

### 3.3 实现要求

#### A. DUT 矩阵

声明：

```python
SUPPORTED_DUTS = (
    "rocket-clean",
    "boom-clean",
    "xiangshan-clean",
    "cva6-clean",
)
```

CLI 的 `--dut` choices 必须使用这个集合。

已知服务器二进制候选：

```text
/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-RocketConfig
/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-SmallBoomV3Config
/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-CVA6Config
/home/dubhe/wjs/xiangshan_vanilla/build/verilator-compile/emu
```

不要继续使用硬编码的旧 SHA；运行时计算实际二进制 SHA256，并写入 campaign metadata 和 manifest。

Rocket/BOOM/CVA6 命令至少应包含固定 `+max-cycles`、明确的 ELF/loadmem 参数和确定的工作目录。XiangShan 命令使用：

```text
emu --no-diff -C <simlen> -i <elf>
```

这里只要求完整保存退出码和日志。

#### B. 生成目录隔离

旧实现共用并移动 `/cascade-mountdir/cascade-elfs` 中的所有文件，并行不安全，必须删除这种行为。

主机共享目录：

```text
/home/dubhe/wjs/cascade_cpu_fuzzing/mount
```

每个 campaign 使用独立目录：

```text
<mount>/cascade-campaigns/<由 out_dir、seed、design 派生的稳定唯一 ID>/
```

容器对应路径：

```text
/cascade-mountdir/cascade-campaigns/<同一 ID>/
```

任何生成、复制、枚举操作只能作用于这个独立目录。不得枚举并移动其他 campaign 的文件。

生成必须使用传入的 seed；不能继续忽略 `seed`。建议使用 Cascade 官方 Python API，以 `seed + case_index` 或官方 descriptor 的显式 offset 生成，且在 metadata 中记录实际 seed、design 和生成脚本版本。

DUT 到 Cascade design 的映射：

```text
rocket-clean   -> rocket
boom-clean     -> boom
cva6-clean     -> cva6
xiangshan-clean -> xiangshan
```

官方容器：

```text
codex_cascade_cpu_fuzzing
```

XiangShan 适配版 Cascade 源位于容器共享目录：

```text
/cascade-mountdir/cascade_xiangshan_adapt/cascade-meta/fuzzer
```

#### C. 原始日志和终态

每个 case 必须保存：

```text
logs/<case_id>.stdout.log
logs/<case_id>.stderr.log
```

同时在 `events.json` 记录：

```text
case_id
completion_seq
status
elapsed_wall_seconds
case_elapsed_seconds
returncode
probe_event_count
stdout_log
stderr_log
elf_sha256
```

状态只允许用于工程分类：

- `completed`：进程结束且获得了本实验要求的有效观测；
- `inconclusive`：进程结束但缺少有效观测；
- `timeout`：超时；
- `infra_failure`：启动失败、文件缺失或不可执行等基础设施问题。

非零返回码应原样记录，再由产物完整性和观测有效性决定能否贡献事件覆盖率，不能仅凭返回码将一次运行归为基础设施故障。

#### D. 事件时间线

`_build_security_event_timeseries` 不得再次从一个不存在的日志目录读取数据。执行 case 时提取出的 `probe_events` 应直接保存在内存记录中，并传给时间线构造函数。

事件 ID 只包含跨方法、跨 case 稳定的类别字段，例如：

```text
event_namespace | dut | chain | stage | privilege
```

不得包含：

```text
case_id、seed、原始地址、campaign_id、method
```

同一 case 的所有事件共享 case 的 `completion_seq`，并增加从 1 开始的 `event_index`。`total_distinct_events` 必须单调不减。

#### E. metadata

必须至少记录：

```text
schema_version
experiment_id
campaign_id
method=cascade
variant=baseline
dut
seed
source_sha
dut_binary_sha256
container image ID/digest
start_utc/end_utc
elapsed_wall_seconds
requested_cases
completed_cases
eligible_cases
timeouts
inconclusive
infra_failures
simlen
per-case timeout
generation workspace/design/seed
```

不要把实际经过的墙钟秒数错误写入名为 `time_budget_seconds` 的字段；预算和实际耗时应分开。

### 3.4 Phase E 验收

依次运行：

```powershell
python -m unittest tests.test_cascade_adapter_engineering -v
python -m unittest tests.test_evaluation_data_contract tests.test_standard_data_contract_engineering -v
python -m unittest discover -s tests -v
```

验收条件：

- 新增 5 个测试全部通过；
- 全量测试无回归；
- 不通过跳过、删除或弱化测试；
- `git diff -- paper/` 为空；
- RED 测试提交和 GREEN 实现提交彼此独立。

建议提交信息：

```text
fix: isolate Cascade campaigns and normalize event timelines
```

## 4. 同步服务器与短冒烟

### 4.1 同步方法

先在本地完成测试和提交，再同步。服务器私有 GitHub 不可用时：

1. 本地创建包含当前分支的 Git bundle；
2. `scp` 到 `/home/dubhe/wjs/`；
3. 在 `/home/dubhe/wjs/riscv-pmp-fuzz-eval-v4` fetch bundle；
4. 更新 `server/engineering-only-evaluation-v4`；
5. 不修改旧工作树。

服务器更新后先运行：

```text
python3 -m unittest tests.test_closed_loop_driver_engineering \
  tests.test_cascade_adapter_engineering \
  tests.test_standard_data_contract_engineering -v
python3 -m unittest discover -s tests -v
```

### 4.2 Spike 三轮工程冒烟

创建新的时间戳目录，例如：

```text
/home/dubhe/wjs/pmpfuzz-eval-artifacts/engineering-v4-smoke-YYYYMMDD-HHMMSS
```

分别运行 `random`、`bb`、`bb-wb`，每个只跑 3 轮、小规模 case：

```text
python3 scripts/evaluation/run_closed_loop_campaign.py \
  --experiment-id engineering-smoke \
  --variant <random|bb|bb-wb> \
  --coverage-mode semantic \
  --dut spike \
  --profile pmp-boundary \
  --seed 1 \
  --bootstrap-size 4 \
  --round-size 4 \
  --max-rounds 3 \
  --time-budget 300 \
  --per-case-timeout 10 \
  --jobs 1 \
  --artifact-root <独立目录>
```

如果 `bb-wb` 的 Spike 路径不产生白盒事件，这是正常的工程冒烟场景；重点是验证 pipeline 不崩溃、调度来源可追踪、时间线与数据契约正确。不要为了获得白盒事件而伪造数据。

必须验证：

1. child timeline 中每个 case 有真实 `completion_monotonic_seconds`；
2. campaign timeline 的 `elapsed_wall_seconds` 严格不减；
3. `completion_seq` 从 1 连续递增，无跨轮重复；
4. `completed_cases`、`eligible_cases`、覆盖 bins 跨轮只增不减；
5. 每个期望 case 都有 case、result 和 timeline 记录；
6. 返回码 1 且产物完整的轮次保留为工程有效；
7. 缺失 timeline/result 的人工负例必须被 validator 拒绝；
8. 运行聚合器后，标准数据产物全部生成且 SHA 清单可复验。

## 5. 四 DUT readiness

### 5.1 强制 DUT

以下三项全部通过后才能开始正式实验：

```text
rocket-clean
boom-clean
xiangshan-clean
```

CVA6：

```text
cva6-clean
```

必须尝试构建和 smoke。如仍失败，保存日志并在 exclusions 中写明工程原因，例如“模拟器未产生所需 probe”或“构建链不可复现”。

### 5.2 每个 DUT 的构建清单

对 clean 和 instrumented 版本分别记录：

```text
DUT 名称
源码仓库路径
源码 Git SHA
是否 dirty
构建命令
工具链版本
输出二进制绝对路径
二进制 SHA256
构建开始/结束时间
构建日志
probe 配置或 whitebox 配置
```

使用隔离构建目录，不覆盖现有可用二进制。

### 5.3 readiness smoke

每个 DUT 至少运行 16 cases，覆盖 4 个既定 profile，每个 profile 4 cases。输出目录按 DUT 和构建类型隔离。

readiness 只判断：

- 二进制可启动；
- ELF 可加载；
- case/result/timeline 齐全；
- black-box 观测可规范化；
- instrumented 版本能产生真实 whitebox 事件；
- clean 与 instrumented 的执行接口一致；
- 运行时间在可接受范围；
- validator 通过。

XiangShan 是强制 DUT。如果 probe 尚未接通，应修复 probe 接口或构建脚本，而不是从矩阵中删除 XiangShan。

## 6. Pilot 与参数冻结

### 6.1 Pilot 目的

Pilot 不是论文正式数据，只用于冻结：

```text
candidate pool 大小
每轮 case 数
并行度
单 case timeout
每 campaign 时间上限
最后新增覆盖 bin 的时间
吞吐量
可达覆盖率平台
```

### 6.2 最小 Pilot 矩阵

每个强制 DUT：

```text
3 seeds × 3 variants(random, bb, bb-wb)
```

CVA6 readiness 通过则加入同样矩阵。

建议先使用 seeds 1、2、3，每 campaign 上限 30 分钟，但一旦候选池耗尽即可正常结束，不得为了凑时间重复执行 case。

正式并行度从 8 路开始验证；确认无共享目录、内存和 I/O 冲突后才考虑 12 路。不要直接开 48 路。

### 6.3 参数冻结报告

生成一个不修改论文的工程报告，至少给出：

```text
每个 DUT/variant 的有效吞吐
候选池耗尽时间
最后新 bin 时间
最后 5/10 分钟新增 bins
内存峰值
并行冲突
最终冻结的 round size/jobs/timeout/time budget
```

## 7. 正式实验 1

实验定义以 `docs/PMPFUZZ_COMPACT_EVALUATION_DESIGN.md` 为准。

对比：

```text
PMPFuzz-Random
PMPFuzz-BB
PMPFuzz-BB+WB
```

强制 DUT：Rocket、BOOM、XiangShan。CVA6 readiness 通过则加入。

正式 seeds：

```text
101, 102, 103, 104, 105, 106, 107, 108, 109, 110
```

同一 DUT 的三种 variant 必须使用配对 seed、相同 candidate pool、相同执行预算和相同停止规则。

主要结果：

- 时间—语义覆盖率曲线；
- cases—语义覆盖率曲线；
- coverage AUC；
- 达到 25%、50%、75%、90% 最终可达覆盖率的时间；
- 最终覆盖率；
- 有效吞吐量；
- BB+WB 的累计真实白盒事件数。

所有曲线必须由逐 case 真实完成时间生成，不能把同一轮的 case 都挤在轮末。

## 8. 正式实验 2

对比：

```text
PMPFuzz-BB+WB
官方 Cascade
```

riscv-dv 只在官方生成链能真正构建时作为可选项；不得用自写脚本冒充 riscv-dv。若环境不可用，保留有时限的构建日志后排除。

实验 2 的公平比较使用共同的、DUT 侧归一化事件覆盖率和相同墙钟预算。Cascade 的 PMPFuzz semantic/pairwise/predicate 字段保持 `null`，不得伪造语义覆盖率。

同样使用 seeds 101–110。强制 DUT 为 Rocket、BOOM、XiangShan，CVA6 readiness 通过则加入。

记录：

- 时间—共同事件覆盖率曲线；
- 最终共同事件覆盖率；
- AUC；
- 吞吐和 timeout/inconclusive/infra_failure 工程统计；
- 二进制、镜像和源码 SHA。

## 9. 实验 3

实验 3 已设计，但本任务禁止执行。除非用户再次明确授权，否则不得启动真实硬件或跨实现结果分析。

## 10. 标准输出和作图交付

每次正式运行必须最终汇总为：

```text
normalized/campaigns.csv
normalized/coverage_timeseries.csv
normalized/security_event_timeseries.csv
aggregate/coverage_threshold_times.csv
aggregate/coverage_auc.csv
aggregate/overhead.csv
aggregate/exclusions.csv
aggregate/validation_report.json
schemas/data_dictionary.md
manifests/artifact-sha256.txt
```

另外生成：

```text
figures/e1_time_vs_semantic_coverage.pdf
figures/e1_time_vs_semantic_coverage.png
figures/e1_cases_vs_semantic_coverage.pdf
figures/e2_time_vs_common_event_coverage.pdf
figures/e2_time_vs_common_event_coverage.png
tables/e1_summary.csv
tables/e2_summary.csv
```

作图规则：

1. 横轴从 0 开始，单位明确；
2. 同一 DUT 使用配对 seed；
3. 主线使用 seed 中位数，阴影使用四分位区间或 95% bootstrap CI，方法写清楚；
4. 不跨 DUT 混合 denominator；
5. coverage 曲线必须单调不减；
6. 图数据必须能从 normalized CSV 独立重建；
7. 同时输出 PDF 和 300 dpi PNG；
8. 生成图所用脚本、参数和输入 SHA 必须保存。

## 11. 每个阶段的报告格式

不要只回复“完成了”。每阶段必须报告：

```text
阶段名称
修改文件
RED 测试及失败原因
GREEN 测试结果
全量测试结果
提交 SHA
服务器命令
服务器输出目录
生成产物及 SHA
仍存在的工程阻塞
是否允许进入下一阶段：YES/NO
```

如果关键门槛未通过，明确写 `NO` 并停止进入 Pilot 或正式长跑，避免浪费服务器时间。

## 12. 立即开始的第一条指令

当前应从 Phase E 开始：

1. 确认历史中包含 `479cb46`，工作树除 `paper/` 外干净；
2. 运行 `tests.test_cascade_adapter_engineering`，保存 5 个 RED；
3. 只修改 Cascade adapter 相关文件，使 5 个测试转绿；
4. 跑全量测试；
5. 提交 GREEN；
6. 报告结果后继续服务器 Spike 三轮冒烟。

不要重新设计论文，不要修改 `paper/`。
