# PMPFuzz 精简实验设计（工程与覆盖率限定版）

**状态**：正式设计冻结候选版  
**适用范围**：仅工程实现、覆盖率、性能、可复现性与跨 DUT 部署  
**禁止事项**：不研究、不复现、不解释任何 `nonpass`、mismatch 或疑似安全现象  
**项目约束**：严格遵守仓库根目录 `AGENTS.md`

## 1. 设计目标

论文只保留三组正式实验：

1. **实验一：覆盖率效果与反馈消融**；
2. **实验二：与外部 baseline 的工程覆盖比较**；
3. **实验三：跨 DUT 部署与工程开销**。

实验三本阶段只完成设计，不运行。当前执行范围仅包括实验一和实验二。

原 `E1-sem`、`E1-pair`、`E1-triple`、`E1-pred` 不再各自运行一套长 campaign。系统以 semantic coverage 作为主要黑盒反馈目标，并从同一执行序列同时计算 semantic、pairwise、security-triples 和 predicates 四类覆盖率。原 mutant、fault-detection 和所有 `nonpass` 分析从当前实验计划中删除。

## 2. 共同实验原则

### 2.1 工程边界

- `nonpass` 只保留不透明状态、计数、时间和产物路径；
- 不读取或解释其指令、波形、寄存器、地址关系和触发原因；
- 不重放、不最小化、不定向变异；
- 不根据 `nonpass` 改变调度；
- 任何图表和结论只讨论覆盖率、吞吐、有效执行比例、开销和可复现性。

### 2.2 独立实验单位

一个独立实验单位是：

```text
(experiment, method/variant, DUT, seed)
```

同一 DUT 上的对比方法使用配对 seed、相同 capability-scoped candidate pool、相同 bootstrap candidate IDs、相同 round size、相同 per-case timeout、相同并行度和相同停止规则。

### 2.3 DUT 与版本

实验一和实验二的 DUT 范围为：

```text
rocket-clean
boom-clean
xiangshan-clean
cva6-clean
```

其中 Rocket、BOOM、XiangShan 是 mandatory DUT。CVA6 也按正式 DUT 准备；只有在可复现构建和 readiness 修复后仍有明确工程阻塞时才允许排除，并必须保留完整失败证据。不能因为 XiangShan 工作量较大而将其删除。

名称中的 `clean` 是现有适配器标识。正式运行必须额外记录实际二进制是否插桩，不能仅根据名称推断。

每个 campaign 必须记录：

```text
PMPFuzz source SHA
DUT source SHA
DUT binary SHA-256
instrumentation patch SHA-256（如适用）
capability fingerprint
toolchain versions
host and CPU allocation
command line
start/end UTC
```

### 2.4 候选池与停止规则

- campaign 启动时构建固定候选池；
- 所有方法从同一候选池选择，严格无放回；
- bootstrap 固定为 32 cases；
- 后续 round 固定为 32 cases；
- 首选停止条件是候选池耗尽；
- 同时设置 30 分钟 wall-clock 安全上限；
- Pilot 若证明 30 分钟不足以耗尽候选池，正式上限只允许在参数冻结时统一调整；
- 不能根据最终覆盖结果事后延长单个方法的预算。

固定候选池意味着最终覆盖率可能趋同，因此主要指标是覆盖速度、AUC 和达到覆盖阈值的时间，而不是只比较最终一个点。

### 2.5 Seeds 与重复

正式实验一、二使用以下 10 个配对 seed：

```text
101, 202, 303, 404, 505, 606, 707, 808, 909, 1010
```

在正式运行前，先用 seeds `1, 2, 3` 做 Pilot。Pilot 只用于验证数据管线和冻结预算，不能与正式结果混合。

### 2.6 Coverage qualification

只有 execution-qualified result 贡献黑盒覆盖率。invalid、缺失、orphan、重复、超时和其他不合格 result：

- 仍计入执行时间和工程状态统计；
- 不贡献 semantic/pairwise/triple/predicate coverage；
- 不贡献调度反馈；
- 不进入白盒反馈集合；
- 不进行原因分析。

### 2.7 时间轴

每个 case 完成时记录真实全 campaign wall-clock 时间：

```text
completion_seq
round_index
round_completion_seq
elapsed_wall_seconds
case_elapsed_seconds
completed_cases
eligible_cases
```

时间必须包含 bootstrap、调度、子进程启动、生成、编译、DUT 执行、结果判定和轮间开销。不得在轮结束后使用文件名顺序或结果文件修改时间重建完成顺序。

## 3. 实验一：覆盖率效果与反馈消融

### 3.1 研究问题

在相同 DUT、候选池、seed、bootstrap 和资源预算下：

1. 黑盒语义反馈是否比随机无放回顺序更快覆盖保护语义空间？
2. 加入白盒反馈后，是否进一步改善黑盒语义覆盖速度或内部事件覆盖速度？

### 3.2 方法

| Variant | 调度规则 | 允许使用的反馈 |
|---|---|---|
| Random | 固定候选池的 seeded shuffle without replacement | 无 |
| PMPFuzz-BB | 按 execution-qualified semantic coverage gap 选择 | 黑盒语义覆盖 |
| PMPFuzz-BB+WB | 每轮最多 16 个白盒候选，剩余由 BB 补足 | 黑盒语义覆盖 + 合格白盒事件 |

三个 variant 使用同一个 instrumented DUT binary 和相同日志开关。Random 和 BB 可以采集白盒日志供离线统计，但调度器不得消费它们。

### 3.3 矩阵

```text
DUTs: rocket-clean, boom-clean, xiangshan-clean, cva6-clean
Mandatory DUTs: rocket-clean, boom-clean, xiangshan-clean
Conditionally excludable DUT: cva6-clean（仅工程 readiness 明确失败）
Variants: random, bb, bb-wb
Pilot seeds: 1, 2, 3
Formal seeds: 101, 202, 303, 404, 505, 606, 707, 808, 909, 1010
Coverage basis: execution-qualified
Primary feedback mode: semantic
Bootstrap: 32
Round size: 32
Per-case timeout: 10 s（Pilot 后可统一调整）
Jobs: Pilot 后冻结；所有配对方法相同
Stop: candidate pool exhausted or fixed wall-clock cap
```

正式规模为：

```text
3 mandatory DUT × 3 variants × 10 seeds = 90 mandatory campaigns
含 CVA6 时：4 DUT × 3 variants × 10 seeds = 120 campaigns
```

### 3.4 主要指标

主指标：

- semantic coverage rate over wall-clock time；
- semantic coverage rate over completed cases；
- normalized AUC；
- time/cases to 25%、50%、75%、90% coverage；
- 每 100 个 execution-qualified results 新增 semantic bins；
- 最后 5 分钟和最后 10 分钟新增 bins；
- time-to-last-new-bin。

辅助指标从同一执行序列计算，不单独运行 campaign：

- pairwise coverage；
- security-triples coverage；
- predicate coverage；
- distinct whitebox events over time；
- completed cases、eligible cases、eligible ratio；
- tests/s、timeout count、infrastructure-failure count；
- scheduling overhead。

### 3.5 统计方法

- 在同一 DUT 和 seed 内做配对比较；
- 报告 10 seeds 的 median、IQR 和 bootstrap 95% confidence interval；
- 报告 BB−Random、BB+WB−BB 的配对效应；
- 未达到覆盖阈值的 campaign 作为 right-censored；
- 不通过挑选单个 seed 支撑结论。

### 3.6 论文图表

**Figure E1-A：Time-to-coverage**

- 三个 mandatory 面板：Rocket、BOOM、XiangShan；
- CVA6 readiness 通过时增加第四面板；
- 横轴：wall-clock minutes；
- 纵轴：execution-qualified semantic coverage rate；
- 三条曲线：Random、BB、BB+WB；
- 粗线：跨 seed median；
- 阴影：bootstrap 95% CI；
- 可选淡线：单 seed 曲线。

**Figure E1-B：Cases-to-coverage / whitebox events**

- 面板一：completed cases 对 semantic coverage；
- 面板二：wall time 对 distinct whitebox events；
- 用于区分调度质量与吞吐差异。

**Table E1：Ablation summary**

每个 DUT/variant 报告：final coverage、AUC、T50、T75、T90、eligible ratio、tests/s 和 scheduling overhead。

### 3.7 验收标准

实验一只有在以下条件全部成立时才可进入论文数据集：

- 三个 variant 的 bootstrap IDs 对同一 DUT/seed 完全相同；
- Random 不读取任何反馈；
- BB 不读取白盒反馈；
- BB+WB 的 selection source 可追溯；
- completion sequence 连续唯一；
- wall time 单调并来自真实 case completion；
- coverage 只增不减，denominator 恒定；
- invalid result 不贡献反馈；
- validator `error_count=0`；
- 图表可完全从 normalized CSV 重建。

## 4. 实验二：与外部 baseline 的工程覆盖比较

### 4.1 研究问题

在相同 Rocket、BOOM、XiangShan（以及 readiness 通过时的 CVA6）DUT、相同插桩、相同资源和停止预算下，PMPFuzz 是否能比成熟通用 RISC-V 测试生成方法更快覆盖共同可观测的 DUT 行为事件？

### 4.2 方法

正式必选方法：

```text
PMPFuzz-BB+WB
Cascade（现有官方 Docker artifact）
```

riscv-dv 仅在官方 generator 和可用模拟器环境能够稳定产生、执行程序时加入。若官方路径在预先限定的工程审计时间内不可用，则标记 `environment-unavailable`，不使用自制 generator 冒充 riscv-dv。

### 4.3 公平比较规则

- 在每个 DUT 内使用相同 instrumented binary；
- 相同 host CPU allocation 和并行度；
- 相同 wall-clock cap；
- 同时报告 fixed executed-test count 视图；
- 生成、编译和执行时间均计入端到端 wall time；
- 相同 per-case host timeout；
- 每种方法保留原始 stdout/stderr/result 和命令；
- PMPFuzz 专属 semantic/pairwise/triple/predicate 字段对 Cascade/riscv-dv 必须为 `null`。

跨方法只使用共同 DUT 事件空间，不能用 PMPFuzz case metadata 给 baseline 计算 PMPFuzz 语义覆盖率。

### 4.4 矩阵

```text
DUTs: rocket-clean, boom-clean, xiangshan-clean, cva6-clean
Mandatory DUTs: rocket-clean, boom-clean, xiangshan-clean
Conditionally excludable DUT: cva6-clean（仅工程 readiness 明确失败）
Methods: pmpfuzz-bb-wb, cascade
Optional method: riscv-dv
Pilot seeds: 1, 2, 3
Formal seeds: 101, 202, 303, 404, 505, 606, 707, 808, 909, 1010
Primary budget: fixed wall-clock cap frozen after Pilot
Secondary view: first N completed tests, N frozen after Pilot
```

不含 riscv-dv 时，正式规模为：

```text
3 mandatory DUT × 2 methods × 10 seeds = 60 mandatory campaigns
含 CVA6 时：4 DUT × 2 methods × 10 seeds = 80 campaigns
```

### 4.5 共同指标

- distinct normalized DUT event IDs over wall-clock time；
- distinct event categories over wall-clock time；
- event-coverage AUC；
- time/cases to 25%、50%、75%、90% of the frozen common event denominator；
- completed tests、valid observations、valid-observation ratio；
- tests/s；
- generator、compile、DUT execution 和 normalization 时间分解；
- timeout、inconclusive、infrastructure failure 计数；
- CPU-hours 和磁盘占用。

任何 `nonpass` 只计为不透明工程状态，不分析、不重放，也不作为比较指标。

### 4.6 共同事件定义

共同 event ID 必须只由 DUT instrumentation 的稳定字段构成，例如：

```text
DUT
event namespace
event category
probe identity
stage/category（若稳定存在）
privilege class（若稳定存在）
```

case ID、方法名、随机 seed 和原始地址不得用于制造方法特有的 event ID。原始地址可作为 evidence 字段保存，但默认不进入 event identity。

共同 event denominator 在 Pilot 后冻结，并写入 manifest。正式实验开始后不得根据观察结果修改。

### 4.7 论文图表

**Figure E2：Common DUT events over time**

- 三个 mandatory 面板：Rocket、BOOM、XiangShan；
- CVA6 readiness 通过时增加第四面板；
- 横轴：wall-clock minutes；
- 纵轴：distinct normalized DUT events；
- 方法：PMPFuzz、Cascade，以及可用时的 riscv-dv；
- median + bootstrap 95% CI。

**Table E2：Baseline summary**

报告 common-event AUC、final distinct events、eligible/valid ratio、tests/s、generation overhead、execution overhead 和 disk usage。

### 4.8 验收标准

- baseline 使用真实官方实现；
- 相同 DUT binary 和 instrumentation；
- 每个 case/program 有独立日志和结果；
- completion time 为真实 wall time；
- event ID 与方法、case ID 无关；
- 所有方法使用相同资源预算；
- PMPFuzz 专属字段在 baseline 中为 `null`；
- validator `error_count=0`；
- 图表可从 normalized CSV 重建。

## 5. 实验三：跨 DUT 部署与工程开销（本阶段不运行）

### 5.1 研究问题

PMPFuzz 的工程管线能否部署到不同 RISC-V RTL 和实际硬件，并以一致数据契约产生覆盖率、吞吐和开销数据？

### 5.2 DUT

```text
Rocket
BOOM
CVA6
XiangShan
U74（黑盒）
C910（黑盒）
```

### 5.3 方法与重复

- RTL：PMPFuzz-BB+WB，5 seeds；
- 实际硬件：PMPFuzz-BB，3 seeds；
- Rocket/BOOM 尽量复用实验一的相同配置数据；
- CVA6/XiangShan 只运行 portability 配置，不加入全部消融和 baseline 矩阵；
- U74/C910 不要求白盒数据，相关字段为 `N/A/null`。

### 5.4 指标

- supported capability profile；
- semantic/pairwise/triple/predicate coverage；
- whitebox events（仅 RTL）；
- completed/eligible cases；
- tests/s；
- timeout/infra-failure rate；
- clean/instrumented runtime overhead（仅 RTL）；
- adapter/setup effort；
- artifact size。

不同 DUT 的 raw event-bin 数不能用于宣称某个 DUT 优于另一个 DUT。本实验只证明部署和数据管线的一致性。

### 5.5 论文表格

一张 portability table 即可，列出 DUT、测试模式、capabilities、覆盖率、白盒事件、eligible ratio、tests/s、instrumentation overhead。实际硬件不适用字段填 `N/A`。

### 5.6 当前状态

```text
DESIGNED_ONLY
DO_NOT_RUN_WITHOUT_NEW_USER_AUTHORIZATION
```

## 6. 标准数据契约

所有 Pilot 和正式实验都必须生成：

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

### 6.1 coverage_timeseries 最小字段

```text
experiment_id,campaign_id,method,variant,dut,seed,coverage_mode,
completion_seq,elapsed_wall_seconds,completed_cases,eligible_cases,
covered_bins,target_bins,coverage_rate,new_bins,status,failure_class,case_id
```

### 6.2 security_event_timeseries 最小字段

```text
experiment_id,campaign_id,method,variant,dut,seed,
completion_seq,event_index,elapsed_wall_seconds,
event_namespace,event_category,event_id,is_new_event,total_distinct_events,case_id
```

### 6.3 原始数据保留

- 原始 case/result/log 不覆盖；
- normalized 数据只由脚本生成；
- plots 只读取 normalized/aggregate 数据；
- exclusions 在统计前应用；
- 每个最终输入文件写 SHA-256；
- synthetic baseline 行不进入 normalized completion 表。

## 7. Pilot 与正式运行门槛

### 7.1 Pilot 前工程 gate

- 真实 closed-loop 入口可以运行；
- 三轮 Random/BB/BB+WB 端到端测试通过；
- completion order、wall time、coverage 和 feedback 资格通过 validator；
- Cascade adapter 的隔离目录、日志、终态和 event timeline 通过短 smoke；
- Rocket/BOOM instrumented binaries、SHA 和 capability fingerprint 完整；
- 完整数据契约可生成；
- `paper/` 未修改。

### 7.2 Pilot 输出

Pilot 冻结：

```text
wall-clock cap
fixed test-count N
jobs/parallelism
per-case timeout
common event denominator
plot sampling/interpolation grid
formal exclusions
```

### 7.3 正式运行顺序

1. 实验一 Pilot；
2. 实验一正式 60 campaigns；
3. 实验二 Cascade Pilot；
4. 实验二正式 40 campaigns；
5. 聚合、validator 和绘图；
6. 实验三保持不运行。

## 8. 预期论文产物

```text
Figure E1-A: Random vs BB vs BB+WB time-to-semantic-coverage
Figure E1-B: cases-to-coverage and whitebox-events-over-time
Table E1: coverage ablation summary
Figure E2: PMPFuzz vs Cascade common-events-over-time
Table E2: baseline performance and overhead summary
Table E3: portability design placeholder（本阶段无数据）
```

图表必须由脚本生成，并保存 PNG、PDF 和绘图输入 CSV。不得手工调整数据点。
