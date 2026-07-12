# PMPFuzz 评估管线与四 DUT 实验就绪修复计划

> 日期：2026-07-13  
> 执行对象：DeepSeek/Claude Code  
> 代码仓库：`D:\c_s\wjs\riscv-pmp-fuzz`  
> 服务器工作区：`/home/dubhe/wjs`  
> 服务器登录：`ssh dubhe`  
> 本文只规定代码、DUT 构建与实验准备。禁止修改 `paper/` 下的任何论文文件。

## 0. 任务结论与执行原则

当前不能继续 Pilot-B 或正式 campaign。已经完成的 Rocket/BOOM Pilot-A 只能作为单轮吞吐、Timeline 和白盒采集 smoke，不能作为 random/guided 对比数据。

原因包括：

1. guided 实际没有启用闭环调度；
2. `run_closed_loop_campaign.py` 不能正确累计多轮 Timeline、覆盖率和完成序号；
3. random 不是严格无放回，guided 也没有可靠排除已运行 case；
4. `bb` 和 `bb-wb` 当前没有实现不同的反馈逻辑；
5. `TimelineRecorder` 虽有白盒字段，但完成回调没有增量提取白盒事件，因此时间—白盒事件曲线恒为零；
6. Cascade adapter 仍是 stub；
7. 当前正式实验矩阵只包含 Rocket 和 BOOM，CVA6 与 XiangShan 没有进入正式矩阵；
8. CVA6 与 XiangShan 尚未达到正式实验所需的可复现白盒就绪状态；
9. 服务器 DUT binary SHA manifest 仍为空，环境清单中的 Spike/Verilator 路径记录失败。

执行顺序必须是：

```text
修复测试先行
→ 修复闭环 campaign
→ 修复增量白盒反馈与 Timeline
→ 修复数据契约和验证器
→ 完成 Cascade adapter
→ 固化四 DUT 的 clean/instrumented 构建
→ 四 DUT readiness smoke
→ 重跑 Pilot-A
→ Pilot-B
→ 冻结正式参数
→ 正式实验
```

除非本文明确要求，不要重构 generator、protection model、emitter、verdict 或论文定义的保护语义。

## 1. 当前四 DUT 的真实就绪状态

“二进制存在”不等于“正式实验就绪”。正式就绪至少要求：执行适配、结构化完成、能力模型、保护语义目标空间、白盒探针、事件解析、Timeline、聚合、版本和二进制哈希全部连通。

| DUT | 当前实验矩阵 | 可执行二进制 | 当前评估目录中的白盒 smoke | 源码探针现状 | 正式就绪结论 |
|---|---|---|---|---|---|
| Rocket | 已包含 E1/E2/E3/Pilot | 有，SHA-256 `33f988486ebbf25711ce9e3ef42f1a8b1f41619b2584e35b8b549e943059db5d` | 有，672 signals、12 observed bins | PMP/PTW/TLB 探针已进入构建；TLBPermissions 模板缺失 | 接近就绪，但仍受全局闭环、manifest 和数据契约阻塞 |
| BOOM | 已包含 E1/E2/E3/Pilot | 有，SHA-256 `e02afa40ccd836641f087fe91c7c93c3fd6265722dd3568b7868642def775265` | 有，526 signals、15 observed bins | 4 个 BOOM 探针已进入构建；共享 Rocket 源码标签需保持运行 DUT 归属 | 接近就绪，但仍受全局闭环、manifest 和数据契约阻塞 |
| CVA6 | 未进入当前正式矩阵 | 有，SHA-256 `96af31945be21ca6fab5da9bb81e1f9cdcddc1cf4bcf889d43a29c20d81df885` | 当前 eval 目录没有；历史 smoke 最好仅 2 个 source-probe signals | PTW/TLB 探针存在；PMP CSR 探针锚定生成文件，不稳定 | 未就绪 |
| XiangShan | 未进入当前正式矩阵 | 有，SHA-256 `bae1f5ba4fd3f42f9425dd251bc6a43fb50f1562c336b874541197ca119d7de4` | 当前 eval 目录没有；历史证据主要是 142 个 PERF signals | 4 个 probe spec 仅能发现源码，完全没有 instrumentation template，当前源码树没有 `PMFUZZ_PROBE` | 未就绪 |

服务器当前 DUT 仓库也不是可直接发表的冻结状态：

- `/home/dubhe/wjs/pmp-duts/chipyard-1.14.0` 为 dirty，Rocket/BOOM/CVA6 子模块和配置均有修改；
- DUT 名称仍叫 `*-clean`，但当前二进制实际包含 PMPFuzz probe；
- `manifests/dut-binaries.sha256` 的主要值为空；
- 当前只有 Rocket/BOOM 的 eval smoke 进入 `/home/dubhe/wjs/pmpfuzz-eval-artifacts`。

不得删除、reset 或覆盖这些现有目录。后续应从已记录 SHA 创建隔离构建副本或 worktree。

## 2. 四个 DUT 在论文实验中的角色

四个 RTL 都是论文的实验对象，但不需要在所有实验中做相同数量的重复。

### 2.1 受控方法比较：Rocket 与 BOOM

以下高成本实验继续集中在 Rocket 和 BOOM：

- random 与四种 coverage-guided 调度对比；
- BB 与 BB+WB 白盒反馈消融；
- PMPFuzz 与 Cascade 等外部 baseline 的共同指标比较；
- 20–30 个 protection-specific mutants；
- 10 个独立 seeds 的主要统计。

原因是这两个 DUT 的 baseline、白盒探针和 mutant 环境最成熟。不要把 CVA6/XiangShan 强行加入全部 baseline/mutant 矩阵，避免实验规模无意义膨胀。

### 2.2 跨 DUT 可部署性：四个 RTL 全部参加

新增 `E4-PORT`，包含：

```text
DUT: rocket-clean, boom-clean, cva6-clean, xiangshan-clean
variant: full（语义引导 + 白盒采集 + 白盒反馈）
seeds: 11, 22, 33, 44, 55
initial budget: 每个 run 1h
round size: 32
```

每个 DUT 报告：

- completed/eligible tests；
- semantic/pairwise/security-triples/predicate coverage；
- execution-qualified rate；
- distinct whitebox security events over time；
- 吞吐、timeout、infra failure；
- 支持/不支持的 capability；
- 结构化完成与白盒探针种类。

`E4-PORT` 用于证明 PMPFuzz 能部署到不同微架构，不用于宣称某个 DUT 比另一个 DUT 更容易覆盖。因此不同 DUT 的 raw whitebox bin 数不能直接解释为优劣。

Rocket/BOOM 若已有完全相同配置的正式 full campaign，可截取前 1 小时复用，不得重复运行。

### 2.3 白盒指标的论文口径

白盒主指标使用“累计发现的不同安全相关事件数”，而不是伪造一个跨 DUT 通用百分比分母：

- 同一 DUT、同一二进制、同一 probe 配置下，可以比较 BB 与 BB+WB 的事件发现曲线；
- 跨 DUT 只比较共同事件类别，例如 `pmp-check`、`ptw-request`、`ptw-response`、`exception-arbitration`、allow/deny 和 PTW level；
- 不把不同 DUT 的事件并集当成共同 denominator；
- 不把 Python 代码覆盖率、普通日志行数或所有性能计数器数量称为 DUT 白盒覆盖率；
- clean 与 instrumented RTL 的运行开销单独报告。

## 3. Phase A：保存状态并建立修复分支

### A1. 保存当前状态

在本地执行只读检查：

```text
git status --short
git rev-parse HEAD
git branch --show-current
```

要求：

- 不修改或提交 `paper/`；
- 不删除未跟踪的进度报告和实验任务书；
- 不执行 `git reset --hard`、`git checkout --` 或清理命令；
- 记录当前 commit `394eb114fbe8af99280d01fb38f131f50c31a64b` 与服务器 SHA 是否一致。

建议从当前代码创建专门修复分支：

```text
feature/evaluation-pipeline-v2
```

只显式暂存代码、测试、配置和本文，不包含 `paper/`。

### A2. 标记无效 Pilot-A

不得删除已有 8 个 Pilot-A campaign。生成：

```text
/home/dubhe/wjs/pmpfuzz-eval-artifacts/aggregate/exclusions.csv
```

将这些活动标为：

```text
classification=pilot-invalid-for-comparison
reason=guided_scheduler_not_enabled
included_in_primary_analysis=false
action=retain_as_throughput_and_pipeline_smoke
```

它们可以用于说明单轮 Timeline、吞吐、有效执行比例和四路并发 smoke，但不得进入 random/guided 效果统计、覆盖率中位数或论文主图。

## 4. Phase B：按 TDD 修复闭环 campaign

主要文件：

- `scripts/evaluation/run_closed_loop_campaign.py`
- `pmpfuzz/semantic_coverage.py`
- `pmpfuzz/timeline.py`
- `pmpfuzz/runner.py`
- `tests/test_closed_loop_campaign.py`（新增）
- `tests/test_evaluation_scripts.py`

### B1. 先写失败测试

新增至少以下测试：

1. 三轮 random campaign 的 `completion_seq` 在整个 campaign 中连续且唯一；
2. 三轮 guided campaign 的累计覆盖率永不回退；
3. `completed_cases`、`eligible_cases` 跨轮累计；
4. campaign 时间包含 bootstrap、调度、coverage 计算和轮间开销；
5. 每轮不能重复运行已经完成的 candidate；
6. random 是对同一候选池的 seeded shuffle without replacement；
7. paired random/guided 使用完全相同 bootstrap case IDs；
8. guided 只能从未运行候选中选择；
9. 子轮失败不会让整个 campaign 静默标为成功；
10. 中断后已有 JSONL 仍可解析，resume 不覆盖原数据；
11. campaign 最后一个 Timeline 点与聚合 coverage 完全一致；
12. 同一个 seed 的两次运行选择顺序可复现。

测试必须先 RED，再修改实现使其 GREEN。

### B2. 建立固定候选池

不要让每个 round 重新临时生成互不关联的候选。

在 campaign 启动时建立：

```text
metrics/candidate_pool.json
```

每个候选至少包含：

```text
candidate_id
profile
generation_seed
scenario_index
required_capabilities
semantic_bins
pairwise_bins
security_triple_bins
predicate_bins
```

`candidate_id` 必须由稳定字段计算，不能使用 Python 进程随机 hash。

同时维护：

```text
metrics/executed_candidates.jsonl
```

所有调度器在选择前必须排除其中已有的 `candidate_id`。

### B3. 明确定义四种 variant

实现不能继续使用“只要不是 random 就走同一条 schedule”这种逻辑。

```text
random:
  固定候选池 seeded shuffle，无放回，不读取任何覆盖反馈

guided:
  根据指定 coverage_mode 的缺口，从未运行候选中选择

bb:
  使用黑盒 execution-qualified coverage 反馈，不使用白盒事件

bb-wb:
  最多 16 个白盒反馈候选 + 黑盒覆盖候选补足至 32，去重并排除已运行候选
```

`bb` 与 `bb-wb` 必须使用相同 instrumented DUT binary、相同日志开关和相同资源预算。`bb` 可以采集白盒日志用于离线核对，但调度器必须忽略它。这样才能把差异归因于反馈，而不是插桩或日志开销。

### B4. 使用单一 campaign 累计状态

删除当前 `_merge_timelines()` 的“直接拼接每轮 JSONL”实现。不要通过后处理猜测跨轮累计状态。

推荐做法：把 closed-loop driver 改成进程内 orchestration，在整个 campaign 生命周期中保持一个：

```text
CampaignState
TimelineRecorder
candidate pool
executed candidate set
covered semantic/pairwise/triples/predicate sets
covered whitebox event set
campaign monotonic start time
```

每个 case 完成时直接更新同一个 recorder。round 只是输出目录和调度边界，不得重置累计覆盖、完成序号或 campaign clock。

如果必须继续使用子进程，必须实现显式 campaign-state 恢复，而不是拼接独立 timeline：

- 从已有全局 JSONL 恢复累计 sets；
- 下一轮从全局最大 `completion_seq + 1` 开始；
- per-case 完成时间基于 driver 的原始 monotonic start；
- schedule 和后处理耗时自然进入 elapsed wall time；
- 每轮结束后对全局状态执行一致性校验。

### B5. 停止与失败规则

campaign 仅在以下条件停止：

- 达到固定墙钟预算；
- 候选池耗尽；
- 预先声明的 coverage 目标全部完成；
- 明确的不可恢复 infrastructure failure。

单个 case timeout 计入结果和时间，但不自动终止 campaign。连续 infrastructure failure 达到预先固定阈值时终止并标为 invalid，不得静默继续。

## 5. Phase C：实现增量白盒 Timeline 与 BB+WB 反馈

主要文件：

- `pmpfuzz/whitebox.py`
- `pmpfuzz/dut_coverage.py`
- `pmpfuzz/timeline.py`
- `pmpfuzz/feedback.py`
- `scripts/evaluation/run_closed_loop_campaign.py`
- `tests/test_incremental_whitebox_timeline.py`（新增）
- `tests/test_whitebox.py`

### C1. 增加单 result 白盒提取 API

当前 `whitebox.py` 主要扫描整个 run directory。新增公开函数，例如：

```text
extract_security_whitebox_signals_for_result(case, result, artifact_root)
whitebox_event_ids_for_result(case, result, artifact_root)
```

要求：

- 只扫描刚完成 result 自己的日志和 artifact；
- 不重复扫描整个 campaign；
- 保持 result DUT 为主归属，日志中的 reported DUT 只作为证据字段；
- 使用稳定 event ID；
- `covered=0` 不生成 coverage event；
- 无效 observation 不得给调度反馈，但原始信号仍可归档。

### C2. 接通 TimelineRecorder

`timeline_on_complete_factory()` 当前没有向 `record()` 传递 `whitebox_new_events`。修复为：

1. case 完成；
2. 增量提取该 result 的事件 ID；
3. 与 recorder 的全局 whitebox event set 求差；
4. 传入 `new_whitebox_events`；
5. 更新 `whitebox_distinct_events`；
6. 同时写 `security_event_timeseries.jsonl` 或足够的信息供后处理规范化。

白盒事件增长必须按 case 实际完成顺序记录，不能在 campaign 结束时一次性补齐。

### C3. 实现 BB+WB 的 16+16 合并

每轮结束后：

1. 从 valid、execution-qualified 的已完成结果构建黑盒 coverage schedule；
2. 从当前白盒信号构建 behavior/whitebox schedule；
3. 白盒 schedule 最多取 16 个未运行候选；
4. 黑盒 schedule 补足至 round size 32；
5. 以 `candidate_id` 去重；
6. 白盒为空时全部由黑盒补足；
7. 记录每个入选 case 的 `selection_source=blackbox|whitebox`；
8. 记录当轮候选数、去重数、已执行排除数和最终选择数。

### C4. 必须增加的测试

1. 新 source-probe event 令 whitebox distinct count 增加；
2. 重复 event 不增加；
3. 另一 DUT 日志标签不能改变 result 的真实 DUT；
4. invalid observation 不用于 feedback；
5. `bb` 和 `bb-wb` 的 bootstrap 完全相同；
6. `bb` 不消费白盒 schedule；
7. `bb-wb` 满足最多 16 个白盒候选；
8. 白盒候选不足时黑盒正确补足；
9. 合并后无重复 candidate；
10. 时间—白盒事件曲线单调不减。

## 6. Phase D：修复数据契约、聚合和验证器

主要文件：

- `scripts/evaluation/aggregate_results.py`
- `scripts/evaluation/validate_timeline.py`
- `scripts/evaluation/plot_coverage_time.py`
- `tests/test_evaluation_data_contract.py`（新增）
- `tests/test_evaluation_scripts.py`

### D1. 区分 raw baseline 与 normalized completion

原始 JSONL 可以保留 synthetic baseline：

```text
completion_seq=0
completed_cases=0
```

但 `normalized/coverage_timeseries.csv` 必须：

- 去掉 synthetic baseline 行；
- 真实完成从 `completion_seq=1` 开始；
- `(campaign_id, coverage_mode, completion_seq)` 唯一；
- `completed_cases` 与 completion sequence 对账。

### D2. 修复 predicate 新增 bin 字段

原始字段是：

```text
new_predicate_bins
```

聚合脚本不能错误读取 `new_predicates_bins`。加入精确单元测试。

### D3. 完成标准输出

必须生成任务书第 13A 节规定的：

```text
normalized/campaigns.csv
normalized/coverage_timeseries.csv
normalized/security_event_timeseries.csv
aggregate/coverage_threshold_times.csv
aggregate/fault_detection.csv
aggregate/overhead.csv
aggregate/exclusions.csv
aggregate/validation_report.json
schemas/data_dictionary.md
manifests/artifact-sha256.txt
```

缺失值必须为空/`null`，不能用假 0。

### D4. 扩展 validator

当前 validator 只检查有限的 Timeline 内部一致性。必须真正检查：

- case/result 是否存在；
- result 与 Timeline case_id/DUT 是否一致；
- 重复结果和 orphan result；
- source/DUT/binary SHA 是否存在；
- environment、commands 和 metadata 是否完整；
- raw/normalized 主键是否重复；
- 累计完成数与终态计数是否对账；
- 白盒事件曲线是否单调；
- 排除活动是否进入主要统计；
- 图表能否从规范化 CSV 重建。

正式数据必须满足 `aggregate/validation_report.json` 的 `error_count=0`。

在上述检查全部实现以前，旧 validator 输出的 `valid=True` 只能解释为“当前已实现的有限内部一致性检查通过”，不得解释为 campaign 已满足正式数据契约。

## 7. Phase E：完成 Cascade baseline adapter

主要文件：

- `scripts/evaluation/baseline_adapters/cascade.py`
- `tests/test_baseline_adapters.py`（新增）

不得把“Cascade ELF 能运行”称为“baseline 完成”。adapter 必须：

Cascade 当前没有标准 `tohost/fromhost` 完成符号，固定 simlen 运行可能以退出码 255 结束。因此不能把 `returncode=255` 简单等同于 DUT failure，也不能把“运行到 simlen”自动等同于有效完成。必须先定义并测试终态分类。

1. 调用已经部署的官方容器 `codex_cascade_cpu_fuzzing`；
2. 不执行 docker pull/run/stop/rm；
3. 记录容器、镜像 digest、source hash、DUT binary hash；
4. 记录 ELF 生成开始和结束时间；
5. 在 Rocket/BOOM 上执行 ELF；
6. 用固定 simlen 和 timeout 形成明确停止规则；
7. 区分 completed、timeout、inconclusive、infra failure；
8. 提取共同 `PMFUZZ_PROBE` security events；
9. 生成标准 campaigns、event timeline 和 overhead 数据；
10. PMPFuzz 专属 semantic/pairwise/predicate 字段保持 `null`。

riscv-dv 再做一次最多 2 小时的官方路径审计。若没有可用 UVM simulator 且官方 generator 仍无法运行，保存证据并标记 environment-blocked。PMPFuzz random 是内部消融，不得声称为 riscv-dv 的等价替代。`/tmp/riscv_priv_gen2.py` 或其他临时自制 generator 不能以 riscv-dv 的名称进入实验、表格或 artifact。

## 8. Phase F：构建可复现的四 DUT 实验版本

### F1. 共同构建规则

每个 DUT 至少准备两个版本：

```text
clean: 未插入 PMFUZZ_PROBE，用于插桩开销测量
instrumented: 固定 PMFUZZ_PROBE 配置，用于白盒反馈和正式白盒数据
```

不得继续直接修改当前 dirty DUT 目录。创建：

```text
/home/dubhe/wjs/pmpfuzz-dut-builds/<dut>/<source-sha>/clean/
/home/dubhe/wjs/pmpfuzz-dut-builds/<dut>/<source-sha>/instrumented/
```

每个目录保存：

```text
source.json
git-status.txt
submodule-shas.txt
instrumentation.patch
instrumentation-manifest.json
build-command.txt
build.log
binary.sha256
toolchain.json
```

不能仅凭 DUT 名称中的 `clean` 判断插桩状态。campaign metadata 必须新增：

```text
instrumentation_mode=clean|instrumented
instrumentation_patch_sha256
```

### F2. Rocket

当前已有可信 source-probe smoke。仍需：

1. 从固定 Rocket/Chipyard SHA 创建隔离 clean 与 instrumented 构建；
2. 复现 PMP、PTW、TLB exception 探针；
3. 为 `rocket_tlb_permissions` 实现缺失的 instrumentation template，或者从声明的 probe 集中删除它并解释原因；
4. 保存 instrumented binary SHA；
5. 运行四类 readiness smoke；
6. 验证 source probe 事件归属 `rocket-clean`；
7. 生成 Timeline、whitebox signals、DUT coverage 和 validation。

Rocket 当前状态不能跳过 manifest 和闭环验证。

### F3. BOOM

当前 BOOM 四个专用探针已存在，且 reattribution smoke 表明可以纠正共享 Rocket 源码标签。仍需：

1. 创建隔离 clean/instrumented 构建；
2. 固定 BOOM submodule SHA 与 patch；
3. 确认 `boom_lsu_tlb_pmp_check`、`boom_ptw_response_ae`、`boom_ptw_ae_array`、`boom_ptw_request` 都能在正式二进制中触发；
4. 确认共享 Rocket PMP checker 的 reported DUT 不会把事件错误归属 Rocket；
5. 运行四类 readiness smoke；
6. 生成完整 manifest 和 validation。

### F4. CVA6

CVA6 目前未就绪，重点修复：

1. 不再把 `cva6_pmp_csr_state` 只插入会被构建覆盖的 `CVA6CoreBlackbox.preprocessed.sv`；
2. 优先在 CVA6 原始 RTL 的 PMP CSR 模块中建立稳定 probe anchor；
3. PTW/TLB probe 必须从原始 `ptw.sv`、`tlb.sv` 可重复生成；
4. 更新 `source_probe.py` 的 path candidates、patterns 和 instrumenter；
5. 在隔离构建目录应用 patch 后重新构建 CVA6Config；
6. 确认 direct command 保持：

```text
+permissive +verbose ... +permissive-off
```

7. 不接受只有 `status=pass`、但 `observation_valid`、`stage_verified` 和结构化事件全部为空的 PTW/PMP smoke；
8. 至少触发 PMP CSR、PTW response 和 TLB exception 三类 source probe；
9. 当前历史 smoke 的 2 个 signal 只作为可行性证据，不能直接进入正式数据；
10. 在当前 eval commit 上重新运行 readiness smoke。

### F5. XiangShan

XiangShan 当前源码树没有 `PMFUZZ_PROBE`，四个 probe 仅有 source discovery spec。必须：

1. 在 `source_probe.py` 中为以下 probe 实现实际 Chisel instrumentation template：

```text
xiangshan_pmp_checker
xiangshan_l1_tlb_exception
xiangshan_l2tlb_ptw_request
xiangshan_pmp_csr
```

2. 从固定 XiangShan SHA 创建隔离 clean/instrumented 源树；
3. 生成、审计并应用统一 patch；
4. 使用支持 goodtrap/xstrap 的配置重新构建 emu；
5. 构建不能是 `CONFIG_NO_DIFFTEST` 导致的不可识别完成版本；
6. `--whitebox-artifacts` 必须启用 commit trace；
7. 结构化解析必须区分 good trap、bad trap、cycle limit、unknown completion；
8. 性能计数器可以作为辅助白盒事件，但不能替代 PMP/PTW source probe；
9. 至少触发 `pmp-check` 和一个 PTW/TLB probe；
10. 保存 emu SHA、build config、patch SHA 和 source SHA；
11. 在当前 eval commit 上重新运行 readiness smoke。

历史 `142 PERF signals / 294 bins` 只能证明性能计数器提取链可行，不能证明 XiangShan protection source probes 已就绪。

## 9. Phase G：四 DUT readiness smoke

新增：

```text
scripts/evaluation/validate_dut_readiness.py
tests/test_dut_readiness.py
```

对每个 DUT 使用 instrumented binary 运行至少：

```text
pmp-boundary: 4 cases
sv39-ptw-pmp-matrix: 4 cases
sv39-final-pmp: 4 cases
tlb-stale-pmp 或 pmp-side-effect: 4 cases
```

每个 DUT 共至少 16 cases，使用短预算，不追求覆盖平台。

每个 DUT 必须通过以下 gate：

1. binary 存在且 SHA-256 非空；
2. source SHA、submodule SHA 和 patch SHA 完整；
3. capability 文件存在且 DUT available；
4. 不支持的 Smepmp/AD-update 等能力被正确 gate；
5. 至少一个允许访问和一个拒绝访问完成；
6. PTW case 有可识别 stage/address 证据；
7. `observation_valid` 与 `stage_verified` 按实际情况填写；
8. Timeline 单调且末点一致；
9. whitebox signals 非空；
10. 至少出现两个 security chains；
11. `dut_coverage.json` 的 by_dut 只包含或正确归属当前运行 DUT；
12. 无 orphan result、重复 case 或残留仿真进程；
13. validation error_count 为 0。

输出：

```text
/home/dubhe/wjs/pmpfuzz-eval-artifacts/readiness/<dut>/
├── manifests/
├── smoke/
├── whitebox/
├── coverage/
├── validation.json
└── DUT_READINESS_REPORT.md
```

总报告：

```text
/home/dubhe/wjs/pmpfuzz-eval-artifacts/readiness/FOUR_DUT_READINESS_REPORT.md
/home/dubhe/wjs/pmpfuzz-eval-artifacts/readiness/four_dut_readiness.json
```

任何 DUT 未通过时，不得在矩阵中标记 formal-ready。可以继续修复其他 DUT，不要伪造或删除失败证据。

## 10. Phase H：更新实验矩阵

修改：

```text
configs/evaluation/experiment_matrix.yaml
```

保留：

- E1-sem/pair/triple/pred：Rocket、BOOM，10 seeds；
- E2-WB：Rocket、BOOM，10 seeds；
- E3 baseline：Rocket、BOOM，10 seeds；
- mutants：Rocket、BOOM。

新增：

```yaml
E4-PORT:
  description: "Cross-DUT PMPFuzz portability with black-box semantics and white-box security events"
  methods: [pmpfuzz]
  variants: [full]
  duts: [rocket-clean, boom-clean, cva6-clean, xiangshan-clean]
  seeds: [11, 22, 33, 44, 55]
  coverage_modes: [semantic, pairwise, security-triples, predicates, whitebox-events]
  time_budget_hours: 1
  round_size: 32
  require_instrumented_dut: true
```

Pilot 也分为：

```text
Pilot-core: Rocket/BOOM，验证 random/guided/BB/BB+WB
Pilot-portability: CVA6/XiangShan，各 1 seed，验证 full pipeline
```

正式矩阵生成器必须拒绝：

- readiness 未通过的 DUT；
- binary SHA 为空；
- capability fingerprint 缺失；
- instrumented variant 没有 patch SHA；
- 同一 paired comparison 使用不同 DUT binary；
- 输出目录已存在。

## 11. 修复后的 Pilot 顺序

### H1. 最小三轮闭环 smoke

先用 Spike，再用 Rocket：

```text
random: 3 rounds
guided-semantic: 3 rounds
bb: 3 rounds
bb-wb: 3 rounds
```

每个 round 8 cases。验证调度、无重复、累计 Timeline 和白盒曲线，不追求统计结果。

### H2. 重跑 Pilot-A

在 Rocket/BOOM 上重跑 seed 1。原 8 个活动不覆盖、不删除。

只有以下条件成立才进入 Pilot-B：

- random/guided 选择序列确实不同；
- paired bootstrap 相同；
- guided 的 schedule 记录 coverage gain；
- BB/BB+WB 调度来源确实不同；
- 所有 Timeline 和 normalized CSV 校验通过；
- 白盒事件曲线不再恒为 0。

### H3. Pilot-B

再运行 seeds 2、3，并生成 `pilot_decision.md`。正式预算默认仍为 6h，不得因为“30 分钟覆盖率低”自动改成 24h。必须依据最后 5/10 分钟 slope 和可达目标空间判断平台期。

`pilot_decision.md` 必须明确回答：

1. 最后 5 分钟和最后 10 分钟分别新增多少 bins；
2. 最后一个新 bin 在什么时间出现；
3. 当前 profile 能否生成 denominator 中的剩余组合；
4. 换用其他已声明 profile 后能否触达这些组合；
5. 6h 预算的选择依据，而不只是最终覆盖百分比。

### H4. 时间预算与并行度冻结

Rocket 当前约 6,230 tests/h，BOOM 约 5,464 tests/h，差异约 12%。这不足以支持为两者设置不同正式时间预算。正式受控比较中：

- Rocket 和 BOOM 均保持 6h 上限；
- 同一个 DUT 上的所有方法使用相同 wall-clock、core 和 timeout 预算；
- 只有新的有效 Pilot 证据才能改变预算；
- 任何提升到 24h 的决定必须等待用户明确批准。

并行策略固定为：

- 修复后的 Pilot 先验证 8 个并行 campaign；
- 8 路连续运行无目录冲突、残留进程、内存或 I/O 问题后，才允许做一次 12 路并行 smoke；
- 正式实验默认使用 8 路并行；
- 不得直接使用全部 48 个逻辑核同时启动 48 个 campaign；
- 不同方法获得相同 core budget；
- 相同 DUT 若共享可写 build/run directory，必须串行或使用完全隔离副本。

## 12. 测试与验收命令

代码修改后依次运行：

```text
python -m unittest tests.test_closed_loop_campaign
python -m unittest tests.test_incremental_whitebox_timeline
python -m unittest tests.test_evaluation_data_contract
python -m unittest tests.test_baseline_adapters
python -m unittest tests.test_dut_readiness
python -m unittest tests.test_timeline tests.test_evaluation_scripts
python -m unittest tests.test_whitebox tests.test_source_probe tests.test_dut_coverage
python -m unittest discover -s tests
```

先在本地运行纯单元测试，再在服务器运行依赖 DUT 的 smoke。不得用 mock-only 测试代替真实四 DUT readiness。

## 13. 完成判据

只有同时满足以下条件，才允许启动正式实验：

1. 多轮 closed-loop 测试通过；
2. random 无放回且 guided 不重放已执行候选；
3. BB 与 BB+WB 的调度实现真实不同；
4. campaign Timeline 跨轮累计正确；
5. 时间包含调度和轮间开销；
6. 时间—白盒事件曲线可用；
7. 标准数据契约全部通过；
8. Cascade adapter 完成；
9. Rocket readiness 通过；
10. BOOM readiness 通过；
11. CVA6 readiness 通过；
12. XiangShan readiness 通过；
13. 四个 DUT 的 source/binary/patch/toolchain SHA 完整；
14. `experiment_matrix.yaml` 包含 `E4-PORT`；
15. 修复后的 Pilot-A、Pilot-B 均有效；
16. 没有修改 `paper/`。

最终提交：

```text
docs/EVALUATION_PIPELINE_FIX_COMPLETION_REPORT.md
/home/dubhe/wjs/pmpfuzz-eval-artifacts/readiness/FOUR_DUT_READINESS_REPORT.md
/home/dubhe/wjs/pmpfuzz-eval-artifacts/pilot/pilot_decision.md
```

每份报告必须区分：完成、失败、排除、阻塞和证据路径。不要只写“测试通过”。

## 14. 给执行代理的直接指令

从 Phase A 开始按顺序执行。先写测试并证明 RED，再修实现使其 GREEN。不要启动 Pilot-B 或任何 6h/24h campaign，直到 Section 13 的前 14 项全部满足。遇到某一个 DUT 构建阻塞时，保存完整证据并继续其他独立修复；不要修改论文、降低数据契约或把历史 smoke 冒充当前正式就绪结果。
