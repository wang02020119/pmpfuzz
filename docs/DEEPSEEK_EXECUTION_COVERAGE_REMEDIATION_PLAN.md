# PMPFuzz Execution-Qualified Coverage 第二阶段修订任务书

> 交接对象：DeepSeek V4 Pro / Claude Code  
> 项目目录：D:\c_s\wjs\riscv-pmp-fuzz  
> 修订依据：2026-07-12 静态代码审计  
> 本轮唯一目标：把黑盒覆盖率真正修正为“有效 result.json 驱动、按 DUT 能力裁剪 C_T 的 execution-qualified coverage”  
> 本轮限制：只修改覆盖率相关代码、测试和项目设计文档；禁止修改 paper/PMPFUZZ_PAPER.md 及 paper/ 目录中的任何文件；不要运行 Spike、RTL、服务器或真实硬件实验；不要提交或推送，除非用户另行授权。

## 1. 当前状态

第一阶段已经完成：

- coverage.json schema 升级到 5。
- manifest coverage 与 execution coverage 分离。
- runner 和 repro 开始记录实际 ISA 与 DUT capability。
- coverage.json 按 DUT 输出 execution coverage。
- schedule CLI 默认选择 execution coverage。
- report 标明 manifest coverage 是 generated-only。

但当前实现还不能验收，因为：

1. unexpected_trap 和 unexpected_no_trap 会被错误排除。
2. direct gap API 可以在没有 capability 时使用未裁剪分母。
3. dut=None 时部分 execution API 会合并多个 DUT。
4. 多个 run 目录会使用第一个 capability，却汇总所有 run 的结果。
5. scheduler 与 coverage.py 使用两套不同的资格判定。
6. 有 capability 但没有 result 时，分母会被错误清零。
7. missing result 和 orphan result 没有完整记录。
8. 多条新增测试只有空洞断言。

本轮不要扩展新功能，只修正上述统计语义。

## 2. 严格数学口径

对目标空间 C 和 DUT T，定义：

\[
C_T = \{c \in C \mid A(c,\mathrm{cap}_T)=\mathrm{valid}\}.
\]

其中：

- C 是 target profile 枚举的有限候选场景。
- cap_T 是该运行记录的 DUT capability。
- A 是 oracle_applicability_for_case。
- C_T 只属于一个 DUT，禁止跨 DUT 合并。

对 case c 和 result r，定义：

\[
Q(c,r)=
(A_r=\mathrm{valid})
\land (\mathrm{status}\in\{\mathrm{pass},\mathrm{fail}\})
\land (\mathrm{observation\_valid}=\mathrm{true})
\land \mathrm{Structured}(r)
\land \mathrm{PhaseValid}(c,r).
\]

PhaseValid 必须根据实际观测事件判断：

\[
\mathrm{PhaseValid}(c,r)=
\begin{cases}
r.\mathrm{phase}\in F, & c \text{ 是 stateful-final};\\
r.\mathrm{phase}=\mathrm{probe}, & r.\mathrm{event}=\mathrm{trap};\\
r.\mathrm{phase}=\mathrm{completed}, & r.\mathrm{event}=\mathrm{completion};\\
\mathrm{false}, & \text{其他情况}.
\end{cases}
\]

F 包含：

- final
- final_sentinel_initial
- final_sentinel_modified
- final_sentinel_other

由此：

- 预期 completion，实际 trap/probe：unexpected_trap，属于有效 mismatch，应计入。
- 预期 trap，实际 completion/completed：unexpected_no_trap，属于有效 mismatch，应计入。
- completion 从 setup、probe 或 warmup 返回：排除。
- trap 从 setup、completed 或 warmup 返回：排除。
- wrong_trap_stage 如果实际为 trap/probe 且结构化观测有效：计入。
- timeout、compile_fail、infra_failure、inconclusive：排除。

对 bin 类型 B：

\[
\mathrm{Cov}_B(T)=
\frac{|B(E_T)\cap B(C_T)|}{|B(C_T)|}.
\]

如果分母为 0，coverage_rate 为 null。  
如果分母大于 0 且没有合格结果，coverage_rate 必须为 0.0。

### 2.1 公式对应的代码含义

上述公式只用于锁定统计口径，不要求补充数学证明。实现时直接按以下伪代码理解：

~~~python
# 1. 为一个具体 DUT 枚举它真正适用的目标场景。
target_cases = [
    case
    for case in enumerate_target_cases(target)
    if oracle_applicability_for_case(case, dut_capability) == "valid"
]

# 2. 只保留具有有效执行证据的 case/result 对。
eligible_cases = []
for case, result in results_for_one_dut:
    qualification = qualify_result_for_coverage(case, result)
    if qualification.eligible:
        eligible_cases.append(case)

# 3. 分母来自 target_cases，分子来自 eligible_cases。
target_bins = bins(target_cases)
covered_bins = bins(eligible_cases) & target_bins

if target_bins:
    coverage_rate = len(covered_bins) / len(target_bins)
else:
    coverage_rate = None
~~~

最重要的实现约束只有三条：

1. target_cases 必须只对应一个 DUT。
2. eligible_cases 必须来自有效 result.json，不能只看 case.json。
3. 没有 result 时 eligible_cases 为空，但 target_cases 不能因此被清空。

## 3. 修改范围

重点修改：

- pmpfuzz/coverage_qualification.py
- pmpfuzz/semantic_coverage.py
- pmpfuzz/coverage.py
- pmpfuzz/triage.py
- 必要时微调 pmpfuzz/__main__.py
- tests/test_coverage_qualification.py
- tests/test_semantic_coverage.py
- tests/test_coverage.py
- tests/test_capabilities.py
- tests/test_runner.py
- tests/test_engineering_cli.py
- docs/PMPFUZZ_DESIGN.md

不要修改：

- oracle.py
- scenario.py
- emitter.py
- judgment.py
- dut_coverage.py 的白盒定义
- feedback.py
- paper/PMPFUZZ_PAPER.md
- paper/ 目录中的其他论文、模板和编译产物
- D:\riscv-blackbox
- 服务器实验目录

如果发现论文文字需要调整，只能在最终交付报告中给出“建议修改文本及位置”，不得实际编辑论文 Markdown、LaTeX、BibTeX、PDF 或模板文件。

## 4. TDD 顺序

严格执行：

1. 保存 git status 和 git diff --stat。
2. 只增加精确反例测试。
3. 运行目标测试，确认因当前业务逻辑错误而 RED。
4. 不得降低断言、删除测试或 skip。
5. 修改最小生产代码获得 GREEN。
6. 每完成一组修复就重跑对应测试。
7. 最后运行全量单元测试和静态检查。
8. 不运行真实 DUT 实验。
9. 输出逐项验收报告。

如果没有用户授权，不要 commit 或 push。RED/GREEN 的命令和结果写入最终报告。

## 5. 修复一：实际事件决定目标阶段

### 5.1 修改位置

文件：

- pmpfuzz/coverage_qualification.py

重点函数：

- result_reached_target_phase，约第 88 行
- _target_phase_label，约第 121 行
- qualify_result_for_coverage，约第 145 行
- _has_structured_observation，约第 243 行

### 5.2 必须先加入的 RED 测试

#### A. unexpected_trap 必须计入

构造：

- case.expected.allowed = True
- result.status = fail
- failure_class = unexpected_trap
- oracle_applicability = valid
- observation_valid = True
- observed_event = trap
- observed_phase = probe
- 至少存在一个 concrete observation

断言：

~~~python
self.assertTrue(qual.eligible)
self.assertTrue(qual.semantic_mismatch)
self.assertEqual(qual.target_phase, "probe")
~~~

不得把 expected.allowed 改成 False。

#### B. unexpected_no_trap 必须计入

构造：

- case.expected.allowed = False
- result.status = fail
- failure_class = unexpected_no_trap
- oracle_applicability = valid
- observation_valid = True
- observed_event = completion
- observed_phase = completed
- 至少存在一个 concrete observation

断言：

~~~python
self.assertTrue(qual.eligible)
self.assertTrue(qual.semantic_mismatch)
self.assertEqual(qual.target_phase, "completed")
~~~

不得把 expected.allowed 改成 True。

#### C. trap 从错误阶段返回必须排除

构造 observed_event=trap、observed_phase=setup，其他条件均有效。

断言：

~~~python
self.assertFalse(qual.eligible)
self.assertEqual(qual.reason, "wrong_phase")
~~~

#### D. completion 从错误阶段返回必须排除

构造 observed_event=completion、observed_phase=probe，其他条件均有效。

断言同上。

#### E. stateful final 四种阶段全部接受

分别测试：

- final
- final_sentinel_initial
- final_sentinel_modified
- final_sentinel_other

case.expected.stage 必须为 stateful_final。

#### F. 未知或缺失 observed_event 必须排除

即使 observed_phase 和 observation_valid 存在，普通测试的 observed_event 缺失或未知也不得计入。

reason 选择一个稳定值：

- missing_structured_observation
- unknown_observation_event

选择后在代码、测试和报告中保持一致。

### 5.3 生产代码改法

result_reached_target_phase 应：

1. stateful_final 先检查 final phase 集合。
2. 普通测试读取 observed_event。
3. trap 只接受 probe。
4. completion 只接受 completed。
5. 其他返回 False。

_target_phase_label 改为同时接收 case 和 result：

~~~python
def _target_phase_label(case, result) -> str | None:
    ...
~~~

普通测试不要再使用 expected.allowed 选择 phase。

### 5.4 structured observation

至少要求：

- observed_event 属于 trap/completion
- observed_phase 非空
- observed_tohost、observed_mcause、observed_mtval 中至少一个非 None

数值 0 合法，禁止用简单 truthiness 判断。

## 6. 修复二：coverage 与 scheduler 统一资格判定

### 6.1 当前问题

pmpfuzz/semantic_coverage.py 的 _observed_execution_bins 手工重复条件，但遗漏 structured observation 检查。

### 6.2 必须新增的 RED 测试

#### G. 缺 concrete observation 时两边都排除

构造：

- status = pass
- oracle_applicability = valid
- observation_valid = True
- observed_event = completion
- observed_phase = completed
- observed_tohost、observed_mcause、observed_mtval 全部为 None

断言：

- coverage.py eligible_results 为 0。
- execution gap 不包含该 case bins。
- scheduler eligible_results 为 0。
- 排除 reason 一致。

#### H. coverage 与 gap 使用相同 eligible case 集

一个 run 中放置：

- 合法 pass
- unexpected_trap
- timeout
- 缺失结构化观测
- wrong phase

比较：

- coverage_from_run 的 execution covered bins
- coverage_gap_from_runs 的 execution observed/covered bins

断言集合完全相等，不只比较数量。

### 6.3 生产代码改法

删除 _observed_execution_bins 中手写条件，统一改为：

~~~python
qual = qualify_result_for_coverage(case, result)
if qual.eligible:
    observed.update(bin_fn(case))
~~~

coverage.py、semantic_coverage.py、schedule qualification 和 report 必须以 qualify_result_for_coverage 为唯一事实来源。

## 7. 修复三：execution API fail closed

### 7.1 当前问题

直接调用以下函数时仍可出现 capability=None 或 dut=None：

- coverage_gap_from_runs
- combination_gap_from_runs
- predicate_gap_from_runs

### 7.2 新增统一上下文

在 semantic_coverage.py 中建议新增：

~~~python
@dataclass(frozen=True)
class ExecutionCoverageContext:
    dut: str
    capability: dict[str, Any]
    capability_fingerprint: str
    run_dirs: tuple[Path, ...]
~~~

新增：

~~~python
def resolve_execution_coverage_context(
    run_dirs: Iterable[Path],
    *,
    dut: str | None,
) -> ExecutionCoverageContext:
    ...
~~~

### 7.3 DUT 解析规则

显式提供 dut 时：

- 每个 run_dir 都必须有 dut_capabilities.json。
- 每个 capability map 都必须包含该 dut。
- 缺失时 ValueError，消息包含 run_dir 和 dut。

未提供 dut 时：

- 只有每个 run 都恰好包含同一个单一 DUT 才能自动推断。
- 任一 run 包含多个 DUT，要求 --dut。
- 不同 run 的唯一 DUT 名称不同，也报错。
- 禁止跨 DUT合并。

### 7.4 coverage capability fingerprint

不要对完整 capability dict 哈希。使用只影响 C_T 的投影：

~~~python
def capability_coverage_projection(capability):
    return {
        "schema_version": capability.get("schema_version"),
        "dut": capability.get("dut"),
        "available": capability.get("available"),
        "isa": capability.get("isa"),
        "supported_capabilities": capability.get("supported_capabilities") or {},
        "ad_update_mode": capability.get("ad_update_mode"),
        "oracle_applicability": capability.get("oracle_applicability"),
    }
~~~

fingerprint 对该投影做稳定 JSON 哈希。

不要纳入：

- 二进制绝对路径
- notes
- 运行目录
- 时间戳
- 诊断描述

### 7.5 多运行目录规则

采用严格一致策略：

- 每个 run 都必须有 capability。
- 所选 DUT 的 coverage fingerprint 必须一致。
- 一致才允许汇总。
- 不一致立即报错，列出 run_dir、ISA 和 fingerprint。
- 禁止取第一个 capability。
- 禁止自行使用 union 或 intersection。

### 7.6 必须新增的 RED 测试

#### I. direct gap 缺 capability 文件报错

分别覆盖 semantic、pairwise、security-triples 和 predicates。

#### J. direct gap 多 DUT且未指定 dut 报错

不能只测试 build_schedule。

#### K. 两个 run 中一个缺 capability 报错

即使另一个 run 有 capability，也不能继续。

#### L. 两个 run capability 不同报错

例如：

- run A: rv64gc，Smepmp false
- run B: rv64gc_smepmp，Smepmp true

错误信息应包含 capability mismatch。

#### M. 两个一致 capability 的 run 正确汇总

两个 run 各有一个 eligible result。

断言：

- eligible_results == 2
- observed bins 是两个 run 的并集
- fingerprint 唯一且稳定

### 7.7 gap API 修改

execution 模式：

1. 没有内部 context 时自行调用 resolver。
2. 禁止 capability=None 继续。
3. 禁止 dut=None 合并全部结果。
4. 所有 run 必须通过 context 校验。

manifest 模式保留旧行为，不要求 capability。

target_* 纯函数可以接收 capability，但公开 execution gap API 不能让该参数成为绕过能力文件校验的后门。

## 8. 修复四：完整汇总所有 run 的 qualification

### 8.1 当前问题

build_schedule 当前只调用：

~~~python
qualify_all_results(run_dirs[0])
~~~

而 gap 会遍历全部 run_dirs。

### 8.2 新增统一证据收集函数

在 coverage_qualification.py 中建议新增：

~~~python
@dataclass
class ExecutionEvidence:
    dut: str
    eligible_cases: list[dict[str, Any]]
    summary: QualificationSummary
~~~

新增：

~~~python
def collect_execution_evidence(
    run_dirs: Iterable[Path],
    *,
    dut: str,
) -> ExecutionEvidence:
    ...
~~~

要求：

- 遍历全部 run_dirs。
- 只读取指定 DUT。
- 每个 case/result 调用统一 qualifier。
- 汇总所有 run 的统计。
- 返回 eligible cases，供所有 bin 类型使用。
- 记录 missing result 和 orphan result。

coverage.py 可使用单 run 包装，但不要复制判定逻辑。

## 9. 修复五：missing 与 orphan 统计

### 9.1 qualification schema

建议：

~~~json
{
  "total_cases": 24,
  "total_results": 22,
  "eligible_results": 18,
  "excluded_results": 4,
  "missing_results": 2,
  "orphan_results": 0,
  "valid_mismatches": 1,
  "excluded_by_reason": {
    "status_timeout": 2,
    "wrong_phase": 1,
    "missing_structured_observation": 1
  }
}
~~~

不变量：

~~~text
total_results == eligible_results + excluded_results
valid_mismatches <= eligible_results
missing_results >= 0
orphan_results <= excluded_results
~~~

定义：

- total_cases：所选 DUT 对应 run 的生成 case 数。
- total_results：声称属于所选 DUT 的 result.json 数。
- eligible_results：满足 Q 的结果数。
- excluded_results：不满足 Q 或找不到 case 的结果数。
- missing_results：没有所选 DUT result 的 case 数。
- orphan_results：找不到对应 case 的 result 数。

orphan result：

- 计入 total_results。
- 计入 excluded_results。
- 计入 orphan_results。
- excluded_by_reason["missing_case"] 增加。

missing result：

- 不进入 total_results。
- 单独进入 missing_results。
- 在 report 中显示。
- 不进入 coverage 分子。

### 9.2 必须新增的 RED 测试

#### N. case 无 result

断言：

- total_cases == 1
- total_results == 0
- eligible_results == 0
- missing_results == 1

#### O. result 无 case

断言：

- total_results == 1
- excluded_results == 1
- orphan_results == 1
- missing_case reason == 1

#### P. 多 DUT result 不串线

同一 case 有 spike 和 rocket-clean result。分别收集时，每个 summary 只包含自己的 DUT。

## 10. 修复六：无 result 时仍保留 C_T 分母

### 10.1 当前错误

coverage.py 在 qs is None 时直接返回四个空 section，得到 0/0。

### 10.2 正确顺序

对每个 available DUT：

1. 先用 capability 枚举 C_T。
2. 生成四类 target bins。
3. 再收集 result。
4. 没有 result 时 observed bins 为空。
5. covered 为 0。
6. missing 等于 total target。
7. total 大于 0时 rate 为 0.0。
8. 只有 C_T 真为空时 rate 才为 null。

删除 qs is None 时直接调用 _empty_coverage_section 的分支。

### 10.3 必须新增的 RED 测试

#### Q. 有 capability、无 result

使用支持 PMP 的 available DUT。

每种适用覆盖率断言：

~~~python
self.assertGreater(section["total_target_bins"], 0)
self.assertEqual(section["covered_target_bins"], 0)
self.assertEqual(
    section["missing_target_bins"],
    section["total_target_bins"],
)
self.assertEqual(section["coverage_rate"], 0.0)
~~~

禁止使用 if total == 0 才执行断言。

#### R. 真实零分母

构造 available capability，但 supported_capabilities.pmp=False。

断言：

~~~python
self.assertEqual(section["total_target_bins"], 0)
self.assertIsNone(section["coverage_rate"])
~~~

## 11. 修复七：替换空洞能力测试

### 11.1 Smepmp 排除

删除这类无效断言：

~~~python
self.assertGreaterEqual(total_target_bins, 0)
~~~

改为比较 rv64gc 与 rv64gc_smepmp：

~~~python
self.assertFalse(
    any("profile=smepmp-" in item for item in no_smepmp_bins)
)
self.assertGreater(
    len(with_smepmp_bins),
    len(no_smepmp_bins),
)
~~~

### 11.2 Spike 与 Rocket 分母

如果测试名称声称分母不同，必须：

~~~python
self.assertNotEqual(
    spike["semantic"]["total_target_bins"],
    rocket["semantic"]["total_target_bins"],
)
~~~

如果 semantic 分母恰好相同，选择能够体现能力差异的 target 或 bin 类型，不能把断言降级为 is not None。

### 11.3 fingerprint

增加：

- path/notes 不同但 coverage capability 相同时，fingerprint 相同。
- ISA 或 supported_capabilities 不同时，fingerprint 不同。

## 12. 修复八：真正测试 runner 与 repro

### 12.1 runner

当前 test_runner 只是构造 RunnerConfig。

使用 unittest.mock：

- patch pmpfuzz.runner.capability_for_dut
- patch pmpfuzz.runner.make_dut
- 使用 count=0，避免编译和 DUT 执行
- 调用 run_campaign(config)

对 Spike 断言：

~~~python
capability_for_dut.assert_called_once_with(
    "spike",
    path=config.spike,
    isa=config.isa,
)
~~~

同时检查 run.json 和 dut_capabilities.json。

### 12.2 repro

当前 test_coverage 手工写元数据再读取，不是真正测试。

替换为 main(["repro", ...]) 或 _cmd_repro 的单元测试：

- 临时 case.json
- patch 编译 subprocess
- patch make_dut
- patch DUT run result
- 不运行真实编译器或 DUT

断言：

- run.json.mode == repro
- run.json.isa == rv64gc
- capability schema version == 3
- Spike capability 调用收到 args.spike 与实际 ISA
- 多 DUT capability 条目完整

### 12.3 CLI

使用 build_parser().parse_args 断言：

- schedule 默认 coverage_basis == execution
- 接受 --coverage-basis manifest
- 接受 --dut spike
- run 已支持 --no-smepmp，不要重复注册

## 13. 重构 build_schedule 与 write_schedule

当前 write_schedule 计算一次 gap，build_schedule 又计算一次，可能产生分叉。

改为：

1. build_schedule 只解析一次 ExecutionCoverageContext。
2. 同一 context 用于分母、observed bins、missing bins、candidate filtering 和 qualification。
3. build_schedule 返回 schedule 与完整 gap，或者在内部保存 gap。
4. write_schedule 只写文件，不重新解析 capability。
5. coverage_gap.json 与 schedule.json 必须记录相同：
   - coverage_basis
   - dut
   - capability_fingerprint
   - eligible_results
   - excluded_results
   - missing_results

新增测试比较两个 JSON 的上述字段。

## 14. coverage.json 最终不变量

顶层继续保留：

~~~json
{
  "schema_version": 5,
  "legacy_top_level_basis": "generated_manifest"
}
~~~

execution coverage 按 DUT 分开。

每种覆盖率：

~~~text
0 <= covered_target_bins <= total_target_bins
missing_target_bins == total_target_bins - covered_target_bins
~~~

total_target_bins > 0 时：

~~~text
coverage_rate == round(covered_target_bins / total_target_bins, 6)
~~~

total_target_bins == 0 时：

~~~text
coverage_rate is null
~~~

qualification：

~~~text
total_results == eligible_results + excluded_results
valid_mismatches <= eligible_results
~~~

禁止：

- 跨 DUT execution percentage
- 缺 capability 回退 manifest
- capability=None 枚举全局分母
- 无 result 时清空 C_T
- 用 case.json 数量作为 execution numerator

## 15. report 修订

triage.py 增加：

- Total generated cases
- Total result records
- Eligible results
- Excluded results
- Missing results
- Orphan results
- Valid mismatches
- Excluded by reason
- Per-DUT denominator 与 coverage rate

保留 Manifest Coverage，并恢复第一阶段删除的 manifest pairwise 和 predicate 参考信息。明确标记 generated-only 即可，不要丢失旧报告能力。

建议结构：

~~~text
## Manifest Coverage
### Semantic
### Pairwise
### Security-Relevant Triples
### Contract Predicates

## Execution-Qualified Coverage
### DUT: spike
~~~

execution scheduler 命令包含：

~~~text
--coverage-basis execution --dut <dut>
~~~

manifest scheduler 命令包含：

~~~text
--coverage-basis manifest
~~~

## 16. 论文处理：只提建议，不修改文件

当前 paper/PMPFUZZ_PAPER.md 第 6.4 节仍描述 aggregator 只统计 generated manifests，并保留 IMPLEMENTATION NEEDED。本轮禁止修改该文件。

### 16.1 单元测试通过后应在报告中提出的建议

只在最终交付报告中建议将实现描述更新为：

- 同时报告 manifest 与 execution-qualified coverage。
- execution coverage 只接收 oracle-valid、observation-valid、结构化、实际事件阶段正确的结果。
- unexpected_trap 和 unexpected_no_trap 属于有效 mismatch。
- C_T 按 DUT capability 独立裁剪。
- 不同 coverage fingerprint 的运行不合并。

### 16.2 本轮没有真实实验时的建议

只在最终报告中建议未来将 IMPLEMENTATION NEEDED 改为：

~~~text
[EVIDENCE NEEDED] Validate execution-qualified, capability-scoped coverage on the final per-DUT campaigns before reporting rates in Section 7.
~~~

第 7 章仍不能报告正式执行覆盖率数字。

即：

- 单元测试通过：机制实现完成。
- 真实运行验证完成：实验取证完成。
- 本轮禁止跨过第二个门槛。

DeepSeek 不得自行执行上述论文修改。是否更新论文由用户在后续会话中决定。

## 17. RED 命令

只修改测试后执行：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
$args = @(
    '-m'
    'unittest'
    'tests.test_coverage_qualification'
    'tests.test_semantic_coverage'
    'tests.test_coverage'
    'tests.test_capabilities'
    'tests.test_runner'
    'tests.test_engineering_cli'
)

& $python @args
if ($LASTEXITCODE -eq 0) {
    throw 'RED 阶段失败：新增反例测试不应在旧实现上全部通过'
}
~~~

有效 RED 应至少包括：

- unexpected_trap eligible
- unexpected_no_trap eligible
- no-result denominator
- direct gap missing capability
- inconsistent multi-run capability
- full multi-run qualification
- structured observation consistency
- runner metadata mock
- repro metadata mock

syntax error、fixture 错误、导入错误或 mock 路径错误不算有效 RED。

## 18. GREEN 顺序

1. coverage_qualification.py phase semantics。
2. evidence collection 与 summary。
3. semantic_coverage.py 统一调用 qualifier。
4. ExecutionCoverageContext。
5. direct gap fail closed。
6. 多 run fingerprint 一致性。
7. build_schedule/write_schedule 单一 context。
8. coverage.py 无结果分母。
9. coverage.py 与 scheduler bins 一致性。
10. triage.py 报告。
11. runner/repro 测试补强。
12. 只更新项目设计文档；不得修改 paper/ 目录。论文建议写入最终报告。

每完成一组就重新运行对应测试。

## 19. 测试命令

目标测试：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
$args = @(
    '-m'
    'unittest'
    'tests.test_coverage_qualification'
    'tests.test_semantic_coverage'
    'tests.test_coverage'
    'tests.test_capabilities'
    'tests.test_runner'
    'tests.test_engineering_cli'
)

& $python @args
if ($LASTEXITCODE -ne 0) {
    throw "Targeted tests failed with exit code $LASTEXITCODE"
}
~~~

全量测试：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
$args = @('-m', 'unittest', 'discover', '-s', 'tests')

& $python @args
if ($LASTEXITCODE -ne 0) {
    throw "Full test suite failed with exit code $LASTEXITCODE"
}
~~~

覆盖率：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
& $python @('-m', 'coverage', 'run', '-m', 'unittest', 'discover', '-s', 'tests')
if ($LASTEXITCODE -ne 0) {
    throw "Coverage test run failed with exit code $LASTEXITCODE"
}

& $python @('-m', 'coverage', 'report', '-m')
if ($LASTEXITCODE -ne 0) {
    throw "Coverage report failed with exit code $LASTEXITCODE"
}
~~~

本轮不运行：

- pmpfuzz run
- 真实 repro
- Spike
- RTL simulator
- 服务器 smoke
- 真实硬件
- 第 7 章实验

## 20. 静态检查

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$git = 'git'
& $git @('diff', '--check')
if ($LASTEXITCODE -ne 0) {
    throw "git diff --check failed with exit code $LASTEXITCODE"
}

& $git @('status', '--short')
& $git @('diff', '--stat')
~~~

人工确认：

- 未修改 oracle.py、scenario.py、emitter.py。
- 未修改 D:\riscv-blackbox。
- 未生成实验目录。
- 未删除 manifest coverage。
- 未增加跨 DUT execution rate。
- 未声称真实实验完成。
- 未修改 paper/PMPFUZZ_PAPER.md 或 paper/ 目录中的任何文件。
- 未 push。

## 21. 禁止的伪修复

禁止：

1. 把 unexpected_trap 测试改成 expected.allowed=False。
2. 把 unexpected_no_trap 测试改成 expected.allowed=True。
3. 用 stage_verified 作为统一资格门槛。
4. 删除 structured observation 检查。
5. capability=None 时假定全部支持。
6. 多 run 只取第一个 capability。
7. 不检查 fingerprint 就汇总。
8. 无 result 时返回 0/0。
9. 用 if total == 0 让测试断言变成可选。
10. 用 total >= 0 验证能力分母。
11. 手工写文件再声称测试了 runner/repro。
12. 删除 manifest 统计。
13. 修改任何 paper/ 文件，或删除论文警告并声称第 7 章已有数据。
14. 修改 oracle、generator 或 emitter 语义。

## 22. 最终验收清单

- [ ] unexpected_trap 是 eligible valid mismatch。
- [ ] unexpected_no_trap 是 eligible valid mismatch。
- [ ] 真正 wrong phase 被排除。
- [ ] stateful final 四类阶段正确。
- [ ] coverage 与 scheduler 只使用统一 qualifier。
- [ ] 缺 structured observation 两边都排除。
- [ ] direct semantic gap 缺 capability 时 fail closed。
- [ ] direct combo gap 缺 capability 时 fail closed。
- [ ] direct predicate gap 缺 capability 时 fail closed。
- [ ] 多 DUT 未指定 dut 时报错。
- [ ] 每个输入 run 都有 capability。
- [ ] 多 run capability 不一致时报错。
- [ ] 多 run capability 一致时汇总全部运行。
- [ ] fingerprint 不受 path/notes 影响。
- [ ] fingerprint 随 ISA/能力变化。
- [ ] missing result 单独统计。
- [ ] orphan result 排除并报告。
- [ ] 无 result 但 C_T 非空时为 0/N 和 0.0。
- [ ] C_T 真为空时为 0/0 和 null。
- [ ] Smepmp 分母差异有精确断言。
- [ ] Spike 与 Rocket 分母差异有精确断言。
- [ ] coverage 与 gap eligible bins 一致。
- [ ] schedule 与 gap 使用同一 fingerprint 和资格统计。
- [ ] runner 测试验证真实 capability 调用。
- [ ] repro 测试调用真实命令路径并 mock 外部执行。
- [ ] 目标测试通过。
- [ ] 全量测试通过。
- [ ] git diff --check 通过。
- [ ] 未运行具体 DUT 实验。
- [ ] paper/ 目录没有任何新增或修改。
- [ ] 第 7 章未报告未经实测的正式覆盖率。

## 23. 最终交付报告

DeepSeek 必须输出：

1. 修改文件列表。
2. 每个高优先级问题的修复位置。
3. 新 PhaseValid 规则。
4. ExecutionCoverageContext 的 DUT 与多 run 规则。
5. capability projection 字段。
6. qualification schema 与不变量。
7. RED 失败测试名称。
8. GREEN 目标测试结果。
9. 全量测试结果。
10. coverage 与 scheduler 一致性结果。
11. 未运行真实实验的声明。
12. 明确声明 paper/ 目录未被修改，并单独列出论文建议文本。
13. git status --short。
14. git diff --stat。
15. 尚未解决的问题。

不要只回复“已修复”，必须逐项对应第 22 节。
