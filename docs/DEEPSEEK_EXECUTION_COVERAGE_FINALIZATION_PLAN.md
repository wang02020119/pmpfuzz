# PMPFuzz Execution-Qualified Coverage 最终收尾计划

> 交接对象：DeepSeek V4 Pro / Claude Code  
> 项目目录：D:\c_s\wjs\riscv-pmp-fuzz  
> 性质：第二版静态复审后的定点修复  
> 唯一目标：修完 execution-qualified coverage 剩余的一致性、记账和测试缺口  
> 严格禁止：不得修改 paper/PMPFUZZ_PAPER.md，不得修改 paper/ 目录中的任何文件，不得运行 Spike、RTL、服务器或真实硬件实验，不得 push。

## 1. 不要重复已经完成的工作

以下内容第二版已经正确实现，本轮不要重写：

- observed_event=trap 使用 probe 阶段。
- observed_event=completion 使用 completed 阶段。
- unexpected_trap 可以作为有效 mismatch。
- unexpected_no_trap 可以作为有效 mismatch。
- stateful final 接受四种 final phase。
- structured observation 检查。
- direct execution gap 缺 capability 时 fail closed。
- capability 文件记录 ISA。
- coverage.json schema version 5。
- manifest coverage 与 execution coverage 分离。
- 有 capability、无 result 时保留目标分母。

本轮只处理后文列出的剩余问题。

## 2. 修改范围

允许修改：

- pmpfuzz/coverage_qualification.py
- pmpfuzz/semantic_coverage.py
- pmpfuzz/coverage.py
- pmpfuzz/capabilities.py
- pmpfuzz/triage.py
- 必要时修改 pmpfuzz/__main__.py
- tests/test_coverage_qualification.py
- tests/test_semantic_coverage.py
- tests/test_coverage.py
- tests/test_capabilities.py
- tests/test_runner.py
- tests/test_engineering_cli.py
- tests/test_contract_predicates.py

禁止修改：

- paper/PMPFUZZ_PAPER.md
- paper/ 目录全部文件
- oracle.py
- scenario.py
- emitter.py
- judgment.py
- D:\riscv-blackbox
- 服务器目录
- 任何实验结果

如果认为论文需要调整，只能在最终报告中给出建议，不能实际编辑。

## 3. 执行方式

严格按以下五组逐组 TDD：

1. 先写本组精确测试。
2. 运行本组测试并确认因指定缺陷而 RED。
3. 修改最少生产代码。
4. 重跑本组测试确认 GREEN。
5. 再进入下一组。
6. 五组完成后运行目标测试和全量测试。
7. 不运行真实 DUT 实验。

禁止一次性改完全部生产代码后再补测试。

## 4. 第一组：修复 execution gap 的零分母

### 4.1 当前错误

以下 execution gap 在目标集合为空时仍返回 1.0：

- semantic_coverage.py 的 coverage_gap_from_runs，当前约第 616 行
- combination_gap_from_runs，当前约第 678 行
- predicate_gap_from_runs，当前约第 731 行

这会把“不存在适用目标”写成“100% 覆盖”。

### 4.2 正确规则

对 execution coverage：

~~~python
if total_target_bins == 0:
    coverage_rate = None
else:
    coverage_rate = round(covered_target_bins / total_target_bins, 6)
~~~

manifest coverage 可以保留旧兼容行为；不要无意改变旧 manifest schema。

建议增加统一 helper：

~~~python
def _gap_coverage_rate(
    covered: int,
    total: int,
    *,
    coverage_basis: str,
) -> float | None:
    if total:
        return round(covered / total, 6)
    if coverage_basis == "execution":
        return None
    return 1.0
~~~

semantic、pairwise、security-triples、predicates 全部调用该 helper。

### 4.3 必须先加入的 RED 测试

构造：

- available=True
- supported_capabilities.pmp=False
- capability 文件存在
- coverage_basis="execution"
- dut="spike"

分别调用：

- coverage_gap_from_runs
- combination_gap_from_runs，coverage_mode="pairwise"
- combination_gap_from_runs，coverage_mode="security-triples"
- predicate_gap_from_runs

精确断言：

~~~python
self.assertEqual(gap["total_target_bins"], 0)
self.assertIsNone(gap["coverage_rate"])
~~~

组合和 predicates 使用各自字段名。

再加一个 manifest 兼容测试，确认是否保留原约定的 1.0。不要把 execution 与 manifest 混成一个规则。

## 5. 第二组：让 coverage.py 真正使用统一 evidence collector

### 5.1 当前错误

coverage.py 当前仍调用：

~~~python
all_quals = qualify_all_results(run_dir)
~~~

因此新的 collect_execution_evidence 没有进入 coverage.json 主路径，导致：

- missing_results 仍可能为 0。
- orphan_results 仍可能为 0。
- report 虽显示字段，但数字不可靠。
- coverage.py 与 scheduler 的 qualification 来源不同。

### 5.2 先修 collect_execution_evidence 的 DUT 过滤顺序

当前逻辑在确认 result 属于目标 DUT 之前执行：

~~~python
cases_with_result.add(case_name)
~~~

这是错误的。

正确方式：

~~~python
matching_results = [
    result
    for result in result_list
    if str(result.get("dut") or "") == dut
]

if matching_results:
    cases_with_result.add(case_name)

for result in matching_results:
    ...
~~~

这样：

- case 只有 Rocket result 时，统计 Spike 必须 missing_results += 1。
- 统计 Rocket 时不 missing。
- 其他 DUT result 不得影响目标 DUT。

### 5.3 coverage.py 重构方法

在 _build_execution_coverage 中，对每个 available DUT：

1. 先枚举 capability-scoped target candidates。
2. 调用：

~~~python
evidence = collect_execution_evidence([run_dir], dut=dut_name)
~~~

3. qualification 直接来自 evidence.summary。
4. eligible_cases 直接使用 evidence.eligible_cases。
5. 不再调用 qualify_all_results。
6. 不再手工遍历 results_by_case 重新筛 eligible。
7. 删除 qs is None 的特殊统计分支；无 result 时 summary 自然全零，但 target candidates 仍然存在。

建议结构：

~~~python
candidates = _target_candidates(
    target=target,
    include_experimental=False,
    seed=20260628,
    capability=capability,
)

evidence = collect_execution_evidence([run_dir], dut=dut_name)
summary = evidence.summary
eligible_cases = evidence.eligible_cases

qualification = {
    "total_results": summary.total_results,
    "eligible_results": summary.eligible_results,
    "excluded_results": summary.excluded_results,
    "missing_results": summary.missing_results,
    "orphan_results": summary.orphan_results,
    "valid_mismatches": summary.valid_mismatches,
    "excluded_by_reason": dict(summary.excluded_by_reason),
}
~~~

### 5.4 qualification 不变量

必须满足：

~~~text
total_results == eligible_results + excluded_results
valid_mismatches <= eligible_results
missing_results >= 0
orphan_results <= excluded_results
~~~

### 5.5 必须先加入的 RED 测试

#### A. case 无 result，coverage.json 必须报告 missing

写一个真实 case.json，不写目标 DUT result。

断言：

~~~python
qual = coverage["execution_coverage"]["by_dut"]["spike"]["qualification"]
self.assertEqual(qual["total_results"], 0)
self.assertEqual(qual["eligible_results"], 0)
self.assertEqual(qual["missing_results"], 1)
~~~

同时断言 coverage 为 0/N，而不是 0/0：

~~~python
self.assertGreater(section["total_target_bins"], 0)
self.assertEqual(section["coverage_rate"], 0.0)
~~~

#### B. orphan result 必须进入 coverage.json

只写 spike result.json，不写对应 case.json。

断言：

~~~python
self.assertEqual(qual["total_results"], 1)
self.assertEqual(qual["excluded_results"], 1)
self.assertEqual(qual["orphan_results"], 1)
self.assertEqual(qual["excluded_by_reason"]["missing_case"], 1)
~~~

如果 coverage.py 无法根据 capability map 确定目标，仍应为 capability map 中的 Spike 生成 qualification。

#### C. 多 DUT missing 不串线

一个 case 只有 rocket-clean result，没有 spike result。

断言：

~~~python
self.assertEqual(spike_qual["missing_results"], 1)
self.assertEqual(rocket_qual["missing_results"], 0)
self.assertEqual(spike_qual["total_results"], 0)
self.assertEqual(rocket_qual["total_results"], 1)
~~~

#### D. report 显示真实数字

构造 case 无 Spike result，调用 write_report。

必须无条件断言报告包含：

~~~text
Missing results: 1
~~~

不能只断言存在 “Missing results” 字样。

## 6. 第三组：收紧多运行目录与 fingerprint

### 6.1 修复 DUT 自动推断状态机

当前 resolver 在处理第一个单 DUT run 后把 resolved_dut 设为非空，后续 run 会走“显式 DUT”分支。

这会错误接受：

- run1 只有 spike
- run2 同时有 spike 和 rocket-clean
- 用户没有指定 --dut

正确方式是保留原始参数：

~~~python
requested_dut = dut
capability_maps = load_all_maps(run_dirs)

if requested_dut is None:
    for run_dir, cap_map in capability_maps:
        if len(cap_map) != 1:
            raise ValueError("pass --dut")
    inferred_names = {
        next(iter(cap_map))
        for cap_map in capability_maps
    }
    if len(inferred_names) != 1:
        raise ValueError("different single DUTs")
    resolved_dut = next(iter(inferred_names))
else:
    resolved_dut = requested_dut
    for run_dir, cap_map in capability_maps:
        if resolved_dut not in cap_map:
            raise ValueError(...)
~~~

不要在读取循环中把“自动推断模式”变成“显式模式”。

### 6.2 public gap 必须先固化 run_dirs

各 public gap 接受 Iterable。如果传入 generator，resolver 会消耗它，后面的遍历可能为空。

每个 public entry 一开始执行：

~~~python
run_dirs = tuple(Path(item) for item in run_dirs)
~~~

然后将同一个 tuple 传给 resolver 和后续逻辑。

适用于：

- coverage_gap_from_runs
- combination_gap_from_runs
- predicate_gap_from_runs
- build_schedule
- write_schedule

### 6.3 精简 coverage fingerprint

capability_coverage_projection 只保留真正影响 C_T 的字段：

~~~python
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

移除整个 smepmp 诊断子对象，包括：

- csr_access
- mml/mmwp 探测描述
- warl_behavior
- probe_status

是否支持 Smepmp 已由 supported_capabilities 反映。诊断文本变化不应改变 C_T fingerprint。

### 6.4 必须先加入的 RED 测试

#### E. 第一项单 DUT、第二项多 DUT，未指定 dut 必须报错

run1 capability map：

~~~json
{"duts": {"spike": {}}}
~~~

run2：

~~~json
{"duts": {"spike": {}, "rocket-clean": {}}}
~~~

调用 direct execution gap，dut=None。

断言 ValueError 且消息包含 pass --dut。

#### F. 显式 dut 可以处理第二项多 DUT

相同两个 run，显式 dut="spike"，且 Spike fingerprint 一致。

断言正常返回，并且只统计 Spike result。

#### G. generator 类型 run_dirs 不得丢失

~~~python
run_iter = (path for path in [run1, run2])
gap = coverage_gap_from_runs(
    run_iter,
    coverage_basis="execution",
    dut="spike",
)
~~~

断言 run_dirs 长度为 2，eligible bins 包含两个运行。

#### H. probe 诊断变化不改变 fingerprint

复制 capability，只修改：

- smepmp.warl_behavior
- smepmp.probe_status
- notes
- path

保持 ISA、supported_capabilities、ad_update_mode 和 oracle_applicability 不变。

断言 fingerprint 相同。

## 7. 第四组：coverage_gap.json 与 schedule.json 使用同一次计算

### 7.1 当前问题

write_schedule 当前：

1. 先独立计算 gap。
2. 再调用 build_schedule。
3. build_schedule 再次解析 context、计算 gap 和 qualification。

这会造成重复计算，两个文件也没有完整共享：

- coverage_basis
- dut
- capability_fingerprint
- qualification

### 7.2 推荐重构

新增内部函数：

~~~python
def _build_schedule_and_gap(
    run_dirs,
    *,
    target,
    max_cases,
    seed,
    include_experimental,
    coverage_mode,
    coverage_basis,
    dut,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ...
~~~

它只做一次：

1. 固化 run_dirs。
2. 解析 ExecutionCoverageContext。
3. 计算 target bins。
4. 收集合格 evidence。
5. 生成 gap。
6. 生成 schedule。
7. 返回二者。

外部 API：

~~~python
def build_schedule(...):
    schedule, _ = _build_schedule_and_gap(...)
    return schedule

def write_schedule(...):
    schedule, gap = _build_schedule_and_gap(...)
    write gap
    write schedule
    return schedule_path
~~~

不要让 write_schedule 再次调用 build_schedule。

### 7.3 gap 必须记录的元数据

execution 模式的 semantic、combo、predicate gap 至少加入：

~~~json
{
  "coverage_basis": "execution",
  "dut": "spike",
  "capability_fingerprint": "...",
  "qualification": {
    "total_results": 2,
    "eligible_results": 2,
    "excluded_results": 0,
    "missing_results": 0,
    "orphan_results": 0,
    "valid_mismatches": 0,
    "excluded_by_reason": {}
  }
}
~~~

manifest 模式也写：

~~~json
"coverage_basis": "manifest"
~~~

但 dut、fingerprint、qualification 可以为 null 或省略，选择一种并测试固定。

### 7.4 必须先加入的 RED 测试

调用 write_schedule 后读取：

- coverage_gap.json
- schedule.json

精确断言：

~~~python
self.assertEqual(gap["coverage_basis"], schedule["coverage_basis"])
self.assertEqual(gap["dut"], schedule["dut"])
self.assertEqual(
    gap["capability_fingerprint"],
    schedule["capability_fingerprint"],
)
self.assertEqual(gap["qualification"], schedule["qualification"])
~~~

还要断言零分母 execution gap 的 rate 为 None。

## 8. 第五组：修掉仍可假通过的测试

### 8.1 coverage/gap 一致性测试中的 case 名覆盖

当前五个 case 很可能都叫 scenario_0000，写入 dict 后只剩一个。

修复方法：

1. 生成 case。
2. 在生成 result 前为 case 设置唯一 name。
3. 再调用 result_to_dict，确保 result.name 与 case.name 一致。

辅助函数建议：

~~~python
def _rename_case(case, unique_name):
    case = copy.deepcopy(case)
    case["name"] = unique_name
    return case
~~~

示例：

~~~python
case1 = _rename_case(_make_case(...), "legal_pass")
result1 = _make_result(case1, ...)

case2 = _rename_case(_make_case(...), "unexpected_trap")
result2 = _make_result(case2, ...)
~~~

写入前先断言：

~~~python
self.assertEqual(len(cases_results), 5)
self.assertEqual(
    len({case["name"] for case, _ in cases_results.values()}),
    5,
)
~~~

coverage/gap 最终比较 covered bin 集合，不要把 coverage 的 covered_bins 与 gap 的全部 observed_bins 混为一谈。

### 8.2 两个一致 capability run 的聚合测试

当前两个 case 都是相同 profile 的 scenario_0000，并且只断言 observed_bins >= 1，不能证明汇总了两个 run。

改为：

- run1：唯一名称 pmp_case，profile pmp-boundary
- run2：唯一名称 sv39_case，profile sv39-perm-matrix
- 两个 capability 完全一致
- 两个 result 都 eligible

调用 collect_execution_evidence 和 gap。

断言：

~~~python
self.assertEqual(evidence.summary.eligible_results, 2)
self.assertEqual(evidence.summary.total_results, 2)
self.assertIn("profile=pmp-boundary", gap["observed_bins"])
self.assertIn("profile=sv39-perm-matrix", gap["observed_bins"])
~~~

禁止使用 len >= 1 作为最终证明。

### 8.3 repro 测试不得吞异常或条件断言

删除：

~~~python
try:
    main(...)
except Exception:
    pass

if run_json_path.exists():
    ...
~~~

使用 mock：

~~~python
@mock.patch("pmpfuzz.__main__.capability_for_dut")
@mock.patch("pmpfuzz.__main__.subprocess.run")
def test_repro_writes_metadata(mock_run, mock_cap):
    mock_cap.return_value = complete_capability
    mock_run.return_value = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="mock compile failure",
    )

    rc = main([...])

    self.assertEqual(rc, 1)
    self.assertTrue(run_json_path.is_file())
    self.assertTrue(cap_path.is_file())
~~~

使用 compile_fail 路径即可验证元数据先写出，不需要真实 make_dut。

然后无条件断言：

~~~python
self.assertEqual(run_data["mode"], "repro")
self.assertEqual(run_data["isa"], "rv64gc")
self.assertEqual(cap_data["schema_version"], 3)
self.assertIn("spike", cap_data["duts"])
mock_cap.assert_called_once_with(
    "spike",
    path=expected_spike_path,
    isa="rv64gc",
)
~~~

不得捕获所有 Exception。不得用 if file.exists 包住断言。

### 8.4 runner test 补充输出断言

现有 count=0 mock test可以保留，但增加：

~~~python
self.assertTrue((out / "run.json").is_file())
self.assertTrue((out / "dut_capabilities.json").is_file())
~~~

读取 JSON 后断言 ISA 和 capability DUT。

### 8.5 CLI 测试

在 test_engineering_cli.py 中加入：

~~~python
args = parser.parse_args([
    "schedule",
    "--from-runs", "seed",
    "--out", "next",
])
self.assertEqual(args.coverage_basis, "execution")
self.assertIsNone(args.dut)

args = parser.parse_args([
    "schedule",
    "--from-runs", "seed",
    "--out", "next",
    "--coverage-basis", "manifest",
    "--dut", "spike",
])
self.assertEqual(args.coverage_basis, "manifest")
self.assertEqual(args.dut, "spike")
~~~

确认 run --no-smepmp 已存在，不要重复注册。

## 9. 报告收尾

triage.py 当前显示 missing/orphan 字段，但 coverage.py 尚未提供真实数据。第二组修复后，报告应自然获得正确数字。

同时恢复 manifest 的参考信息：

- semantic
- pairwise
- security-relevant triples
- predicates

都要明确标注 generated-only。

不得删除 execution 部分。不得把 manifest rate 当作正式执行率。

增加报告测试：

- Missing results: 1
- Orphan results: 1
- Manifest Pairwise
- Manifest Predicates
- Execution-Qualified Coverage
- execution scheduler 命令含 --coverage-basis execution --dut spike

## 10. 论文保护检查

本轮开始和结束时都执行：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$paperBefore = Get-Item -LiteralPath 'paper\PMPFUZZ_PAPER.md'
$paperBeforeLength = $paperBefore.Length
$paperBeforeWriteTime = $paperBefore.LastWriteTimeUtc
~~~

完成后只检查，不修改：

~~~powershell
$paperAfter = Get-Item -LiteralPath 'paper\PMPFUZZ_PAPER.md'

if ($paperAfter.Length -ne $paperBeforeLength) {
    throw 'Forbidden modification: paper/PMPFUZZ_PAPER.md length changed'
}

if ($paperAfter.LastWriteTimeUtc -ne $paperBeforeWriteTime) {
    throw 'Forbidden modification: paper/PMPFUZZ_PAPER.md timestamp changed'
}
~~~

还要检查：

~~~powershell
$git = 'git'
& $git @('diff', '--', 'paper')
if ($LASTEXITCODE -ne 0) {
    throw "git diff paper check failed with exit code $LASTEXITCODE"
}
~~~

注意：paper/ 当前可能是未跟踪目录，因此 git diff 不足以单独证明未修改；必须同时比较文件长度和时间。

禁止用 touch、格式化工具或编辑器自动保存论文文件。

## 11. RED 命令

每组先单独运行。

第一至第四组：

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
)

& $python @args
if ($LASTEXITCODE -eq 0) {
    throw 'Expected RED: new regression tests should fail before production fixes'
}
~~~

第五组 runner/repro/CLI：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
$args = @(
    '-m'
    'unittest'
    'tests.test_runner'
    'tests.test_engineering_cli'
    'tests.test_contract_predicates'
)

& $python @args
if ($LASTEXITCODE -eq 0) {
    throw 'Expected RED: hardened tests should fail before fixes'
}
~~~

RED 必须来自指定业务缺陷。语法错误、mock 路径错误、fixture 错误不算。

## 12. GREEN 与全量验证

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
    'tests.test_contract_predicates'
)

& $python @args
if ($LASTEXITCODE -ne 0) {
    throw "Target tests failed with exit code $LASTEXITCODE"
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

测试覆盖率：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
& $python @('-m', 'coverage', 'run', '-m', 'unittest', 'discover', '-s', 'tests')
if ($LASTEXITCODE -ne 0) {
    throw "Coverage run failed with exit code $LASTEXITCODE"
}

& $python @('-m', 'coverage', 'report', '-m')
if ($LASTEXITCODE -ne 0) {
    throw "Coverage report failed with exit code $LASTEXITCODE"
}
~~~

静态检查：

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

本轮不运行：

- python -m pmpfuzz run
- 真实 repro
- Spike
- RTL simulator
- WSL/服务器 smoke
- 真实硬件
- 第 7 章实验

## 13. 禁止的伪修复

禁止：

1. 把 execution 零分母写成 1.0。
2. 继续让 coverage.py 使用旧 qualify_all_results。
3. 在 DUT 过滤之前标记 cases_with_result。
4. 用 len >= 1 证明两个 run 已汇总。
5. 使用相同 internal case name 构造多 case 测试。
6. 捕获所有 Exception 后让测试继续。
7. 用 if file.exists 包住必须存在的文件断言。
8. 只改测试名称，不增强断言。
9. 多运行目录只取第一个 capability。
10. 自动推断时接受任一多 DUT map。
11. 把诊断文本纳入 C_T fingerprint。
12. 删除 manifest coverage。
13. 修改 paper/ 目录。
14. 运行任何具体 DUT 实验。
15. push。

## 14. 最终验收清单

- [ ] semantic execution gap 零分母为 null。
- [ ] pairwise execution gap 零分母为 null。
- [ ] security-triples execution gap 零分母为 null。
- [ ] predicate execution gap 零分母为 null。
- [ ] manifest 零分母兼容行为有测试。
- [ ] coverage.py 使用 collect_execution_evidence。
- [ ] coverage.py 不再使用 qualify_all_results。
- [ ] case 无 result 时 coverage.json missing_results=1。
- [ ] orphan result 时 coverage.json orphan_results=1。
- [ ] 只有其他 DUT result 时目标 DUT missing_results=1。
- [ ] total_results 等于 eligible_results 加 excluded_results。
- [ ] 自动推断遇到后续多 DUT map 时失败。
- [ ] 显式 --dut 可以处理多 DUT map。
- [ ] generator 类型 run_dirs 不会被提前耗尽。
- [ ] fingerprint 忽略 path、notes 和 Smepmp 诊断文本。
- [ ] fingerprint 随 ISA 或 supported_capabilities 改变。
- [ ] coverage_gap.json 记录 basis、DUT、fingerprint 和 qualification。
- [ ] schedule.json 与 coverage_gap.json 元数据完全一致。
- [ ] write_schedule 不重复构建两套 context/gap。
- [ ] 五 case 测试确实包含五个唯一 case name。
- [ ] 两 run 聚合测试明确得到 eligible_results=2。
- [ ] 两 run 聚合测试覆盖两个不同 profile bin。
- [ ] repro 测试不捕获所有异常。
- [ ] repro 测试无条件断言元数据文件存在。
- [ ] runner 测试无条件断言两个元数据文件存在。
- [ ] CLI 默认 execution 与显式 manifest 均有测试。
- [ ] report 显示真实 missing/orphan 数字。
- [ ] manifest 与 execution 报告仍明确分离。
- [ ] 目标测试通过。
- [ ] 全量测试通过。
- [ ] git diff --check 通过。
- [ ] 未运行任何 DUT 实验。
- [ ] paper/PMPFUZZ_PAPER.md 长度和时间均未变化。
- [ ] paper/ 目录没有任何修改。
- [ ] 未 push。

## 15. 最终交付报告

DeepSeek 完成后必须逐项报告：

1. 修改文件。
2. 五组 RED 的具体失败测试。
3. 每组 GREEN 结果。
4. execution 零分母四类结果。
5. coverage.json missing/orphan 示例。
6. 多运行目录推断与 fingerprint 规则。
7. schedule.json 与 coverage_gap.json 一致性。
8. 修复后的五 case 唯一名称列表。
9. 两 run 测试中的两个 profile bin。
10. repro mock 的补丁位置和返回值。
11. 目标测试总数与结果。
12. 全量测试总数与结果。
13. coverage.py 相关模块覆盖率。
14. git diff --check 结果。
15. paper 文件修订前后的长度和时间。
16. 明确声明没有运行 DUT 实验。
17. git status --short。
18. git diff --stat。
19. 尚未解决的问题。

不要只回复“完成”或“测试通过”。必须对应第 14 节逐项说明。
