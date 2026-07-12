# PMPFuzz Execution-Qualified Coverage 修订任务书

> 交接对象：DeepSeek V4 Pro / Claude Code  
> 项目目录：D:\c_s\wjs\riscv-pmp-fuzz  
> 任务性质：代码修订、测试补充、真实 Spike 冒烟验证、论文实现描述同步  
> 实施原则：严格执行 TDD，先补失败测试，再写最小实现，最后完成全量回归和真实运行验证。

## 1. 任务目标

当前 PMPFuzz 的覆盖率统计主要依据运行目录中的 case.json，也就是“生成过哪些测试场景”。这种统计适合作为测试语料清单，但不能证明测试确实在 DUT 上执行到目标观测阶段。

本次修订需要保留现有的 manifest coverage，同时新增 execution-qualified coverage。新的覆盖率必须同时满足以下要求：

1. 只统计实际产生结构化执行结果的测试。
2. 只统计 oracle 可应用的测试。
3. 只统计到达目标观测阶段的测试。
4. timeout、基础设施错误、编译失败、无法判断和能力不支持的测试不得计入分子。
5. oracle 有效且产生语义 mismatch 的 fail 结果仍然属于有效执行，必须计入覆盖率。
6. 覆盖率分母必须按照具体 DUT 的能力进行裁剪，不能要求一个 DUT 覆盖其根本不支持的语义场景。
7. 多个 DUT 必须分别报告，不得合并为一个全局百分比。
8. 调度器默认使用 execution-qualified coverage 查找缺口，但仍允许显式选择旧的 manifest coverage。
9. 论文第 7 章的实验结果只能引用 execution-qualified coverage；manifest coverage 只可作为生成语料统计。

## 2. 修改范围与禁止事项

### 2.1 允许修改

主要修改以下文件：

- pmpfuzz/coverage_qualification.py（新增）
- pmpfuzz/capabilities.py
- pmpfuzz/runner.py
- pmpfuzz/semantic_coverage.py
- pmpfuzz/coverage.py
- pmpfuzz/__main__.py
- pmpfuzz/triage.py
- tests/test_coverage_qualification.py（新增）
- tests/test_coverage.py
- tests/test_semantic_coverage.py
- tests/test_capabilities.py
- tests/test_runner.py
- paper/PMPFUZZ_PAPER.md
- 必要时更新 README.md 或 docs/PMPFUZZ_DESIGN.md 中的覆盖率说明

### 2.2 不得修改

本任务不要顺带修改以下内容：

- 测试场景的保护语义
- oracle 的语义判定规则
- scenario generator 的生成策略
- emitter 的代码生成逻辑
- white-box 覆盖率本身的定义
- D:\riscv-blackbox 中的逆向实验
- 已有实验原始数据
- 与本问题无关的代码风格或目录结构

不要删除旧的 manifest coverage。兼容性方案是“保留旧统计，新增明确命名的新统计”，而不是直接改变旧字段含义。

## 3. 覆盖率资格的严格定义

一个结果只有同时满足以下条件，才可计入 execution-qualified coverage：

- oracle_applicability == "valid"
- status 属于 {"pass", "fail"}
- observation_valid is True
- 结果到达该测试要求的目标阶段
- 存在可解析的结构化观测结果

注意：

- pass 结果计入覆盖率。
- fail 结果如果是有效的语义 mismatch，也计入覆盖率。
- timeout 不计入。
- compile_fail 不计入。
- infra_failure 不计入。
- inconclusive 不计入。
- setup_unsupported 不计入。
- capability_dependent 不计入。
- experimental 不计入。
- 只有 case.json、没有结果文件的测试不计入。
- 执行到了错误阶段或错误路径的结果不计入。
- 不要把 stage_verified 作为一刀切的资格条件。wrong_trap_stage 可能正是一个有效的架构语义 mismatch；缺少阶段信息的情况应由结果分类逻辑归入 inconclusive 或 wrong_phase。

### 3.1 目标阶段

普通测试按结果类型判断：

- 预期 trap 或以 trap 为观测终点的场景：必须到达 probe 阶段。
- 预期正常完成的场景：必须到达 completed 阶段。

状态测试按 case 中的期望阶段判断：

- 当 case["expected"]["stage"] == "stateful_final" 时，结果必须到达 final 阶段。
- 同时检查现有结果格式中三个 final_sentinel 变体；以仓库现有字段名为准，不要自行发明不兼容字段。

目标阶段的判断必须集中在一个函数中，避免 coverage.py、semantic_coverage.py 和 triage.py 各自实现一套略有差异的逻辑。

## 4. DUT 能力裁剪后的覆盖率分母

每个 DUT 都应拥有独立分母。处理方式如下：

1. 根据目标 coverage profile 枚举所有候选场景。
2. 为每个候选场景构造 oracle 能力检查所需的最小 case 描述。
3. 调用：

~~~python
oracle_applicability_for_case(candidate_case, dut_capability)
~~~

4. 只保留返回 "valid" 的候选场景。
5. 用过滤后的候选集合计算该 DUT 的 semantic、pairwise、security triples 和 predicates 分母。

不得合并不同 DUT 的分母。

例如：

- 不支持 Smepmp 的 Spike 运行不应把 Smepmp-only 场景放入分母。
- 不支持 Sv39 的 DUT 不应把 Sv39-only 场景放入分母。
- 不支持 U-mode 的 DUT 不应把 U-mode-only 场景放入分母。
- 如果裁剪后分母为 0，coverage_rate 必须为 null，不能写成 1.0。

## 5. 第一阶段：先补测试，确认 RED

在编写实现前，先新增和修改测试。必须看到测试因缺少本任务要求的能力而失败。

### 5.1 新增 tests/test_coverage_qualification.py

至少覆盖以下十个测试：

1. 合法 pass 结果被计入。
2. 合法 fail/mismatch 结果被计入。
3. timeout 被排除。
4. inconclusive 被排除。
5. observation_valid 为 true，但没有到达目标阶段时被排除。
6. 只有 case.json 时，manifest coverage 增加，但 execution coverage 不增加。
7. DUT 不支持 Smepmp 时，相关场景既不进入分子，也不进入分母。
8. Spike 与 Rocket 因能力不同产生不同分母。
9. 缺失 dut_capabilities.json 时，execution coverage 标记 unavailable，并给出原因。
10. 分母为 0 时，coverage_rate 为 null。

额外建议测试：

- compile_fail、infra_failure、setup_unsupported、capability_dependent 和 experimental 均被排除。
- 有效 mismatch 的 fail 结果不能因为 status == "fail" 被误排除。
- 多 DUT 运行目录在未指定 --dut 时，调度器应报清晰错误。
- 单 DUT 运行目录可自动推断 DUT。
- wrong_trap_stage 如果是结构化、可判定的语义 mismatch，按仓库实际结果字段判断是否属于有效执行；不要机械依赖 stage_verified。

### 5.2 修改现有测试

修改以下测试文件：

- tests/test_coverage.py
- tests/test_semantic_coverage.py
- tests/test_capabilities.py
- tests/test_runner.py

具体要求：

- 原先只创建 case.json 的测试必须显式指定 coverage_basis="manifest"，避免旧测试误以为默认仍是 manifest。
- 为 execution 模式构造完整 fixture：case、result、run.json 和 dut_capabilities.json。
- coverage schema 断言更新为版本 5。
- 增加 Spike 使用实际二进制路径与实际 ISA 的测试。
- 增加 repro 命令写出 run.json 和 dut_capabilities.json 的测试。
- 增加 schedule 默认使用 execution，显式 --coverage-basis manifest 保留旧行为的测试。

### 5.3 RED 阶段命令

在本机 PowerShell 中执行：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
$args = @(
    '-m'
    'unittest'
    'tests.test_coverage_qualification'
    'tests.test_coverage'
    'tests.test_semantic_coverage'
    'tests.test_capabilities'
    'tests.test_runner'
)

& $python @args
if ($LASTEXITCODE -eq 0) {
    throw 'RED 阶段失败：新测试不应该在修复前全部通过'
}
~~~

RED 阶段的失败必须来自缺少新功能，例如模块不存在、字段不存在、错误覆盖率结果或缺少 CLI 参数。不要接受由语法错误、测试 fixture 拼错、导入路径错误导致的假失败。

## 6. 第二阶段：新增统一资格判定模块

新增文件：

- pmpfuzz/coverage_qualification.py

### 6.1 循环依赖约束

这个模块不要导入 schema.py。当前 schema.py 已导入 semantic_coverage.py，反向导入容易形成循环依赖。

优先使用：

- Python 标准库 json
- pathlib
- dataclasses
- collections.Counter
- typing

### 6.2 建议的数据结构

~~~python
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CoverageQualification:
    eligible: bool
    reason: str
    status: str | None
    oracle_applicability: str | None
    observation_valid: bool | None
    target_phase: str | None
    reached_phase: str | None
    semantic_mismatch: bool
~~~

字段名可以根据仓库现有风格微调，但必须能支持：

- 判断是否计入。
- 汇总排除原因。
- 单独统计有效 mismatch。
- 在报告和调度器中复用。

### 6.3 建议实现的函数

~~~python
def read_json_file(path): ...
def load_case_map(run_dir): ...
def load_results(run_dir): ...
def load_capability_map(run_dir): ...
def result_reached_target_phase(case, result): ...
def qualify_result_for_coverage(case, result): ...
~~~

必须先检查仓库现有运行目录布局，兼容现有结果文件路径和 aggregate.json 组织方式。不要只为测试 fixture 写一套现实运行无法读取的格式。

### 6.4 统一的 reason 值

建议至少支持以下稳定 reason：

- eligible
- missing_result
- missing_oracle_applicability
- oracle_not_valid，或者更具体的 oracle_<value>
- status_not_eligible，或者更具体的 status_<value>
- observation_invalid
- missing_structured_observation
- wrong_phase

reason 将进入 coverage.json 与报告，因此应保持稳定、机器可读，不要写成自然语言句子。

## 7. 第三阶段：修正能力探测元数据

### 7.1 修改 pmpfuzz/capabilities.py

重点检查 capability_for_dut，当前大约位于第 20 行附近。

将函数扩展为接受可选 ISA：

~~~python
def capability_for_dut(
    dut: str,
    path: str | None = None,
    isa: str | None = None,
    ...
):
    ...
~~~

返回记录中加入：

~~~python
"isa": isa
~~~

对于 Spike：

- 如果调用者提供 ISA，Smepmp 支持情况必须以实际 ISA 为准。
- rv64gc 应判断为不支持 Smepmp。
- rv64gc_smepmp 应判断为支持 Smepmp。
- 不要因为系统中的 Spike 二进制本身可能支持某扩展，就把本次运行未启用的扩展记为可用。

建议将 DEFAULT_CAPABILITY_SCHEMA_VERSION 从 2 提升到 3，并更新测试和读取兼容逻辑。

### 7.2 缺失能力文件时的行为

如果运行目录缺少 dut_capabilities.json：

- execution coverage 必须标记 available: false。
- 必须写明 unavailable_reason。
- 不得静默回退到默认能力。
- 不得静默改用 manifest coverage。
- manifest coverage 仍可独立计算。

## 8. 第四阶段：让 runner 和 repro 记录真实能力

### 8.1 修改 pmpfuzz/runner.py

重点检查大约第 178 行附近的能力创建逻辑。

修复要求：

- 对 Spike 使用实际的 config.spike 路径。
- 传入实际的 config.isa。
- 对其他通过 dut_bin 指定的 DUT，使用真实 dut_bin 路径。
- 其他 DUT 也尽量记录 ISA。
- 不要在用户指定自定义 Spike 路径后，仍探测 PATH 中另一个 Spike。

伪代码：

~~~python
if dut == "spike":
    capability = capability_for_dut(
        dut,
        path=config.spike,
        isa=config.isa,
    )
elif config.dut_bin:
    capability = capability_for_dut(
        dut,
        path=config.dut_bin,
        isa=config.isa,
    )
else:
    capability = capability_for_dut(
        dut,
        isa=config.isa,
    )
~~~

以项目实际 Config 字段为准。

### 8.2 修改 pmpfuzz/__main__.py 的 repro

重点检查 _cmd_repro，大约位于第 454 行附近。

当前问题：repro 路径可能不会写出 run.json 和 dut_capabilities.json，这会使 execution coverage 无法确定 DUT 能力。

修复要求：

1. 在 DUT 循环前解析 DUT 列表和实际 ISA。
2. 为每个 DUT 使用实际二进制路径和实际 ISA 创建 capability。
3. 写出 run.json。
4. 写出 dut_capabilities.json。
5. 元数据格式与普通 run 命令保持一致。

run.json 至少记录：

~~~json
{
  "mode": "repro",
  "source_case": "...",
  "duts": ["spike"],
  "isa": "rv64gc",
  "no_smepmp": true
}
~~~

dut_capabilities.json 使用 schema version 3，并包含每个 DUT 的能力和 fingerprint。

## 9. 第五阶段：为 semantic coverage 增加 execution 模式

修改：

- pmpfuzz/semantic_coverage.py

重点函数及当前大致位置：

- coverage_gap_from_runs：约第 394 行
- combination_gap_from_runs：约第 429 行
- predicate_gap_from_runs：约第 475 行
- build_schedule：约第 512 行
- write_schedule：约第 610 行
- target_semantic_bins：约第 671 行
- target_combo_bins：约第 683 行
- target_contract_predicates：约第 696 行
- _target_candidates：约第 723 行

行号只用于快速定位，以实际文件为准。

### 9.1 为候选场景构造能力检查 case

新增类似函数：

~~~python
def _capability_case_for_scenario(scenario):
    ...
~~~

返回内容至少包括：

- profile
- privilege
- access
- translation
- mseccfg.mml
- mseccfg.mmwp
- mseccfg.rlb
- ad_update_mode
- stateful_sequence
- 如果 translation 为 Sv39，则加入 sv39.pte，内容由现有 PTE 数据结构转换而来

建议：

~~~python
from dataclasses import asdict
~~~

如果 scenario 使用 dataclass，可用 asdict 转换 PTE。必须保持 oracle_applicability_for_case 能读取的字段结构。

每个 target candidate 中保留 capability_case，供分母过滤使用。

### 9.2 扩展 target 函数

以下函数增加 capability 参数：

~~~python
def target_semantic_bins(..., capability=None): ...
def target_combo_bins(..., capability=None): ...
def target_contract_predicates(..., capability=None): ...
~~~

当 capability 不为 None 时，仅保留：

~~~python
oracle_applicability_for_case(candidate["capability_case"], capability) == "valid"
~~~

的候选。

当 capability 为 None 时，保留原 manifest 行为，以维持兼容。

### 9.3 扩展 gap 函数

以下函数增加参数：

~~~python
coverage_basis: str = "execution"
dut: str | None = None
~~~

适用于：

- coverage_gap_from_runs
- combination_gap_from_runs
- predicate_gap_from_runs
- build_schedule
- write_schedule

行为要求：

#### manifest

- 维持原先根据 case.json 统计的行为。
- 不要求结果文件。
- 不要求能力文件。
- 明确标记 coverage_basis 为 manifest。

#### execution

- 加载 case、result 和 capability map。
- 使用统一资格判定模块过滤结果。
- 使用选定 DUT 的能力裁剪分母。
- 如果只有一个 DUT，可以自动推断。
- 如果存在多个 DUT 且未指定 dut，必须报清晰错误，要求用户传 --dut。
- 如果缺失能力文件，不能回退到 manifest。

### 9.4 schedule.json 新增字段

schedule.json 至少记录：

~~~json
{
  "coverage_basis": "execution",
  "dut": "spike",
  "capability_fingerprint": "...",
  "qualification": {
    "eligible_results": 20,
    "excluded_results": 4,
    "excluded_by_reason": {
      "status_timeout": 2,
      "wrong_phase": 1,
      "oracle_capability_dependent": 1
    }
  }
}
~~~

字段可以嵌入现有结构，但含义必须清楚。

## 10. 第六阶段：扩展 coverage.json

修改：

- pmpfuzz/coverage.py

重点检查文件开头和 schema 定义，当前大约第 32 行附近。

### 10.1 schema 版本

将 coverage schema 从 4 提升为 5。

### 10.2 保留旧顶层字段

不要删除或重解释现有顶层 manifest 字段。增加明确标记：

~~~json
"legacy_top_level_basis": "generated_manifest"
~~~

这样旧工具仍能读取原字段，新论文和新报告则使用 execution_coverage。

### 10.3 新增 execution_coverage

建议结构：

~~~json
{
  "schema_version": 5,
  "legacy_top_level_basis": "generated_manifest",
  "execution_coverage": {
    "schema_version": 1,
    "coverage_model": "execution-qualified-capability-scoped-v1",
    "by_dut": {
      "spike": {
        "available": true,
        "capability_fingerprint": "...",
        "qualification": {
          "total_results": 24,
          "eligible_results": 20,
          "valid_mismatches": 1,
          "excluded_results": 4,
          "excluded_by_reason": {
            "status_timeout": 2,
            "wrong_phase": 1,
            "oracle_capability_dependent": 1
          }
        },
        "semantic": {},
        "pairwise": {},
        "security_triples": {},
        "predicates": {}
      }
    }
  }
}
~~~

每种覆盖率至少包含：

~~~json
{
  "total_target_bins": 100,
  "covered_target_bins": 40,
  "missing_target_bins": 60,
  "coverage_rate": 0.4,
  "covered_bins": [],
  "missing_bins": []
}
~~~

必须维持以下不变量：

~~~text
0 <= covered_target_bins <= total_target_bins
missing_target_bins == total_target_bins - covered_target_bins
coverage_rate == covered_target_bins / total_target_bins
~~~

分母为 0 时：

~~~json
"coverage_rate": null
~~~

不能使用 1.0，也不要制造“空集合已完全覆盖”的误导。

### 10.4 unavailable 结构

能力文件缺失或无法确定 DUT 时，建议输出：

~~~json
{
  "available": false,
  "unavailable_reason": "missing_dut_capabilities",
  "qualification": {
    "total_results": 0,
    "eligible_results": 0,
    "valid_mismatches": 0,
    "excluded_results": 0,
    "excluded_by_reason": {}
  }
}
~~~

不要用空的正常 coverage 结构假装成功。

## 11. 第七阶段：CLI 修改

修改：

- pmpfuzz/__main__.py

重点检查参数定义，大约第 42 行附近及 schedule 子命令的参数区。

为 schedule 增加：

~~~python
--coverage-basis
~~~

选项：

- execution
- manifest

默认值：

~~~text
execution
~~~

再增加：

~~~python
--dut
~~~

默认 None。将两个参数完整传递到 write_schedule 或 build_schedule。

coverage 命令要求：

- 对每个 DUT 分别输出 execution coverage。
- 不生成跨 DUT 混合的全局 execution percentage。
- 旧 manifest 字段仍可生成。
- 日志或终端摘要中要明确区分 Manifest Coverage 与 Execution-Qualified Coverage。

## 12. 第八阶段：修订报告

修改：

- pmpfuzz/triage.py

重点检查大约第 77 行附近的覆盖率报告。

当前问题：报告可能把顶层 manifest coverage 直接称为 semantic coverage，容易让读者误以为这些场景已经成功执行。

修订要求：

1. 增加 Manifest Coverage 小节。
2. 明确说明这是 generated-only 统计。
3. 增加 Execution-Qualified Coverage 小节。
4. 按 DUT 分别展示。
5. 展示资格统计和排除原因。
6. 如果 execution coverage unavailable，显示原因，不得回退。
7. 报告给出的下一轮调度命令应包含：

~~~text
--coverage-basis execution --dut <dut>
~~~

## 13. 第九阶段：GREEN 与重构顺序

建议严格按以下顺序实现，每完成一步就运行相关测试：

1. coverage_qualification.py
2. capabilities.py
3. runner.py
4. repro 元数据
5. semantic_coverage.py
6. coverage.py
7. CLI 参数
8. triage.py
9. 文档与论文同步

不要一次性改完所有文件再运行测试，这样很难定位问题。

每一步只做使测试通过的最小实现。GREEN 后再清理重复逻辑，但不要改变既有测试语义。

## 14. 本机全量测试

在 PowerShell 中执行：

~~~powershell
Set-Location -LiteralPath 'D:\c_s\wjs\riscv-pmp-fuzz'

$python = 'python'
$args = @('-m', 'unittest', 'discover', '-s', 'tests')

& $python @args
if ($LASTEXITCODE -ne 0) {
    throw "Full test suite failed with exit code $LASTEXITCODE"
}
~~~

必须记录：

- 总测试数
- 失败数
- 跳过数
- 是否存在与本任务无关的既有失败
- 新增测试是否全部执行

如项目环境安装了 coverage.py，再执行：

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

本次新增和显著修改模块应争取达到 80% 以上覆盖率。不要为了数字给无关模块补空洞测试。

## 15. 真实 Spike 冒烟实验

实验尽量在服务器的 wjs 工作目录中进行。

可能的服务器仓库路径为：

~~~text
/home/dubhe/wjs/pmp-fuzz-stage1
~~~

先确认实际路径和 Git 状态，不要直接假设：

~~~bash
cd /home/dubhe/wjs/pmp-fuzz-stage1
pwd
git status --short
~~~

不得修改服务器上的 Android、work 和 ida-hcli 目录。

### 15.1 环境检查

~~~bash
python3 -m pmpfuzz env-check
~~~

如环境检查失败，先记录缺失项。只安装完成本任务所需的软件包，不要做与任务无关的环境升级。

### 15.2 运行小规模 Spike 测试

~~~bash
OUT="runs/execution_coverage_smoke_$(date +%Y%m%d_%H%M%S)"

python3 -m pmpfuzz run \
  --dut spike \
  --profile pmp-boundary \
  --count 24 \
  --seed 20260712 \
  --jobs 1 \
  --no-smepmp \
  --time-budget 5m \
  --per-case-timeout 10 \
  --out "$OUT"
~~~

这里使用 --no-smepmp 是为了验证实际 ISA 与能力分母裁剪：本次运行不应要求覆盖 Smepmp-only 场景。

### 15.3 生成覆盖率和下一轮调度

~~~bash
python3 -m pmpfuzz coverage --run-dir "$OUT"

python3 -m pmpfuzz schedule \
  --from-runs "$OUT" \
  --target core-stateful \
  --coverage-mode predicates \
  --coverage-basis execution \
  --dut spike \
  --max-cases 8 \
  --seed 20260713 \
  --out "${OUT}_next"
~~~

如果项目实际 CLI 参数与此略有不同，应以 --help 和现有测试为准调整，但不得改变验证目标。

## 16. 如何人工查看结果

### 16.1 查看运行摘要

~~~bash
python3 -m json.tool "$OUT/aggregate.json" | less
~~~

确认：

- 有真实结果记录。
- 至少有部分 pass 或 fail。
- timeout 等状态不会被误当成合格执行。
- fail 中如果存在有效 mismatch，后续 qualification 会单独统计。

### 16.2 查看 DUT 能力

~~~bash
python3 -m json.tool "$OUT/dut_capabilities.json" | less
~~~

确认：

- 存在 spike 条目。
- available 为 true。
- isa 记录本次实际 ISA，例如 rv64gc。
- 本次使用 --no-smepmp 时，Smepmp 不应被标为可用。
- 存在稳定的 capability fingerprint。

### 16.3 查看覆盖率

~~~bash
python3 -m json.tool "$OUT/coverage/coverage.json" | less
~~~

确认：

- schema_version 为 5。
- legacy_top_level_basis 为 generated_manifest。
- execution_coverage.coverage_model 为 execution-qualified-capability-scoped-v1。
- execution_coverage.by_dut.spike.available 为 true。
- eligible_results 大于 0。
- excluded_by_reason 与 aggregate.json 中的非合格结果相符。
- 不支持的 Smepmp 语义不进入 Spike 的目标分母。
- 四类覆盖率均满足数值不变量。

### 16.4 查看调度结果

~~~bash
python3 -m json.tool "${OUT}_next/schedule.json" | less
~~~

确认：

- coverage_basis 为 execution。
- dut 为 spike。
- capability_fingerprint 与能力文件一致。
- qualification 统计存在。
- 生成的下一轮 case 数不超过 8。
- 下一轮调度针对 execution coverage 的缺口，而不是仅仅 case.json 中未出现的字段组合。

## 17. 自动化冒烟结果检查

执行以下检查脚本：

~~~bash
python3 - "$OUT/coverage/coverage.json" <<'PY'
import json
import math
import sys

path = sys.argv[1]
with open(path, "r", encoding="ascii") as handle:
    data = json.load(handle)

assert data["schema_version"] == 5
assert data["legacy_top_level_basis"] == "generated_manifest"

entry = data["execution_coverage"]["by_dut"]["spike"]
assert entry["available"] is True
assert entry["qualification"]["eligible_results"] > 0

for name in ("semantic", "pairwise", "security_triples", "predicates"):
    coverage = entry[name]
    total = coverage["total_target_bins"]
    covered = coverage["covered_target_bins"]
    missing = coverage["missing_target_bins"]

    assert 0 <= covered <= total
    assert missing == total - covered

    if total == 0:
        assert coverage["coverage_rate"] is None
    else:
        expected = round(covered / total, 6)
        assert math.isclose(
            coverage["coverage_rate"],
            expected,
            rel_tol=0,
            abs_tol=1e-6,
        )

print("execution coverage smoke: PASS")
PY
~~~

如果实际代码没有对 coverage_rate 统一保留六位小数，可调整 expected 的舍入方式，但必须保证 JSON 写入逻辑与测试断言一致。

## 18. 最终验收标准

只有全部满足以下条件，任务才算完成：

- [ ] 全量单元测试通过。
- [ ] 新增 tests/test_coverage_qualification.py。
- [ ] coverage.json schema version 为 5。
- [ ] manifest coverage 与 execution coverage 在数据结构和报告中明确分离。
- [ ] 只有 case.json、没有执行结果的测试不进入 execution coverage。
- [ ] timeout、compile_fail、infra_failure、inconclusive 等不进入 execution coverage。
- [ ] oracle 有效的语义 mismatch 即使 status 为 fail，仍进入 execution coverage。
- [ ] 未到达目标观测阶段的结果不进入 execution coverage。
- [ ] 不支持的 Smepmp/Sv39/U-mode 场景不进入对应 DUT 的分母。
- [ ] 不同 DUT 分别计算分母与覆盖率。
- [ ] 缺失 dut_capabilities.json 时显示 unavailable，不静默回退。
- [ ] schedule 默认使用 execution coverage。
- [ ] 显式 --coverage-basis manifest 仍可使用旧模式。
- [ ] Spike 冒烟实验中 eligible_results > 0。
- [ ] 所有 coverage 数值满足分子、分母和缺口不变量。
- [ ] 新生成的 schedule 可以被后续生成器正常读取。
- [ ] report 清楚区分 generated manifest 与 executed coverage。
- [ ] 没有修改白盒覆盖率定义、测试语义、oracle、generator 或 emitter。
- [ ] 没有修改 D:\riscv-blackbox 和服务器禁止目录。
- [ ] 没有提交或推送未经用户确认的 Git 变更。

## 19. 论文与设计文档同步

只有在代码、单元测试和真实 Spike 冒烟全部通过后，才更新论文描述。

修改：

- paper/PMPFUZZ_PAPER.md

重点检查第 6.4 节附近，当前大约第 257 行。

需要：

1. 删除或替换 [IMPLEMENTATION NEEDED] 标记。
2. 删除“当前 aggregator 仅报告 generated manifest coverage”这类已经过时的描述。
3. 说明实现现在同时报告：
   - generated manifest coverage
   - execution-qualified, capability-scoped coverage
4. 说明论文实验采用第二种统计。
5. 简洁说明：
   - 只有 oracle 可应用、观测有效且到达目标阶段的结果才计入。
   - 有效 mismatch 仍计入。
   - 分母按每个 DUT 的实际能力裁剪。
   - 黑盒与白盒反馈仍保持各自定义，不应混成一个覆盖率。

同时检查 README.md 和 docs/PMPFUZZ_DESIGN.md。如果它们描述了覆盖率或调度器，更新为与实现一致的双模式说明。

## 20. 常见错误

### 20.1 只修改 coverage.py

这是不够的。调度器、报告、runner 元数据、repro 元数据和能力分母必须保持一致，否则同一运行会出现多套互相冲突的覆盖率。

### 20.2 把所有 fail 都排除

错误。PMPFuzz 的目标就是发现语义 mismatch。只要 oracle 可应用、结构化观测有效且到达目标阶段，mismatch fail 是有效执行，必须计入覆盖率并单独统计。

### 20.3 把 timeout 当作“执行过”

错误。timeout 不能证明目标语义观测已经完成，因此不得计入 execution coverage。

### 20.4 只检查 observation_valid，不检查阶段

错误。初始化完成或进入某个早期阶段不代表目标访问已被观测。必须检查目标阶段。

### 20.5 合并多个 DUT

错误。不同 DUT 能力不同，分母不同。不得计算一个跨 DUT 的 execution coverage 百分比。

### 20.6 缺少能力文件时使用默认能力

错误。这会制造看似精确、实际不可复现的分母。必须标记 unavailable。

### 20.7 删除 manifest coverage

错误。manifest coverage 仍用于检查生成器语料多样性和兼容旧工具，只是不能用于论文的执行覆盖率结论。

### 20.8 借机重写 generator、oracle 或 emitter

禁止。本任务仅处理执行资格、能力分母、调度和报告。

### 20.9 在验证前删除论文标记

不要这样做。只有实现、测试和真实冒烟都成功后，才可声称该能力已经实现。

## 21. 最终交付报告格式

完成后给出一份简洁但可审计的报告，包含：

1. 修改文件列表。
2. 覆盖率资格规则的最终实现位置。
3. capability-scoped denominator 的实现位置。
4. 新增测试清单。
5. RED 阶段看到了什么预期失败。
6. GREEN 后相关测试和全量测试结果。
7. Spike 冒烟命令、输出目录和关键统计。
8. coverage.json 中四类覆盖率的分子、分母和百分比。
9. 被排除结果的原因分布。
10. 论文和文档修改位置。
11. 尚未解决的问题或环境限制。
12. git diff --stat 与 git status --short 的输出。

不要只回复“已修复”。最终报告必须让另一位研究者能够判断统计口径是否真实落地。
