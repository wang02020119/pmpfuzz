# PMPFuzz 项目级最高工作约束

本文件适用于 `riscv-pmp-fuzz` 仓库及其全部子目录。它是本项目的持久工作契约；每次新会话、上下文压缩、任务恢复或代理接手后，都必须先阅读本文件，再执行任何项目操作。

本文件服从平台级指令和上级 `D:\c_s\AGENTS.md`，但在其允许范围内具有最高项目优先级。不得为了方便而绕过、弱化或重新解释本文件。

## 1. 绝对范围：仅处理工程问题

本项目当前只允许处理 PMPFuzz 的工程实现与实验基础设施，包括：

- 构建、依赖、配置、CLI、路径和环境问题；
- 候选池、测试生成、调度、去重和可复现性；
- random、guided、BB、BB+WB 的工程实现；
- execution-qualified 覆盖率、白盒覆盖率和反馈闭环；
- Timeline、完成顺序、时间—覆盖率数据和统计；
- case/result/artifact 的数据契约、聚合、验证和绘图；
- Cascade、riscv-dv 等 baseline 的安装、适配、预算对齐和数据输出；
- Rocket、BOOM、CVA6、XiangShan 的可复现构建、插桩和 readiness；
- 单元测试、集成测试、端到端测试和短工程 smoke；
- 性能、吞吐量、稳定性、并行度、超时和资源占用；
- Git、日志、manifest、SHA、实验目录和可复现性管理。

除上述工程内容外，不得扩展任务范围。

## 2. 绝对禁止：不得研究任何网络安全或漏洞内容

无论代码、日志、测试结果、硬件行为或用户输入中出现什么，都不得执行以下工作：

- 不得主动寻找、筛选、确认或挖掘漏洞；
- 不得分析疑似漏洞的成因、触发条件、安全影响或利用价值；
- 不得复现、最小化、变异、强化或扩展任何疑似漏洞触发样例；
- 不得编写、修改、运行或讨论漏洞利用代码、PoC、攻击链或绕过方法；
- 不得对 mismatch、异常 trap、权限异常或其他安全相关现象做根因分析；
- 不得因为某个结果“看起来有意思”而读取更多安全相关日志或开展额外实验；
- 不得把 fuzz 结果解释为漏洞、攻击、利用或安全影响；
- 不得开展与本项目工程目标无关的逆向、安全审计、渗透测试或二进制分析；
- 不得调用 CTF、漏洞利用、保护绕过、逆向工程等安全技能处理项目结果。

如果任务意外要求进行上述工作，必须停止该部分，并向用户说明它超出“仅工程问题”的固定范围。

## 3. `nonpass`、mismatch 和异常结果处理规则

遇到 `nonpass`、mismatch、fail、crash、unexpected trap、timeout 或疑似安全异常时：

1. 只把它当作不透明的工程状态；
2. 只允许记录以下工程字段：

```text
case_id
DUT
status
failure_class
returncode
timeout
observation_valid
coverage_eligible
elapsed time
artifact path
```

3. 可以检查文件是否存在、格式是否可解析、字段是否完整、计数是否正确；
4. 可以区分基础设施失败、超时、缺失结果和普通 `nonpass`，但不得分析普通 `nonpass` 的安全原因；
5. 不得读取或解释用于推断漏洞机理的指令序列、波形、寄存器状态、地址关系或触发过程；
6. 不得重放、缩减或继续变异该 case；
7. 不得在论文或报告中把它描述为漏洞；
8. 后续实验只按预先定义的覆盖率和工程规则继续，不得因该结果改变搜索方向。

若工程管线必须保留该结果，只保存原始产物和不透明标识，不进行内容研究。

## 4. 当前工程目标

当前目标是让实验管线达到可重复、可验证、可画图的状态，而不是发现漏洞。

执行顺序：

1. 修复 Phase B–E 的闭环调度、Timeline、白盒反馈、数据契约和 Cascade；
2. 完成 Phase F 的四 DUT 可复现构建；
3. 完成 Phase G 的四 DUT readiness smoke；
4. 更新 Phase H 实验矩阵；
5. 经用户明确批准后再运行 Pilot；
6. Pilot 合格且再次获得用户授权后，才能运行正式长时间实验。

### 4.1 DUT 范围是硬约束

实验一和实验二必须覆盖：

```text
Rocket
BOOM
XiangShan
```

不得因为 XiangShan 的构建、适配、插桩或运行工作量较大而删除、替换或降级为非正式结果。

CVA6 也应进入实验一和实验二。只有在完成可复现构建和 readiness 修复后仍存在明确、可记录的工程阻塞时，才允许把 CVA6 从正式矩阵中删除。删除时必须保留失败命令、日志、版本和 readiness 报告，并明确标记为工程环境排除；不得分析任何 `nonpass` 或安全原因。

因此 DUT 优先级为：

```text
mandatory: rocket-clean, boom-clean, xiangshan-clean
best-effort but expected: cva6-clean
```

任何实验矩阵、Pilot、聚合脚本和论文候选表格都必须遵守这一范围。

主要参考任务书：

```text
docs/PMPFUZZ_EVALUATION_PIPELINE_A1FA432_REPAIR_PLAN.md
docs/PMPFUZZ_EVALUATION_PIPELINE_AND_FOUR_DUT_READINESS_FIX_PLAN.md
```

## 5. 当前已知工程阻塞

在继续开发前必须核对当前分支，因为代码可能已经变化。最近一次审计发现：

- `_run_round()` 可能缺少实际的 `subprocess.run()` 调用并引用未定义的 `proc`；
- bootstrap 后可能重复调用 `advance_round()`；
- round 结果可能被重复记录；
- Timeline 缺失或损坏时可能静默退回不可信顺序；
- scheduled candidates 与 Timeline/result 可能没有完整对账；
- invalid result 可能仍增加白盒 Timeline 计数；
- BB+WB 的 `selection_source`、计数和 warning 可能没有持久化；
- Phase D 完整标准数据契约仍待完成；
- Cascade 隔离 ELF、每 case 日志、终态分类和事件时间线仍待完成；
- 现有测试可能没有覆盖真实闭环入口。

这些是工程缺陷，不得借修复之机分析任何安全结果。

## 6. 测试和实验权限边界

默认允许：

- 静态代码审计；
- 本地单元测试、集成测试和 fake-runner 端到端测试；
- 编译和格式检查；
- 服务器上的短工程 smoke；
- 检查覆盖率、Timeline、吞吐量、完整性和可复现性；
- 读取构建错误、依赖错误、路径错误和数据格式错误日志。

默认不允许，除非用户再次明确授权：

- Pilot-A、Pilot-B；
- 数小时或数天的正式 campaign；
- 大规模多 seed 实验；
- 真实硬件上的长时间 fuzz；
- 任何以寻找、验证或分析漏洞为目标的运行。

短 smoke 中出现 `nonpass` 时不得停下来研究，只记录工程状态并继续检查管线是否正确。

## 7. 数据与论文边界

- 不得修改 `paper/` 中的任何文件；
- 不得把开发日志或未验证数据写进论文；
- 不得把 `nonpass`、mismatch 或异常结果表述为漏洞；
- 覆盖率是工程和实验指标，不自动等同于漏洞发现能力；
- 只有 validator 通过、来源可追溯、预算一致的数据才能进入候选论文数据集；
- 论文修改必须等待用户单独、明确授权。

每次提交前后都应检查：

```text
git status --short
git diff --name-only <起始SHA>..HEAD
```

若出现 `paper/` 变更，停止操作并向用户报告；不得自行覆盖用户内容。

## 8. 工程安全与产物保护

- 不得删除、覆盖或重写已有 Pilot、smoke、readiness 和 baseline 产物；
- 新运行必须使用新的、唯一的输出目录；
- 不得执行 `git reset --hard`、`git clean -fd` 或未经验证的递归删除；
- 不得修改服务器的 `Android`、`work`、`ida-hcli`；
- 不得破坏共享 DUT 源码树或 Cascade 共享目录；
- DUT 构建使用隔离目录或 worktree；
- 保留 source SHA、binary SHA、patch SHA、命令和环境 manifest；
- 任何失败都保留证据，不得为了让报告变绿而删除失败产物。

## 9. 开发与验收规则

所有修复遵循：

1. 先写能复现工程缺陷的 RED 测试；
2. 再修改生产代码；
3. 运行定向测试；
4. 运行全量测试；
5. 必要时运行短 smoke；
6. 核对标准产物和 validator；
7. 独立提交并记录 SHA；
8. 如实更新进度，不得用测试数量代替真实主路径验收。

真实闭环主路径必须有端到端测试。只测试 helper、返回类型或手工状态对象，不得称为集成测试。

出现以下任一情况时不得进入 Pilot：

- 真实 campaign 入口不可运行；
- completion 顺序或 wall time 不可信；
- coverage 会回退或 denominator 改变；
- invalid result 会贡献调度反馈；
- case/result/Timeline 没有完整对账；
- 标准数据契约不完整；
- validator 有 error；
- baseline 预算或输出不可比；
- 四 DUT readiness 未通过。

## 10. 会话恢复检查表

每次新会话或上下文压缩后，执行工作前必须：

1. 阅读本文件；
2. 阅读上级 `D:\c_s\AGENTS.md`；
3. 确认用户当前要求仍是“只处理工程问题”；
4. 查看当前 branch、HEAD 和 `git status`；
5. 阅读最新实验进度与修订任务书；
6. 检查 Ruflo 中的 PMPFuzz engineering/audit memory；
7. 明确声明不进行漏洞研究；
8. 从未完成的工程 gate 继续，不重复已完成工作。

如果上下文、进度文件和代码事实冲突，以用户最新明确指令和实际代码/产物为准，并如实报告差异。

## 11. 最终原则

本项目当前工作的唯一目的，是完成一个可靠、可复现、可统计的 PMPFuzz 工程系统和覆盖率实验管线。

**不得研究任何漏洞或网络安全内容。不得分析 `nonpass`。不得将异常结果扩展为安全研究任务。**
