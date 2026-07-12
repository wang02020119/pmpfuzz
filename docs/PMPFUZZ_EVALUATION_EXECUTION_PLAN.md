# PMPFuzz 论文实验执行任务书

> 交付对象：DeepSeek V4 Pro / Claude Code
>
> 文档目标：在服务器上实现实验记录基础设施，完成 PMPFuzz 的 baseline、覆盖率、消融、缺陷检测、跨 DUT 和真实硬件实验，并生成论文可直接使用的原始数据、统计表和图。
>
> 当前日期：2026-07-12

## 0. 不可违反的约束

1. **所有编译、RTL 仿真、baseline 和正式 campaign 必须在服务器上运行。** Windows 本机只用于编辑、审计和同步代码，不能用本机结果代替服务器结果。
2. 服务器上的全部工作必须位于 `/home/dubhe/wjs` 下。不得修改 `Android`、`work`、`ida-hcli` 目录中的任何内容。
3. **禁止修改论文文件及整个 `paper/` 目录。** 特别禁止修改：
   - `paper/PMPFUZZ_PAPER.md`
   - `paper/cybersecurity-manuscript/`
   - `paper/cybersecurity-template/`
4. 不得编造实验结果、补写不存在的漏洞、手工调整曲线或删除失败 campaign。
5. 正式覆盖率必须使用 execution-qualified coverage。不得用 generated-manifest coverage 冒充执行覆盖率。
6. 不得用 `result.json` 的文件修改时间还原实验顺序；不得用各 case 的 `elapsed_seconds` 相加模拟并发 campaign 的墙钟时间。
7. 不得用 PMPFuzz 专属的 scenario metadata 给 riscv-dv 或 Cascade 计算“PMPFuzz 语义覆盖率”。跨工具比较必须使用共同 DUT 观测指标。
8. 不得直接在原始 Rocket、BOOM、CVA6、XiangShan 或物理板卡工程目录中注入故障。每个 mutant 和插桩版本必须使用独立 worktree、独立复制或可重放 patch。
9. 每个实验命令、版本、环境、排除项和失败都必须保留。不得只保留成功结果。
10. 在开始长时间实验前，必须先完成单元测试、冒烟实验和 pilot；任何验收项失败都应停止，不得继续消耗服务器资源。
11. **服务器已经通过官方 Cascade Docker artifact 部署了真正的 Cascade。不得默认重新克隆、重新安装、重新构建镜像或升级 Cascade。** 必须复用现有容器，记录容器、镜像 digest、挂载、Cascade source、DUT source 和实际二进制。
12. riscv-dv 当前不视为已安装，由 DeepSeek 在 `/home/dubhe/wjs/pmpfuzz-eval-third-party/riscv-dv` 下自行安装、构建、验证和锁定版本。

## 1. 当前仓库状态与启动前阻塞项

本任务书创建时，本地仓库为：

- 仓库：`https://github.com/wang02020119/riscv-pmp-fuzz.git`
- 分支：`feature/real-whitebox-dut-coverage`
- 当前 HEAD：`381550af54e3340621633bad6a0e887d0ac3272f`
- 本地分支领先远端 4 个提交，并且仍有未提交的执行覆盖率代码和测试。
- `paper/` 当前是未跟踪目录，**绝对不能被加入提交**。

因此，正式服务器实验前必须先保存当前代码状态。

### 1.1 本地代码保存流程

DeepSeek 必须先执行：

```bash
git status --short
git diff --stat
git diff -- pmpfuzz tests README.md docs
python -m unittest discover -s tests
```

测试通过后，只显式暂存代码、测试和非论文文档。**禁止使用 `git add -A`、`git add .`。**

暂存后必须检查：

```bash
git diff --cached --name-only
git diff --cached --name-only | grep '^paper/' && exit 1 || true
```

只有确认输出中没有 `paper/` 后，才能提交并推送：

```bash
git commit -m "Finalize execution-qualified coverage and evaluation infrastructure"
git push origin feature/real-whitebox-dut-coverage
```

如果不准备提交某个现有修改，不得擅自丢弃；先列出文件和原因，等待确认。

### 1.2 服务器工作区

服务器连接信息已经核实：

```text
SSH alias: dubhe
Host/IP: 10.122.220.95
Port: 22
User: dubhe
Authentication: SSH private key
Windows identity file: C:\Users\13840\.ssh\id_rsa
Remote workspace root: /home/dubhe/wjs
```

优先使用本机现有 SSH 配置直接登录：

```bash
ssh dubhe
```

等价的显式登录形式为：

```bash
ssh -p 22 -i ~/.ssh/id_rsa dubhe@10.122.220.95
```

该服务器使用密钥完成 SSH 登录，不应要求 SSH 账户密码。如果出现 SSH 密码提示，不要猜测或反复尝试，应先检查是否使用了正确的本机 SSH 配置和私钥。sudo 凭据由任务委托者在本地会话中单独提供，禁止把密码写入仓库、脚本、`commands.log`、环境清单或实验产物。

连接后先记录：

```bash
hostname
whoami
pwd
date --iso-8601=seconds
```

在服务器新建独立目录，不复用旧 campaign 输出：

```bash
cd /home/dubhe/wjs
git clone --branch feature/real-whitebox-dut-coverage \
  https://github.com/wang02020119/riscv-pmp-fuzz.git \
  riscv-pmp-fuzz-eval
cd /home/dubhe/wjs/riscv-pmp-fuzz-eval
git rev-parse HEAD
git status --short
```

要求服务器 clone 的 SHA 与刚刚推送的代码 SHA 完全一致。若不一致，停止实验。

实验原始数据放在仓库外：

```text
/home/dubhe/wjs/pmpfuzz-eval-artifacts/
├── manifests/
├── pilot/
├── campaigns/
├── baselines/
├── mutants/
├── aggregate/
└── plots/
```

不要把大型运行结果提交到 Git。

## 2. 论文需要由实验回答的问题

### RQ1：语义有效性与判定正确性

PMPFuzz 生成的测试能否到达预定目标访问，并被 protection oracle 和 host-side judgment 正确判定？

需要报告：

- attempted cases；
- applicable cases；
- execution-qualified results；
- setup/harness failure；
- pass、mismatch、timeout、inconclusive；
- 可归因到目标访问的比例；
- 模型预期与 golden model 的一致性；
- protection stage 归因正确、模糊和错误的数量。

Spike 是 golden model，不是 DUT。Rocket、BOOM、CVA6、XiangShan 和物理芯片才是测试目标。

### RQ2：黑盒语义覆盖反馈是否有效

当前候选空间包含 28 个 profile、共 1,262 个候选。最终覆盖率可能通过穷举达到较高值，因此主要指标不能只有最终覆盖率。

必须比较：

- 达到 50%、80%、90% 和 100% 覆盖所需时间；
- 达到上述覆盖所需执行测试数；
- time-to-coverage 曲线；
- cases-to-coverage 曲线；
- 曲线下面积；
- 每 100 个 execution-qualified results 新增的 coverage bins。

四类覆盖分别实验：

- semantic；
- pairwise；
- security-triples；
- predicates。

### RQ3：白盒反馈是否提供额外价值

在相同语义生成器、相同初始测试、相同时间和相同 case 数量下，比较：

- `PMPFuzz-BB`：只使用黑盒语义反馈；
- `PMPFuzz-BB+WB`：黑盒反馈加白盒安全事件反馈。

需要比较：

- distinct security-relevant events over time；
- 新事件发现速度；
- PMP/PTW/TLB/trap/side-effect 事件类别；
- 发现的 protection faults；
- time-to-first-fault。

### RQ4：与外部 baseline 相比能否更深入测试保护逻辑

外部 baseline：

1. **riscv-dv**：特性匹配 baseline，启用 M/S/U、page table、PMP/ePMP 配置。
2. **Cascade**：成熟的通用 RISC-V CPU fuzzer baseline。

受控比较集中在 Rocket 和 BOOM，因为两者具有较成熟的 PMPFuzz、riscv-dv、Cascade 和 mutant 运行条件。

跨工具比较的共同指标只能来自相同 DUT 插桩，例如：

- PMP match；
- allow/deny；
- PTW memory access；
- final physical access；
- page-table level；
- TLB activity；
- trap selection；
- instruction commit/squash；
- forbidden side-effect suppression。

外部 baseline 的 PMPFuzz semantic/pairwise/predicate 字段必须为 `null`，不能伪造。

### RQ5：缺陷检测能力

对经过独立确认、可传播到架构结果的 protection-specific mutants 和已知真实回归进行检测。

报告：

- detected faults / eligible faults；
- time-to-first-detection；
- tests-to-first-detection；
- 10 次独立 campaign 中的发现概率；
- false positive；
- false negative；
- deduplicated root causes；
- 正确 stage attribution；
- replay 和确认状态。

### RQ6：跨 DUT 和真实芯片可部署性

PMPFuzz 完整系统需要覆盖：

- Rocket；
- BOOM；
- CVA6；
- XiangShan；
- U74 实际硬件；
- C910 实际硬件。

C910 只运行能力模型判定为适用的场景，不强制生成不存在的 PMP 结果。真实硬件需要同时记录黑盒覆盖随时间的变化。

### RQ7：性能和插桩开销

报告：

- tests/second；
- generator、compile、DUT execution、judgment 的时间分解；
- clean RTL 与 instrumented RTL 的运行时间差；
- 每个 campaign 的磁盘占用；
- 每个确认漏洞或 mutant detection 消耗的 core-hours。

## 3. 实验方法矩阵

### 3.1 内部覆盖消融

每种 coverage mode 单独进行，不要临时发明一个未经论文定义的 combined score。

| 实验 | 变体 A | 变体 B | DUT | 重复 |
|---|---|---|---|---:|
| E1-sem | Uniform random order | semantic-guided | Rocket、BOOM | 各 10 seeds |
| E1-pair | Uniform random order | pairwise-guided | Rocket、BOOM | 各 10 seeds |
| E1-triple | Uniform random order | security-triples-guided | Rocket、BOOM | 各 10 seeds |
| E1-pred | Uniform random order | predicates-guided | Rocket、BOOM | 各 10 seeds |

公平要求：

- 每一对 random/guided 使用相同 seed；
- 使用相同 capability-scoped candidate space；
- 使用相同初始 bootstrap batch；
- 相同 round size；
- 相同 DUT、工具链、timeout 和时间预算；
- 不重复执行已经选择过的 candidate；
- random 是无放回的均匀随机排列；
- guided 只使用已完成、execution-qualified 的历史覆盖。

建议初始配置：

- bootstrap batch：32 cases；
- 后续每 round：32 cases；
- pilot 使用 3 seeds；
- 正式使用 10 seeds；
- 正式时间预算在 pilot 后固定，优先选择 6h；若多数曲线仍未进入平台期，再提升到 24h；
- 一旦固定正式预算，不得根据最终结果调整。

### 3.2 白盒反馈消融

| 实验 | 变体 A | 变体 B | DUT | 重复 |
|---|---|---|---|---:|
| E2-WB | PMPFuzz-BB | PMPFuzz-BB+WB | Rocket、BOOM | 各 10 seeds |

两者共享同一 bootstrap batch。每个后续 round 最多 32 cases。

`PMPFuzz-BB+WB` 的 round 选择规则固定如下：

1. 从白盒反馈 schedule 中最多选择 16 个未运行 case；
2. 从当前指定的黑盒 coverage mode 中补足至 32 个；
3. 去重；
4. 白盒反馈为空时全部由黑盒覆盖调度补足；
5. 不允许额外增加总 case 数或时间预算。

这段策略应由 evaluation driver 完成，不要修改 verdict，也不要放松生成约束。

### 3.3 外部 baseline

| 实验 | 方法 | DUT | 共同指标 | 重复 |
|---|---|---|---|---:|
| E3 | PMPFuzz | Rocket、BOOM | DUT security events、fault detection | 各 10 seeds |
| E3 | riscv-dv | Rocket、BOOM | DUT security events、fault detection | 各 10 seeds |
| E3 | Cascade | Rocket、BOOM | DUT security events、fault detection | 各 10 seeds |

必须同时做两种预算：

1. fixed wall-clock；
2. fixed executed-test count。

fixed wall-clock 衡量端到端效率；fixed test count 分离生成质量与吞吐率。

### 3.4 Protection mutant 实验

目标数量：20–30 个经过确认的 protection-specific faults，优先在 Rocket 和 BOOM 上平衡分布。

类别至少包括：

- PMP first-match / priority；
- TOR/NA4/NAPOT boundary；
- partial overlap；
- privilege、MPRV、MPP；
- PTW memory access PMP；
- final physical PMP；
- PTE permissions；
- A/D update；
- TLB/PMP stale permission；
- trap cause/address/stage；
- denied-store side effect；
- Smepmp MML/MMWP/RLB，仅在 DUT 支持时。

每个 fault 必须满足：

1. mutation site 位于预先声明的 protection chain module；
2. clean build 通过控制测试；
3. mutant build 可以构建；
4. 有独立 witness 或形式化证据证明可影响架构可见结果；
5. witness 不进入 fuzz seed corpus；
6. 不修改测试 harness、日志解析器或 PMPFuzz；
7. 每个 mutant 有独立 patch、SHA256 和元数据。

可以借鉴 Encarsia 的 Signal Mix-up 和 Broken Conditional 变换及其 formal observability filtering，但必须限定到 protection chain，不能直接把整个通用 EnCorpus 当成 PMPFuzz 的保护缺陷集合。

## 4. 必须先实现的时间—覆盖率记录基础设施

### 4.1 为什么现有数据不够

当前 `result.json` 中的 `elapsed_seconds` 只表示单个 case 的执行耗时。`runner.py` 支持多个 future 并发完成，随后又按 case 名排序结果。因此：

- 不能依靠结果文件排序；
- 不能依靠文件 mtime；
- 不能累加 per-case elapsed；
- 必须在 future 实际完成时记录 campaign wall-clock。

**状态说明：实验方案能够生成可靠的时间—覆盖率曲线，但当前代码尚未完成这项持久化记录。正式 campaign 在 timeline callback、JSONL recorder 和末点一致性测试全部通过前禁止启动。**

### 4.2 需要修改和新增的代码

只允许修改代码和测试，不允许修改论文。

建议文件：

```text
pmpfuzz/runner.py
pmpfuzz/coverage.py
pmpfuzz/coverage_qualification.py
pmpfuzz/timeline.py                         # 新增
pmpfuzz/__main__.py
scripts/evaluation/run_closed_loop_campaign.py    # 新增
scripts/evaluation/validate_timeline.py           # 新增
scripts/evaluation/aggregate_results.py           # 新增
scripts/evaluation/plot_coverage_time.py          # 新增
scripts/evaluation/baseline_adapters/riscv_dv.py  # 新增
scripts/evaluation/baseline_adapters/cascade.py   # 新增
configs/evaluation/experiment_matrix.yaml         # 新增
tests/test_timeline.py                            # 新增
tests/test_evaluation_scripts.py                  # 新增
```

#### A. `runner.py`

为 `_run_indexed_work_with_budget()` 增加可选 `on_complete` callback。

callback 必须在主线程、future 完成并返回结果之后调用，参数至少包括：

```text
index
scenario
CampaignResult
completion_seq
campaign_elapsed_seconds
```

`campaign_elapsed_seconds` 必须由同一个 `time_fn()` 相对于 campaign `start_time` 计算。测试可注入 fake clock。

#### B. 共享 coverage target 构造

当前正式 coverage 和 timeline 不能各写一套 denominator 逻辑。应从 `coverage.py` 中提取一个公共函数，由正式 coverage 和 timeline 共用。

公共函数输入：

```text
target profile group
DUT capability
include_experimental
seed used for target enumeration
```

公共函数输出四组 target bins：

```text
semantic
pairwise
security_triples
predicates
```

不要把数学公式重新手写进 timeline。直接复用现有：

- `qualify_result_for_coverage()`；
- `semantic_bins_for_case()`；
- `combo_bins_for_case()`；
- `contract_predicates_for_case()`；
- capability-scoped target enumeration。

#### C. `pmpfuzz/timeline.py`

实现 append-only `TimelineRecorder`。

每次 case 完成后：

1. 读取刚写出的 `case.json` 和 `result.json`；
2. 调用 `qualify_result_for_coverage()`；
3. 只有 eligible case 才更新覆盖集合；
4. valid mismatch 必须和 pass 一样贡献覆盖；
5. timeout、inconclusive、compile/infra failure、unsupported 和无效观测不能改变覆盖；
6. 写入一行 JSONL；
7. 立即 flush，避免长 campaign 中断后丢失数据。

CLI 增加：

```text
--record-timeline
--campaign-id
--variant
```

实验 driver 必须始终启用 `--record-timeline`。

### 4.3 Timeline JSONL schema

文件位置：

```text
<run-dir>/metrics/coverage_timeline.jsonl
```

第一行是 `completion_seq=0` 的起点。每完成一个 case 追加一行。

每行至少包含：

```json
{
  "schema_version": 1,
  "campaign_id": "E1-sem__rocket-clean__guided__seed-0001",
  "variant": "guided-semantic",
  "dut": "rocket-clean",
  "seed": 1,
  "completion_seq": 12,
  "case_id": "...",
  "profile": "pmp-boundary",
  "elapsed_wall_seconds": 53.721,
  "case_elapsed_seconds": 4.193,
  "completed_cases": 12,
  "eligible_cases": 10,
  "status": "pass",
  "failure_class": null,
  "coverage_eligible": true,
  "qualification_reason": "eligible",
  "semantic_covered": 23,
  "semantic_target": 90,
  "semantic_rate": 0.255556,
  "pairwise_covered": 51,
  "pairwise_target": 410,
  "pairwise_rate": 0.12439,
  "security_triples_covered": 17,
  "security_triples_target": 900,
  "security_triples_rate": 0.018889,
  "predicates_covered": 8,
  "predicates_target": 21,
  "predicates_rate": 0.380952,
  "new_semantic_bins": 2,
  "new_pairwise_bins": 5,
  "new_security_triple_bins": 1,
  "new_predicate_bins": 0,
  "whitebox_distinct_events": 119,
  "new_whitebox_events": 3
}
```

注意：上面数字只是 schema 示例，不能写入论文或当作实验结果。

还需要保存：

```text
<run-dir>/metrics/campaign_metadata.json
<run-dir>/metrics/commands.log
<run-dir>/metrics/environment.json
```

其中 `campaign_metadata.json` 包含：

- UUID；
- start/end UTC；
- source SHA；
- DUT SHA/binary SHA256；
- baseline SHA；
- seed；
- variant；
- coverage mode；
- round size；
- time budget；
- jobs；
- timeout；
- host name；
- exact command line。

### 4.4 Timeline 验收测试

必须新增自动测试验证：

1. `elapsed_wall_seconds` 单调不减；
2. `completion_seq` 从 0 连续增长；
3. 四类 coverage rate 单调不减；
4. valid mismatch 增加 coverage；
5. invalid observation 不增加 coverage；
6. wrong phase 不增加 coverage；
7. timeout/inconclusive/unsupported 不增加 coverage；
8. denominator 在同一 campaign 中保持不变；
9. denominator 为 0 时 rate 为 `null`；
10. timeline 最后一行四类 covered/target/rate 与最终 `coverage/coverage.json` 完全一致；
11. 并发 fake tasks 按实际完成顺序记录，而不是按 case 名排序；
12. 进程中断后 JSONL 已完成行仍可解析；
13. 已存在非空输出目录时拒绝静默覆盖。

## 5. Closed-loop campaign driver

实现 `scripts/evaluation/run_closed_loop_campaign.py`，负责连续 round，而不是手工运行几十次命令。

### 5.1 Driver 输入

```text
--experiment-id
--variant random|guided|bb|bb-wb
--coverage-mode semantic|pairwise|security-triples|predicates
--dut
--seed
--round-size
--time-budget
--per-case-timeout
--artifact-root
--whitebox-artifacts
```

### 5.2 Driver 行为

1. 检查输出目录不存在；
2. 记录环境和命令；
3. 生成相同的 capability-scoped candidate pool；
4. 执行共同 bootstrap batch；
5. 每 round 完成后运行正式 execution coverage；
6. `random` 使用未运行 candidate 的随机排列；
7. `guided` 调用对应 coverage mode 的 scheduler；
8. `bb-wb` 提取 whitebox signals，构建 feedback schedule，再按 16+16 规则合并；
9. 去重并排除已执行 candidate；
10. 所有 round 的墙钟时间连续累计，调度和反馈计算时间也计入 campaign wall-clock；
11. 达到时间预算、候选耗尽或目标覆盖完全时结束；
12. 写出 campaign-level timeline、summary 和完整 round 索引。

每个 round 可以保存在：

```text
<campaign>/rounds/round_0000/
<campaign>/rounds/round_0001/
...
```

campaign-level timeline 必须合并各 round，但不能丢失原始 round timeline。

## 6. 时间—覆盖率图：强制交付

时间—覆盖率图是本任务的强制结果，不是可选项。

### 6.1 图 A：黑盒执行有效覆盖率随时间变化

文件：

```text
plots/fig_coverage_vs_time_internal.pdf
plots/fig_coverage_vs_time_internal.png
aggregate/coverage_vs_time_internal.csv
```

布局为 2×2 子图：

1. Semantic coverage；
2. Pairwise coverage；
3. Security-triple coverage；
4. Protection-predicate coverage。

每个子图至少包含：

- Random；
- Guided。

如果同一图加入 BB+WB，必须说明它针对哪个 coverage mode，不能混合未经定义的总分。

绘图规范：

- X 轴：elapsed wall-clock time，单位小时；
- Y 轴：execution-qualified coverage，0%–100%；
- 每个单次 campaign 是 step curve，使用 `where="post"`；
- 主线：10 个 seeds 的中位数；
- 阴影：Q1–Q3；
- 不做平滑拟合；
- 不截断 Y 轴；
- 使用色盲友好配色；
- PDF 为矢量图；
- PNG 至少 300 dpi；
- 图例、字体和线宽统一；
- caption 数据另写入 `figure_metadata.json`。

不同 run 的原始时间点不同。聚合时：

1. 在 `[0, time_budget]` 上建立 200 个等间隔时间点；
2. 对每个 run 使用 last observation carried forward；
3. 未开始前覆盖率为 0；
4. 不能线性插值制造不存在的覆盖增长；
5. 再计算中位数、Q1、Q3 和 bootstrap 95% CI；
6. CSV 同时保存所有统计量。

### 6.2 图 B：覆盖率随执行测试数量变化

文件：

```text
plots/fig_coverage_vs_cases_internal.pdf
plots/fig_coverage_vs_cases_internal.png
aggregate/coverage_vs_cases_internal.csv
```

X 轴为 completed cases 或 execution-qualified cases，两种口径应分别输出。该图用于区分“调度质量提升”和“只是执行更快”。

### 6.3 图 C：共同白盒安全事件随时间变化

文件：

```text
plots/fig_security_events_vs_time.pdf
plots/fig_security_events_vs_time.png
aggregate/security_events_vs_time.csv
```

比较：

- PMPFuzz-BB；
- PMPFuzz-BB+WB；
- riscv-dv；
- Cascade。

分 Rocket 和 BOOM 两个 panel。Y 轴是相同插桩定义下的 distinct security-relevant events，不能使用跨 DUT 事件并集计算一个误导性百分比。

### 6.4 图 D：缺陷发现时间

文件：

```text
plots/fig_fault_detection_time.pdf
plots/fig_fault_detection_time.png
aggregate/fault_detection_time.csv
```

使用 Kaplan–Meier 或带 censored marks 的 time-to-detection ECDF。未在预算内发现的 run 必须作为 censored 数据保留，不能删除。

## 7. Baseline 安装和适配

第三方代码放在：

```text
/home/dubhe/wjs/pmpfuzz-eval-third-party/
├── riscv-dv/
└── encarsia/
```

Cascade 不放入上述新目录。服务器已有官方 Docker artifact、Cascade generator 和相关 DUT 构建，应复用现有部署。

### 7.1 riscv-dv

riscv-dv 由 DeepSeek 负责安装完整依赖、构建并完成 feature smoke。不得只克隆仓库而不验证 PMP/privileged 功能。

```bash
cd /home/dubhe/wjs
mkdir -p pmpfuzz-eval-third-party
cd pmpfuzz-eval-third-party
git clone https://github.com/chipsalliance/riscv-dv.git
cd riscv-dv
git rev-parse HEAD
```

优先评估开源 eUVM port：

```bash
cd /home/dubhe/wjs/pmpfuzz-eval-third-party/riscv-dv/euvm/build
make -j "$(nproc)"
make run INSTRCOUNT=1000
```

正式实验前必须完成 feature smoke：

- 生成 RV64 程序；
- 生成 M/S/U transition；
- 生成 page table / `satp`；
- 生成 `pmpcfg` / `pmpaddr`；
- 能在 Spike 上完成；
- 能在 Rocket/BOOM 的统一执行环境中运行；
- 保存 generator config 和 seed。

如果默认 eUVM 命令没有启用 PMP，不得把普通 RV64 随机程序冒充 PMP baseline。应查明并记录启用参数；无法启用时停止该 baseline 并报告阻塞原因。

### 7.2 Cascade

2026-07-12 已进行只读核实。真正的 Cascade baseline 位于服务器现有 Docker 部署中：

```text
container name: codex_cascade_cpu_fuzzing
container id at audit time: afce3773b8c5
image: docker.io/ethcomsec/cascade-artifacts:latest
image id: sha256:3d403b05be4a57fc1910b7e73bc807d499e382f73197ae8978ca1954524f0a11
repo digest: ethcomsec/cascade-artifacts@sha256:3d403b05be4a57fc1910b7e73bc807d499e382f73197ae8978ca1954524f0a11
host mount: /home/dubhe/wjs/cascade_cpu_fuzzing/mount
container mount: /cascade-mountdir
```

该镜像对应 USENIX Security 2024 论文 *Cascade: CPU Fuzzing via Intricate Program Generation* 的 artifact。服务器保存的 artifact README 明确指向 `cascade-meta`，并说明正式 fuzzing 入口为：

```text
/cascade-meta/fuzzer/do_fuzzsingle.py
/cascade-meta/fuzzer/do_fuzzdesign.py
```

服务器挂载的 XiangShan 适配目录中也存在实际 Cascade generator 源码，而不只是仿真后端：

```text
/home/dubhe/wjs/cascade_cpu_fuzzing/mount/cascade_xiangshan_adapt/cascade-meta/fuzzer/do_fuzzsingle.py
/home/dubhe/wjs/cascade_cpu_fuzzing/mount/cascade_xiangshan_adapt/cascade-meta/fuzzer/do_fuzzdesign.py
/home/dubhe/wjs/cascade_cpu_fuzzing/mount/cascade_xiangshan_adapt/cascade-meta/fuzzer/cascade/fuzzsim.py
```

这些文件具有 2023 ETH Zurich / Flavien Solt 的 Cascade 版权头，并调用 `fuzz_single_from_descriptor`、`fuzzdesign` 和 Cascade RTL simulation flow。

服务器还有另一个使用相同镜像的 `codex_feedbackfuzz_cpu_fuzzing` 容器。它属于另一套 feedback-fuzzing 工作目录，不应默认用于标准 Cascade baseline。标准 baseline 优先使用 `codex_cascade_cpu_fuzzing`。

DeepSeek 不得执行 `docker pull`、`docker run`、`docker stop`、`docker rm` 或重建镜像。该容器已经运行。正式实验前先做只读核实：

```bash
docker ps -a
docker images
docker inspect codex_cascade_cpu_fuzzing
docker image inspect ethcomsec/cascade-artifacts:latest
```

然后只读确认容器内 source，不启动 fuzzing：

```bash
docker exec codex_cascade_cpu_fuzzing \
  bash -lc 'test -f /cascade-meta/fuzzer/do_fuzzsingle.py && test -f /cascade-meta/fuzzer/do_fuzzdesign.py'

docker exec codex_cascade_cpu_fuzzing \
  bash -lc 'sha256sum /cascade-meta/fuzzer/do_fuzzsingle.py /cascade-meta/fuzzer/do_fuzzdesign.py /cascade-meta/fuzzer/cascade/fuzzsim.py'
```

上述 `docker exec` 只做 source 存在性和哈希核实，不运行 Cascade campaign。

当前 PMPFuzz 代码和 Cascade DUT 还涉及以下主机路径：

```text
/home/dubhe/wjs/boom_host_deploy/cascade-chipyard
/home/dubhe/wjs/boom_host_deploy/cascade-chipyard/cascade-rocket/build/run_vanilla_notrace_0.1/default-verilator/Vtop_tiny_soc
/home/dubhe/wjs/cascade_cpu_fuzzing/mount/cascade_xiangshan_adapt
```

其中 `/home/dubhe/wjs/boom_host_deploy/cascade-chipyard` 是 Cascade 的 DUT/design repository，不是 Cascade generator 本身。审计时其信息为：

```text
remote: https://github.com/cascade-artifacts-designs/cascade-chipyard
HEAD: 0317c19b4148afb95243c39ca1f3772916a29a52
state: dirty，包含 Rocket/BOOM core file 和 submodule 修改
```

因此必须分别冻结：

1. Cascade Docker image digest；
2. 容器内 `/cascade-meta` source hashes；
3. `cascade-chipyard` Git SHA 和 dirty patch；
4. 最终使用的 Rocket/BOOM simulator binary SHA256。

DeepSeek 首先执行只读盘点：

```bash
test -d /home/dubhe/wjs/boom_host_deploy/cascade-chipyard
test -x /home/dubhe/wjs/boom_host_deploy/cascade-chipyard/cascade-rocket/build/run_vanilla_notrace_0.1/default-verilator/Vtop_tiny_soc
test -d /home/dubhe/wjs/cascade_cpu_fuzzing
find /home/dubhe/wjs -maxdepth 4 -type d -iname '*cascade*' -print
```

对找到的每个 Cascade DUT Git 仓库记录：

```bash
git -C <cascade-path> rev-parse HEAD
git -C <cascade-path> status --short
git -C <cascade-path> remote -v
```

如果 Cascade DUT 仓库是 dirty 状态：

1. 保存 `git diff` 和 `git diff --stat`；
2. 不得 reset、checkout 或 pull；
3. 判断实际运行二进制是否依赖这些修改；
4. 将 patch、仓库 SHA 和二进制 SHA256 写入 baseline manifest；
5. 在整个正式实验期间冻结该版本。

如果存在多个 Cascade 容器或适配副本，标准 Rocket/BOOM baseline 优先使用官方镜像容器 `codex_cascade_cpu_fuzzing` 中的 `/cascade-meta`。`cascade_xiangshan_adapt` 只用于 XiangShan 适配实验，不能替代标准 baseline。选择后不得在正式实验中途切换。

使用官方 artifact 文档构建 Rocket 和 BOOM。正式运行前必须证明：

- 生成程序包含 privilege transitions 和 CSR interactions；
- 程序在 clean DUT 上可运行；
- 共同 DUT security probes 能从该程序执行中得到事件；
- native bug result 可以映射到统一的 detection record；
- 所有修改均以 patch 保存，不修改 PMPFuzz oracle。

仓库中现有 `rocket-cascade` 只是 PMPFuzz testcase 的一个执行后端，不等于已经完成 Cascade generator baseline。不得把两者混为一谈。

### 7.3 Encarsia

Encarsia 只用于 mutant 生成和验证方法，不作为 PMPFuzz 的 baseline。

```bash
cd /home/dubhe/wjs/pmpfuzz-eval-third-party
git clone https://github.com/comsec-group/encarsia.git
cd encarsia
git rev-parse HEAD
```

先用官方小规模示例验证工具链，再限制 source/module 范围生成 protection-chain mutants。不要直接启动 1 TB 级别的完整 EnCorpus 实验。

## 8. 服务器环境记录

在任何正式实验前生成：

```text
/home/dubhe/wjs/pmpfuzz-eval-artifacts/manifests/environment.json
/home/dubhe/wjs/pmpfuzz-eval-artifacts/manifests/python-freeze.txt
/home/dubhe/wjs/pmpfuzz-eval-artifacts/manifests/git-shas.txt
/home/dubhe/wjs/pmpfuzz-eval-artifacts/manifests/tool-versions.txt
/home/dubhe/wjs/pmpfuzz-eval-artifacts/manifests/dut-binaries.sha256
```

至少记录：

- hostname；
- OS、kernel；
- CPU 型号、逻辑核数；
- RAM；
- Python；
- GCC/RISC-V GCC；
- Spike；
- Verilator；
- Java、Scala、sbt；
- PMPFuzz SHA；
- Rocket/BOOM/CVA6/XiangShan SHA；
- riscv-dv/Cascade/Encarsia SHA；
- DUT binary SHA256；
- 插桩 patch SHA256；
- capability files；
- 每个 campaign 的完整命令。

绘图环境使用独立 venv：

```bash
cd /home/dubhe/wjs/riscv-pmp-fuzz-eval
python3 -m venv .venv-eval
source .venv-eval/bin/activate
python -m pip install --upgrade pip
python -m pip install numpy pandas matplotlib scipy seaborn lifelines pyyaml
python -m pip freeze > /home/dubhe/wjs/pmpfuzz-eval-artifacts/manifests/python-freeze.txt
```

## 9. 开发和冒烟验证顺序

必须使用测试先行方式完成时间线功能。

### 9.1 RED：先写失败测试

新增并运行：

```bash
python -m unittest tests.test_timeline tests.test_evaluation_scripts
```

确认测试因尚未实现 timeline/callback 而失败，并保存测试日志。

### 9.2 GREEN：实现最小功能

完成 callback、公共 target bins、timeline recorder、validation 和 plot 脚本后运行：

```bash
python -m unittest tests.test_timeline tests.test_coverage_qualification tests.test_coverage tests.test_runner tests.test_evaluation_scripts
python -m unittest discover -s tests
```

全部通过后才运行 smoke。

### 9.3 Spike smoke

```bash
cd /home/dubhe/wjs/riscv-pmp-fuzz-eval
python3 -m pmpfuzz env-check
python3 -m pmpfuzz run \
  --dut spike \
  --profile pmp-boundary \
  --count 8 \
  --seed 1 \
  --jobs 1 \
  --time-budget 10m \
  --per-case-timeout 10 \
  --record-timeline \
  --campaign-id smoke-spike \
  --variant smoke \
  --out /home/dubhe/wjs/pmpfuzz-eval-artifacts/pilot/smoke-spike

python3 -m pmpfuzz coverage \
  --run-dir /home/dubhe/wjs/pmpfuzz-eval-artifacts/pilot/smoke-spike

python3 scripts/evaluation/validate_timeline.py \
  --campaign /home/dubhe/wjs/pmpfuzz-eval-artifacts/pilot/smoke-spike

python3 scripts/evaluation/plot_coverage_time.py \
  --input /home/dubhe/wjs/pmpfuzz-eval-artifacts/pilot/smoke-spike \
  --out /home/dubhe/wjs/pmpfuzz-eval-artifacts/pilot/smoke-plot
```

### 9.4 RTL smoke

分别对 `rocket-clean` 和 `boom-clean` 运行 8–16 个 `pmp-boundary` 或 `sv39-ptw-pmp-matrix` cases，启用 `--whitebox-artifacts`。每个 smoke 必须通过 timeline 验证，并生成一张测试图。

## 10. Pilot 实验

正式长跑前执行：

- DUT：Rocket、BOOM；
- variants：random、guided、BB、BB+WB；
- coverage modes：semantic、predicates；
- seeds：1、2、3；
- round size：32；
- 每个 run：30–60 分钟；
- mutants：最多 5 个；
- baseline：riscv-dv 和 Cascade 各完成至少一个可运行 smoke。

Pilot 只用于回答：

- 每小时能运行多少 cases；
- 6h 是否足以进入覆盖平台期；
- timeline 是否稳定；
- DUT 构建是否共享冲突；
- 数据量和磁盘占用；
- baseline 是否真正进入 protection paths；
- mutant 是否可观察。

Pilot 结果单独保存在 `pilot/`，不得与正式结果混合。

Pilot 完成后生成 `pilot_decision.md`，固定：

- 正式 time budget；
- jobs；
- per-case timeout；
- round size；
- seeds；
- DUT commits；
- baseline commits；
- 纳入的 mutants。

固定后不得根据正式实验输赢修改。

## 11. 正式实验执行

### 11.1 Seeds

使用明确列表，不使用临时随机种子：

```text
101, 202, 303, 404, 505, 606, 707, 808, 909, 1010
```

内部 paired comparison 使用相同 seed。每个 campaign 输出目录必须包含 seed。

### 11.2 Campaign 输出结构

```text
campaigns/<experiment>/<dut>/<variant>/<coverage-mode>/seed-<seed>/
├── campaign.json
├── rounds/
├── metrics/
│   ├── coverage_timeline.jsonl
│   ├── coverage_timeline.csv
│   ├── campaign_metadata.json
│   ├── environment.json
│   └── commands.log
├── aggregate/
├── coverage/
├── whitebox/
├── failures/
└── validation.json
```

严禁覆盖已有 seed 目录。重跑时创建 `retry-01`，并在排除记录中说明原 run 是否进入统计。

### 11.3 并行策略

- make-based DUT 的单个 campaign 保持 `jobs=1`；
- 并行化应发生在不同 campaign 之间；
- 每个并行 campaign 必须有独立输出目录；
- 如果 DUT build/run directory 会共享写入，不得并行相同 DUT；
- 不要为了加速而改变某个方法的 CPU 核数；
- 每个方法获得相同 core budget。

### 11.4 中途监控

每个长 campaign 至少每 30 分钟记录：

- 进程仍在运行；
- timeline 继续增长；
- 磁盘空间；
- 最近完成 case；
- 当前覆盖率；
- timeout/infra failure 数；
- DUT 是否出现异常残留进程。

监控日志放入 campaign 的 `metrics/monitor.log`。不得通过修改运行状态来“修复”某一方法的结果；发现环境故障时整次 run 标为 infrastructure-invalid，并使用预先定义的 retry 规则。

## 12. Mutant 和真实漏洞确认

每个候选检测结果按以下流程确认：

```text
original campaign mismatch
→ 同一 ELF/场景在目标 mutant 或 DUT 重放 3 次
→ clean DUT 重放 3 次
→ Spike golden model 重放 3 次
→ 至少一个非目标 clean RTL 重放 3 次（适用时）
→ instrumented target 重放 3 次
→ 根因去重
→ 保存全部日志、ELF、case、result、patch 和 SHA256
```

结果分类：

```text
confirmed fault
candidate fault
model disagreement
inconclusive observation
infrastructure failure
duplicate root cause
```

只有 `confirmed fault` 进入主要 bug detection 表。其余结果保留并在附录数据中说明。

## 13. 真实硬件实验

在完成 RTL 正式实验后再进行 U74 和 C910。

要求：

- 使用已有的实验驱动微架构逆向结果和 capability profile；
- 记录板卡型号、SoC、核心、固件/OpenSBI/U-Boot/Linux 版本；
- 记录加载通道、串口配置、reset/cold boot 策略；
- 每个 case 的部署和恢复时间计入 wall-clock；
- 生成黑盒 execution-qualified coverage timeline；
- 保存原始串口日志；
- 不在物理目标上强制运行 capability 判定为 unsupported 的场景；
- U74 和 C910 分别画 PMPFuzz-only coverage-vs-time 曲线；
- 实际漏洞只在完成重放和根因确认后报告。

## 13A. 标准实验数据契约（强制）

本节不是建议，而是最终交付数据必须满足的格式。PMPFuzz、riscv-dv 和 Cascade 的原始输出可以不同，但进入统计与绘图前，必须转换为下面定义的统一数据表。不得只提交截图、终端日志或人工整理的 Excel 表。

### 13A.1 通用编码、时间和缺失值规则

- 文本文件统一使用 UTF-8 编码。
- 原始逐事件记录使用 JSON Lines（`.jsonl`）：每行一个完整 JSON 对象，只追加，不覆盖既有记录。
- 规范化表和聚合表使用带表头的逗号分隔 CSV；字段中出现逗号、双引号或换行时按标准 CSV 规则转义。
- 元数据、统计检验结果和校验报告使用 JSON。
- 时间戳统一使用 UTC ISO 8601 格式，例如 `2026-07-12T08:30:15.123Z`。
- 所有耗时统一使用秒，字段名以 `_seconds` 结尾，可为小数；计数必须为非负整数；覆盖率和比例使用 `[0,1]` 范围内的小数。
- 小数点固定使用 `.`，不得加入千位分隔符，不得写百分号。
- JSON 中缺失或不适用的值写 `null`；CSV 中留空。不得用 `N/A`、`unknown`、`-1` 或虚假的 `0` 代替缺失值。
- 布尔值只使用 `true` 和 `false`。
- 每个 JSON/JSONL 对象和每张 CSV 表都必须包含 `schema_version`，本轮实验固定为 `1.0`。
- Parquet 可以作为可选的派生副本，但不能作为唯一数据源。
- 所有论文图表必须由规范化 CSV 或聚合 CSV 通过脚本生成，禁止手工修改绘图数据。

### 13A.2 标准目录结构

最终结果目录至少包含：

```text
evaluation-results/<experiment_id>/
├── raw/                 # 各工具未经聚合的原始记录和日志
├── normalized/          # 按本节数据契约转换后的统一表
├── aggregate/           # 跨种子、跨 DUT 的统计结果
├── plots/               # PDF、PNG 和绘图脚本
├── schemas/             # JSON Schema 与字段说明
├── manifests/           # 软件版本、命令、环境和文件哈希
└── README.md            # 数据说明和一键重建图表的命令
```

`raw/` 只保存原始事实，不允许在后处理时回写。任何清洗、筛选、补充标签或格式转换都写入 `normalized/`，从而能够追溯论文中的每个数字。

### 13A.3 活动清单：`normalized/campaigns.csv`

每个独立的“工具 × 变体 × DUT × seed”运行占一行，主键为 `campaign_id`。列顺序固定如下：

```text
schema_version,experiment_id,campaign_id,method,variant,dut,seed,coverage_mode,source_sha,dut_sha,dut_binary_sha256,baseline_sha,start_utc,end_utc,time_budget_seconds,round_size,jobs,per_case_timeout_seconds,completed_cases,eligible_cases,pass_count,mismatch_count,timeout_count,inconclusive_count,infra_failure_count,excluded,exclusion_reason,artifact_path
```

字段约束：

- `method` 只使用 `pmpfuzz`、`riscv-dv` 或 `cascade`。
- `variant` 用于区分 PMPFuzz 完整版、消融配置或 baseline 配置；完整 PMPFuzz 统一写 `full`。
- `coverage_mode` 只使用 `semantic`、`rtl`、`blackbox_event` 或 `none`；如果一次活动同时产生多类覆盖率，这里写主要反馈模式，详细数据在时间序列表中分行记录。
- `source_sha` 是被测 PMPFuzz 或 baseline 的 Git 提交；`baseline_sha` 仅对 baseline 必填。
- `dut_binary_sha256` 是实际执行的仿真器、bitstream、固件镜像或关键 DUT 构建产物的 SHA-256。
- `completed_cases` 表示完成一次 DUT 执行并得到终态的测试数；`eligible_cases` 表示通过观测有效性判定、可贡献覆盖率的测试数。
- `excluded=true` 的活动不得进入主要统计，且 `exclusion_reason` 和 `artifact_path` 必填。

### 13A.4 时间—覆盖率长表：`normalized/coverage_timeseries.csv`

这是绘制所有时间—覆盖率曲线的唯一标准输入。每个活动、覆盖模式和完成时刻占一行；联合主键为 `(campaign_id, coverage_mode, completion_seq)`。列顺序固定如下：

```text
schema_version,experiment_id,campaign_id,method,variant,dut,seed,coverage_mode,completion_seq,elapsed_wall_seconds,completed_cases,eligible_cases,covered_bins,target_bins,coverage_rate,new_bins,status,failure_class,case_id
```

字段约束：

- `completion_seq` 从 1 开始，按测试完成顺序严格递增；不能使用提交顺序代替完成顺序。
- `elapsed_wall_seconds` 从该活动进程开始计时，必须单调不减，包含生成、编译、DUT 执行、判断和反馈的全部墙钟时间。
- `covered_bins` 是截至该时刻累计覆盖的目标数；`target_bins` 是该 DUT 和覆盖模式的固定目标总数；`new_bins` 是当前测试新覆盖的目标数。
- 当 `target_bins > 0` 时，`coverage_rate = covered_bins / target_bins`；否则三者中的不可定义项留空，禁止伪造为 `0/N`。
- 无效执行可以增加 `completed_cases`，但不能增加 `eligible_cases`、`covered_bins` 或 `new_bins`。
- 有效 mismatch 仍属于已执行且可分析的语义组合，因此可以贡献覆盖率。
- baseline 若不能提供 PMPFuzz 的保护语义覆盖，不得把指令数、代码覆盖或事件数伪装成 `semantic`。应分别写为 `rtl` 或 `blackbox_event`；不适用的 `covered_bins`、`target_bins` 和 `coverage_rate` 留空。
- `status` 使用统一枚举：`pass`、`mismatch`、`timeout`、`inconclusive`、`infra_failure`。

除逐测试完成记录外，后处理脚本还应从该长表生成固定墙钟采样表，例如每 60 秒一个点。绘图时所有工具使用同一时间网格，活动在结束后不外推覆盖率。

### 13A.5 黑盒安全事件长表：`normalized/security_event_timeseries.csv`

黑盒活动无法取得 RTL 信号时，用统一的安全相关事件空间记录反馈。每个新观察到的事件占一行；联合主键为 `(campaign_id, completion_seq, event_namespace, event_id)`。列顺序固定如下：

```text
schema_version,experiment_id,campaign_id,method,variant,dut,seed,completion_seq,elapsed_wall_seconds,event_namespace,event_category,event_id,is_new_event,total_distinct_events,case_id
```

`event_namespace` 用于区分 trap、访问结果、权限组合、阶段结果等事件域；`event_id` 必须是由规范化事件字段稳定计算的标识，不能使用进程内随机哈希。完整的事件字段定义写入 `schemas/data_dictionary.md`。

### 13A.6 覆盖阈值表：`aggregate/coverage_threshold_times.csv`

用于回答“达到相同覆盖率需要多长时间”。每个活动、覆盖模式和阈值占一行，列顺序固定如下：

```text
schema_version,experiment_id,campaign_id,method,variant,dut,seed,coverage_mode,threshold,threshold_reached,elapsed_wall_seconds,completed_cases,eligible_cases,censored
```

推荐阈值至少包含 `0.25,0.50,0.75,0.90`。若活动结束仍未达到阈值，`threshold_reached=false`、`censored=true`，时间和测试数留空；不得把活动总时长误写为达到阈值的时间。

### 13A.7 漏洞或注入缺陷发现表：`aggregate/fault_detection.csv`

每个“缺陷 × 工具 × 变体 × seed”占一行，联合主键为 `(fault_id, method, variant, seed)`。列顺序固定如下：

```text
schema_version,experiment_id,fault_id,fault_category,root_cause_id,dut,method,variant,seed,time_budget_seconds,detected,detection_elapsed_seconds,detection_completed_cases,detection_eligible_cases,censored,trigger_case_id,failure_class,stage_attribution,confirmation_status,replay_count,artifact_path
```

- 同一根因的多个表现必须共享 `root_cause_id`，避免把重复触发计为多个漏洞。
- 未在预算内发现时，`detected=false`、`censored=true`，发现时间和触发用例留空。
- `confirmation_status` 使用 `unconfirmed`、`reproduced` 或 `root_cause_confirmed`。
- `artifact_path` 指向可复现用例、日志和差分结果，不得只写自然语言描述。

### 13A.8 开销表：`aggregate/overhead.csv`

每个活动占一行，主键为 `campaign_id`。列顺序固定如下：

```text
schema_version,experiment_id,campaign_id,method,variant,dut,seed,instrumented,wall_seconds,generation_seconds,compile_seconds,dut_execution_seconds,judgment_seconds,scheduling_seconds,completed_cases,eligible_cases,tests_per_second,artifact_bytes,core_hours
```

如果某个工具无法准确拆分阶段耗时，对应分项留空，但 `wall_seconds`、测试数和 `tests_per_second` 必须提供。阶段分项之和与墙钟时间不要求相等，因为并行执行可能重叠。

### 13A.9 排除记录：`aggregate/exclusions.csv`

所有从主要统计中剔除的活动或样本必须进入该表：

```text
schema_version,experiment_id,scope,id,reason,detected_utc,action,retry_id,included_in_primary_analysis,evidence_path
```

排除标准必须在查看主要结果前固定。基础设施故障可以重跑，但原活动和原始日志不得删除；`retry_id` 指向替代活动。工具没有发现目标、覆盖率低或结果不显著不能作为排除理由。

### 13A.10 Schema、数据字典和完整性校验

必须同时交付：

- `schemas/data_dictionary.md`：解释每个字段、单位、允许值和计算方法。
- `schemas/*.schema.json`：至少校验原始 `coverage_timeline.jsonl`、活动元数据和统计 JSON。
- `manifests/artifact-sha256.txt`：递归记录原始数据、规范化数据、脚本和图表的 SHA-256。
- `aggregate/validation_report.json`：记录校验时间、校验脚本版本、错误数、警告数和逐项结果。

校验脚本至少检查：

1. 所有主键和联合主键无重复。
2. 同一活动中的 `completion_seq` 严格递增，`elapsed_wall_seconds`、累计测试数和累计覆盖数单调不减。
3. `eligible_cases <= completed_cases`，各种终态计数之和能够与活动总数对账。
4. `coverage_rate` 与 `covered_bins / target_bins` 一致，允许的浮点误差不超过 `1e-9`。
5. 时间序列最后一行与该活动的最终覆盖摘要一致。
6. 被排除的活动不会进入主要统计；重跑活动可通过 `retry_id` 追溯到原活动。
7. 图表脚本在全新输出目录中可以仅依赖已交付数据重建全部 PDF 和 PNG。

只有 `validation_report.json` 中 `error_count` 为 0，才允许把数据用于论文表格和图。

## 14. 聚合和统计

`aggregate_results.py` 必须输出：

```text
aggregate/campaign_index.csv
aggregate/qualification_summary.csv
aggregate/coverage_final.csv
aggregate/coverage_threshold_times.csv
aggregate/coverage_auc.csv
aggregate/security_event_summary.csv
aggregate/fault_detection.csv
aggregate/overhead.csv
aggregate/exclusions.csv
aggregate/statistics.json
```

### 14.1 Coverage threshold

对每个 run 和 coverage mode 计算达到以下阈值的首次时间和 case 数：

```text
50%
80%
90%
100%
```

未达到时保存为空并标记 censored，不使用 campaign 结束时间冒充达到时间。

### 14.2 AUC

同时计算：

- coverage vs wall-clock AUC；
- coverage vs completed cases AUC；
- coverage vs eligible cases AUC。

所有 AUC 在统一预算范围内归一化，避免较长 run 自动获得更大面积。

### 14.3 统计报告

每个指标至少输出：

- n；
- median；
- Q1/Q3；
- mean，仅作为补充；
- 95% bootstrap CI；
- paired difference，内部消融适用；
- Cliff's delta 或另一个适合非正态数据的 effect size。

不要只报告 p-value，也不要只报告一个最好 seed。

## 15. 数据完整性验证

正式绘图前，`validate_timeline.py` 必须对每个 campaign 检查：

- JSONL 每行可解析；
- campaign id 唯一；
- source/DUT SHA 存在；
- elapsed wall time 单调；
- completion sequence 连续；
- coverage 单调；
- denominator 稳定；
- rate 与 numerator/denominator 一致；
- final timeline 与正式 coverage.json 一致；
- timeline 中的 case/result 都存在；
- result 不存在时有明确记录；
- duplicate result 被拒绝；
- environment 和 command manifest 完整；
- 输出目录没有被另一 run 覆盖。

验证结果写入 `validation.json`。只有 `valid=true` 的 campaign 进入主统计。排除项必须进入 `aggregate/exclusions.csv`。

完成后对所有最终数据生成 SHA256：

```bash
cd /home/dubhe/wjs/pmpfuzz-eval-artifacts
find campaigns baselines mutants aggregate plots -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > manifests/artifact-sha256.txt
```

## 16. 必须交付的表和图

### 表

1. `table_targets.csv`：DUT、类型、版本、PMP/Smepmp/Sv39、观测深度、白盒支持。
2. `table_baselines.csv`：方法、生成策略、oracle、feedback、支持目标、版本。
3. `table_coverage.csv`：四类覆盖的最终值、threshold time、AUC。
4. `table_faults.csv`：fault、类别、DUT、方法、是否发现、时间、根因。
5. `table_real_findings.csv`：真实发现、影响、复现、确认状态。
6. `table_overhead.csv`：吞吐、插桩开销、存储、core-hours。

### 图

1. **时间—黑盒覆盖率曲线，必做。**
2. case 数—黑盒覆盖率曲线，必做。
3. 时间—白盒安全事件曲线，必做。
4. fault time-to-detection / survival curve，必做。
5. 各 protection category 覆盖或 fault recall 柱状图，可选。

每张图必须同时交付：

- raw CSV；
- aggregated CSV；
- plotting script；
- PDF；
- 300 dpi PNG；
- figure metadata；
- 生成命令。

## 17. 完成判据

只有同时满足以下条件，任务才算完成：

1. timeline 单元测试和全量测试通过；
2. Spike、Rocket、BOOM timeline smoke 通过；
3. timeline 最后点与 execution coverage 完全一致；
4. pilot 完成并冻结正式参数；
5. random/guided 四种 coverage-mode 对比完成；
6. BB/BB+WB 消融完成；
7. riscv-dv 和 Cascade 至少在 Rocket/BOOM 上形成可比较共同指标；
8. protection mutant corpus 有独立确认记录；
9. 10 seeds 的正式数据完成，或对未完成项有明确 infrastructure blocker；
10. U74/C910 真实硬件数据与串口日志归档；
11. 所有主图和表从原始数据一键再生；
12. 不存在论文文件修改；
13. 最终输出一份 `EVALUATION_COMPLETION_REPORT.md`，逐项列出完成、失败、排除和证据路径。

## 18. 停止条件

遇到以下情况必须停止对应阶段并报告，不能自行绕过：

- 服务器代码 SHA 与预期不一致；
- 全量单元测试失败；
- timeline 与 coverage.json 不一致；
- DUT capability 文件缺失或 fingerprint 冲突；
- baseline 无法启用其声称的 PMP/privileged 配置；
- baseline 与 PMPFuzz 使用了不同 DUT build；
- mutant 没有独立可观察性证据；
- 运行目录被覆盖或两个 campaign 串线；
- 磁盘、内存或残留进程使结果不可信；
- 物理板卡 reset/boot 状态无法确认；
- 需要修改 `paper/` 才能继续。

停止时仍需保存日志、命令和当前数据，不得清理现场。

## 19. 最终汇报格式

DeepSeek 最终回复必须包含：

1. 代码修改文件列表；
2. Git commit 和服务器 source SHA；
3. 运行过的测试及结果；
4. 服务器环境摘要；
5. 每个实验矩阵的完成状态；
6. 每个 campaign 的 artifact 路径；
7. 排除和失败原因；
8. 生成的图表路径；
9. raw/aggregate CSV 路径；
10. 一键重绘命令；
11. 论文可以安全引用的结果；
12. 尚不能写入论文的结果；
13. 明确确认 `paper/` 未被修改。
