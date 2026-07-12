# PMPFuzz 实验进度报告

**生成时间**: 2026-07-12 13:05 UTC+8
**写给**: Codex Review
**目的**: 全面展示当前实验状态、结果、发现的问题，请求指导

---

## 0. 关键信息速览

| 项目 | 值 |
|------|-----|
| 服务器 | dubhe-workstation, 48核 AMD Threadripper PRO 7965WX, 123GB RAM, 1.8TB SSD (816GB可用) |
| 本机 | Windows 11, riscv-pmp-fuzz repo |
| 分支 | `feature/real-whitebox-dut-coverage` |
| 最新commit | `394eb11` (已推送GitHub) |
| 服务器代码路径 | `/home/dubhe/wjs/riscv-pmp-fuzz-eval` |
| 实验产物路径 | `/home/dubhe/wjs/pmpfuzz-eval-artifacts/` |
| 实验任务书 | `docs/PMPFUZZ_EVALUATION_EXECUTION_PLAN.md` |

---

## 1. 已完成阶段

### Phase 0: 本地代码保存 ✅
- 全量 **276 测试全部通过** (29.7秒)
- 显式暂存代码，排除 `paper/` 目录
- Commit `394eb11`: "Fix: populate timeline coverage targets before campaign execution"
- 已推送到 GitHub `feature/real-whitebox-dut-coverage`

### Phase 1: 服务器部署 ✅
- SSH `dubhe@10.122.220.95` 通过私钥登录
- Git bundle 方式部署 (服务器无GitHub SSH权限)
- SHA验证一致: `394eb114fbe8af99280d01fb38f131f50c31a64b`
- 5种DUT全部可用:
  - Spike: `/home/dubhe/wjs/boom_host_deploy/opt-riscv/bin/spike` (v1.1.1-dev)
  - Rocket-clean: chipyard-1.14.0 RocketConfig Verilator
  - BOOM-clean: chipyard-1.14.0 SmallBoomV3Config Verilator
  - CVA6-clean: chipyard-1.14.0 CVA6Config Verilator
  - XiangShan-clean: xiangshan_vanilla Verilator emu
- 工具链: riscv64-unknown-elf-gcc (Xuantie-900, 14.1.1), Verilator 5.046
- Python venv: `.venv-eval` (numpy, pandas, matplotlib, scipy, seaborn, pyyaml)
- 产物目录结构已建立:
  ```
  /home/dubhe/wjs/pmpfuzz-eval-artifacts/
  ├── manifests/    (environment.json, git-shas.txt, python-freeze.txt, dut-binaries.sha256)
  ├── pilot/        (Pilot-A campaigns)
  ├── campaigns/    (正式实验 - 尚未开始)
  ├── baselines/    (Cascade smoke logs, riscv-dv fallback)
  ├── mutants/      (尚未开始)
  ├── aggregate/    (尚未开始)
  └── plots/        (尚未开始)
  ```

### Phase 2: Timeline 基础设施 ✅  **← 最大代码改动**

按照任务书 Section 4 实现了完整的时间-覆盖率记录基础设施。

**新增文件 (10个)**:

| 文件 | 行数 | 功能 |
|------|------|------|
| `pmpfuzz/timeline.py` | 277 | TimelineRecorder: append-only JSONL, lazy baseline, metadata writer |
| `scripts/evaluation/validate_timeline.py` | 148 | 18项一致性检查, 输出 validation.json |
| `scripts/evaluation/aggregate_results.py` | 178 | 扫描campaign目录, 生成CSV表 |
| `scripts/evaluation/plot_coverage_time.py` | 151 | 2×2子图, PDF+300dpi PNG |
| `scripts/evaluation/run_closed_loop_campaign.py` | 193 | Round-loop: bootstrap → schedule → run → repeat |
| `scripts/evaluation/baseline_adapters/riscv_dv.py` | 17 | riscv-dv适配器 (stub, riscv-dv未构建) |
| `scripts/evaluation/baseline_adapters/cascade.py` | 17 | Cascade适配器 (stub) |
| `configs/evaluation/experiment_matrix.yaml` | 55 | E1-E3 实验矩阵 + Pilot + 正式参数 |
| `tests/test_timeline.py` | 321 | 16个Timeline单元测试 |
| `tests/test_evaluation_scripts.py` | 129 | 5个评估脚本测试 |

**修改文件 (3个)**:

| 文件 | 改动 |
|------|------|
| `pmpfuzz/runner.py` | `_run_indexed_work_with_budget()` 增加 `on_complete` callback (index, scenario, CampaignResult, completion_seq, campaign_elapsed_seconds); `RunnerConfig` 增加 `record_timeline`, `campaign_id`, `variant` 字段 |
| `pmpfuzz/coverage.py` | 提取 `compute_coverage_targets()` 公共函数，供timeline和正式coverage共用denominator |
| `pmpfuzz/__main__.py` | 添加 `--record-timeline`, `--campaign-id`, `--variant` CLI参数; `_cmd_run()` 中初始化TimelineRecorder并填充target bins |

**Timeline JSONL schema** (每行):
```json
{
  "schema_version": 1,
  "campaign_id": "E1-sem__rocket-clean__random__seed-0001",
  "variant": "random",
  "dut": "rocket-clean",
  "seed": 1,
  "completion_seq": 312,
  "case_id": "pmp-boundary__...",
  "elapsed_wall_seconds": 873.521,
  "case_elapsed_seconds": 2.193,
  "completed_cases": 312,
  "eligible_cases": 290,
  "status": "pass",
  "coverage_eligible": true,
  "qualification_reason": "eligible",
  "semantic_covered": 61, "semantic_target": 388, "semantic_rate": 0.1572,
  "pairwise_covered": 500, "pairwise_target": 4276, "pairwise_rate": 0.1169,
  "security_triples_covered": 77, "security_triples_target": 1082, "security_triples_rate": 0.0712,
  "predicates_covered": 19, "predicates_target": 47, "predicates_rate": 0.4043,
  "new_semantic_bins": 2, "new_pairwise_bins": 5, "new_security_triple_bins": 1, "new_predicate_bins": 0
}
```

**Timeline验证项 (18项)**:
1. JSONL每行可解析
2. campaign_id唯一
3. metadata存在
4. schema_version有效
5. completion_seq从0连续增长
6. elapsed_wall_seconds单调不减
7. 四类coverage rate单调不减 (各独立检查)
8. 四类denominator恒定 (各独立检查)
9. rate = covered/target (1e-9容差, 四类各独立检查)
10. **末点与coverage.json完全一致** (四类各独立检查)

**测试**: `python -m unittest discover -s tests` → **Ran 276 tests, OK**

### Phase 3: Smoke 测试 ✅

**Spike smoke** (8 cases, pmp-boundary):
```
campaign-total=8 pass=8 nonpass=0
valid=True errors=0  (18/18 checks PASS)
```

**Rocket-clean smoke** (4 cases, pmp-boundary, whitebox):
```
valid=True errors=0  (18/18 checks PASS)
PMFUZZ_PROBE events confirmed
```

**BOOM-clean smoke** (4 cases, pmp-boundary, whitebox):
```
valid=True errors=0  (18/18 checks PASS)
PMFUZZ_PROBE events confirmed
```

### Phase 5: Baseline 部署 ✅/⚠️

#### Cascade Baseline ✅ 完全可用

关键发现: Cascade生成的ELF能直接在PMPFuzz插桩的DUT上运行，触发相同的 `PMFUZZ_PROBE` 安全事件。

| 项目 | 记录 |
|------|------|
| 容器 | `codex_cascade_cpu_fuzzing` (ID: afce3773b8c5) |
| 镜像 | `ethcomsec/cascade-artifacts:latest` (sha256:3d403b05be4a57fc1910b7e73bc807d499e382f73197ae8978ca1954524f0a11) |
| Cascade源码hash | do_fuzzsingle.py: d2f1bea0; do_fuzzdesign.py: d26d922f; fuzzsim.py: bfa01ee3 |
| DUT repo | cascade-chipyard @ 0317c19b (dirty, 6 modified .core files) |
| Rocket binary SHA256 | `b0b9dc378e237914f095e3a8f75130c04298738fa6a9b0cc10e25b5a96dedf0b` |
| ELF生成 | `do_genmanyelfs.py 5` → 5个ELF (rocket_0~4.elf), 每个约500-900KB |
| Rocket smoke | ELF在rocket-clean上运行，PMFUZZ_PROBE触发 (chain=pmp-check, prv=1=S-mode, prv=3=M-mode) |
| BOOM smoke | 同上，PMFUZZ_PROBE触发 |
| 特权级 | ELF包含M/S模式切换、PMP CSR写入 (pmpcfg0, pmpaddr0)、medeleg/mtvec/stvec/mstatus 操作 |

**Cascade ELF反汇编示例** (关键部分):
```asm
    80000010:  30201073  csrw   medeleg,zero       # 写medeleg
    80000014:  30501073  csrw   mtvec,zero          # 写mtvec
    80000018:  10501073  csrw   stvec,zero           # 写stvec (S-mode)
    8000001c:  01f00093  li     ra,31
    80000020:  3a009073  csrw   pmpcfg0,ra           # 写PMP配置
    80000028:  03601093  slli   ra,zero,0x36
    8000002c:  fff08093  addi   ra,ra,-1
    80000030:  3b009073  csrw   pmpaddr0,ra          # 写PMP地址
    80000058:  300e9073  csrw   mstatus,t4           # 写mstatus (切换特权级)
```

**局限**: Cascade ELF无标准 tohost/fromhost符号, 退出码为255。需fixed simlen做超时控制。Cascade的oracle与PMPFuzz oracle不同。

#### riscv-dv Baseline ⚠️ 阻塞

| 路径 | 结果 | 阻塞原因 |
|------|------|----------|
| eUVM (D语言) | ❌ 无法构建 | 依赖 esdl, uvm-ldc D库; esdl源码 `dub build` 失败 |
| pygen (Python) | ❌ 无法构建 | 需要 PyVSC + pyboolector, pyboolector native编译失败 |
| SystemVerilog原版 | ❌ 不可用 | 需要VCS/Incisive/Questa商业仿真器 |

**处理方案**: PMPFuzz的 `random` variant 作为无关联随机baseline。公共比较使用共同DUT security events。riscv-dv的 PMPFuzz语义覆盖字段全部为空。

**已创建fallback**: `/tmp/riscv_priv_gen2.py` — 简单M/S/U特权级随机程序生成器, 5个ELF编译成功, Spike执行有memory map问题(未修)。

---

## 2. 当前进行中: Pilot-A

### 已完成: Rocket-clean 4 campaigns

| # | Campaign ID | DUT | Variant | Coverage | Cases | Wall时间 | tests/h | valid |
|---|-------------|-----|---------|----------|-------|----------|---------|-------|
| 1 | `E1-sem__rocket-clean__random__seed-0001` | rocket-clean | random | semantic | 3,115 | 0.5h | 6,230 | ✅ True |
| 2 | `E1-sem__rocket-clean__guided-semantic__seed-0001` | rocket-clean | guided-semantic | semantic | 3,115 | 0.5h | 6,230 | ✅ True |
| 3 | `E1-pred__rocket-clean__random__seed-0001` | rocket-clean | random | predicates | 3,116 | 0.5h | 6,230 | ✅ True |
| 4 | `E1-pred__rocket-clean__guided-predicates__seed-0001` | rocket-clean | guided-predicates | predicates | 3,115 | 0.5h | 6,229 | ✅ True |

**Rocket 30分钟最终覆盖率** (seed=1, pmp-boundary):

| 覆盖类型 | Covered | Target | Rate | 30min内新增bins |
|----------|---------|--------|------|-----------------|
| semantic | 61 | 388 | 15.0% | 61 |
| pairwise | 500 | 4,276 | 11.5% | 500 |
| security_triples | 77 | 1,082 | 7.1% | 77 |
| predicates | 19 | 47 | 39.0% | 19 |

**有效执行比例**: ~93% (2899 pass / 3115 total per campaign)

### 已完成: BOOM-clean 4 campaigns ✅

| # | Campaign ID | DUT | Variant | Coverage | Cases | Wall时间 | tests/h | valid |
|---|-------------|-----|---------|----------|-------|----------|---------|-------|
| 5 | `E1-sem__boom-clean__random__seed-0001` | boom-clean | random | semantic | 2,733 | 0.5h | 5,466 | ✅ True |
| 6 | `E1-sem__boom-clean__guided-semantic__seed-0001` | boom-clean | guided-semantic | semantic | 2,733 | 0.5h | 5,466 | ✅ True |
| 7 | `E1-pred__boom-clean__random__seed-0001` | boom-clean | random | predicates | 2,732 | 0.5h | 5,464 | ✅ True |
| 8 | `E1-pred__boom-clean__guided-predicates__seed-0001` | boom-clean | guided-predicates | predicates | 2,731 | 0.5h | 5,462 | ✅ True |

**BOOM 30分钟最终覆盖率** (seed=1, pmp-boundary):

| 覆盖类型 | Covered | Target | Rate |
|----------|---------|--------|------|
| semantic | 60 | 388 | 15.5% |
| pairwise | 500 | 4,276 | 11.7% |
| security_triples | 77 | 1,082 | 7.1% |
| predicates | 19 | 47 | 40.4% |

**有效执行比例**: ~90.3% (2467 pass / 2733 total) — 略低于Rocket的~93%

### Pilot-A 汇总

| DUT | tests/h | 有效比例 | 并行安全性 | 30min semantic覆盖率 | 30min predicates覆盖率 |
|-----|---------|----------|-----------|---------------------|----------------------|
| rocket-clean | 6,230 | 93.1% | ✅ 无冲突 | 15.0% | 39.0% |
| boom-clean | 5,464 | 90.3% | ✅ 无冲突 | 15.5% | 40.4% |

**全部8个Pilot-A campaign: valid=True errors=0 ✅**

---

## 3. 发现的问题 & 需要指导

### 问题1: Guided variant实际未启用调度 ⚠️ 重要

**现象**: 当前Pilot-A的random和guided campaign使用了相同的 `--count 9999` 参数，导致两者生成完全相同的3,115个case，覆盖率和执行结果完全一致。

**根因**: PMPFuzz的 `run` 命令在给定 `--count N --seed S` 时，始终先生成全部N个scenario再执行。真正的guided调度需要通过 `--schedule schedule.json` 参数，且需要闭循环driver逐round执行（bootstrap → coverage → schedule → next round）。

**影响**: Pilot-A中random vs guided的比较无效。正式实验前必须修复。

**已完成**: `run_closed_loop_campaign.py` 已经实现了完整的round-loop逻辑(bootstrap → coverage → schedule → run → repeat)。但尚未在Pilot中验证。

**请求指导**: 
- Pilot-A是否需要重跑guided variant？
- 还是直接用闭循环driver进入Pilot-B？

### 问题2: 覆盖率远未达平台期 ⚠️

**数据**: 30分钟Rocket semantic覆盖率仅15%。仍在快速增长，每100 cases约新增2个semantic bins。

**推论**: 任务书建议的6小时正式预算可能不够。覆盖率可能在整个6小时内持续线性增长。

**请求指导**:
- 是否等BOOM数据出来后，再决定是否需要向用户请求提高到24小时？
- 还是按任务书默认先固定6小时？

### 问题3: riscv-dv baseline阻塞

eUVM (D语言)和pygen (Python)两条路径都无法构建。已按任务书Section 7.1文档化。

**当前处理**:
- PMPFuzz random模式作为等价无关联随机对照
- Cascade baseline正常工作
- 公共比较使用共同DUT security events (PMFUZZ_PROBE)

**请求指导**:
- 这个处理方案是否可接受？
- 是否需要进一步尝试其他riscv-dv构建方式（如安装特定版本ldc/dub）？

### 问题4: BOOM tests/h 可能显著低于Rocket

BOOM Verilator编译更复杂，第一个case可能需要数分钟编译。如果BOOM tests/h远低于Rocket，正式实验时需要为两者设定不同的时间预算。

**请求指导**:
- 是否允许为Rocket和BOOM设定不同的时间预算？
- 还是强制相同预算以保证公平比较？

### 问题5: 并发度

当前Pilot-A使用4个并行campaign (单DUT jobs=1)。无目录冲突，无DUT残留进程 (make-based DUT自身是串行的)。

**计划**: Pilot-A确认安全后，Pilot-B提升到8并行。

**请求指导**: 正式实验建议多少并行度？全部48核？还是保守使用8-16？

---

## 4. 尚未开始的工作

| 阶段 | 内容 | 估计耗时 |
|------|------|----------|
| Pilot-B | seeds 2,3; 32 runs; 每run 30-60min | 8-16小时 |
| 参数冻结 | 写 pilot_decision.md | 30分钟 |
| F1 | 正式语义覆盖: 10 paired seeds × 2 DUT × 2 variants | 约30小时(8并行) |
| F2 | 其他覆盖反馈 (pairwise/triples/predicates) | 复用F1 random数据 + 新增guided |
| F3 | 白盒消融 (BB vs BB+WB) | 约20小时 |
| F4 | 外部baseline (PMPFuzz vs Cascade) | 约20小时 |
| Protection mutants | 20-30个 | 待评估 |
| U74/C910 | 真实硬件 | 待评估 |
| 最终聚合/验证/绘图 | aggregate + plots + validation_report | 4-8小时 |

---

## 5. 服务器当前状态

```
主机名: dubhe-workstation
CPU: AMD Ryzen Threadripper PRO 7965WX 24-Cores (48逻辑核)
RAM: 123GB total, 112GB available
磁盘: 1.8TB total, 816GB available (/home/dubhe)
运行进程: 全部Pilot-A已完成 (0个残留pmpfuzz进程, 0个残留verilator进程)
Pilot磁盘占用: ~2.2GB (8 campaigns × ~275MB)
```

---

## 6. 下一步计划

1. **立即**: 等待BOOM 4个campaign完成 (约5分钟后)
2. **立即**: 验证BOOM结果 (coverage + timeline)
3. **根据指导决定**:
   - 修复guided variant问题后重跑部分Pilot-A
   - 或直接进入Pilot-B
   - 或调整预算
4. **Pilot-B**: seeds 2,3; 共32 runs; 每run 30-60分钟
5. **冻结参数**: 写 `pilot/pilot_decision.md`
6. **正式实验**: F1 → F2 → F3 → F4

---

**等待Codex审阅和指导。任何问题都可以进一步展开。**
