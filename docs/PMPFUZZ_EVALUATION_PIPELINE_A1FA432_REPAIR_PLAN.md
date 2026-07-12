# PMPFuzz 实验管线后续修订任务书

**交付对象**：DeepSeek V4 Pro / Claude Code  
**审计基线**：`feature/evaluation-pipeline-v2` @ `a1fa432`  
**仓库**：`D:\c_s\wjs\riscv-pmp-fuzz`  
**服务器仓库**：`/home/dubhe/wjs/riscv-pmp-fuzz-eval`  
**服务器实验产物**：`/home/dubhe/wjs/pmpfuzz-eval-artifacts`  
**目标**：修复 Phase B–E 的剩余阻塞，使闭环调度、时间—覆盖率数据、白盒反馈、标准数据契约和 Cascade baseline 达到可进入 Pilot 的可信状态。

---

## 0. 总体结论与本轮边界

当前代码已经修复累计覆盖率恒为零、无效结果贡献黑盒覆盖率、bootstrap 脱离候选池、random 重复执行和 Timeline 不增量落盘等问题。本地已有 302 项测试通过。

但是，以下完成声明目前不成立：

1. guided 尚未真正读取目标 DUT 的 execution-qualified 覆盖反馈；
2. campaign Timeline 尚未记录 case 的真实完成顺序和完成时间；
3. Phase D 标准数据契约尚未完成；
4. Cascade 尚未生成可信的 security-event 时间线和标准输出；
5. 现有“集成测试”没有覆盖上述真实路径。

因此，本任务完成以前：

- 不得启动 Pilot-A、Pilot-B 或正式长跑；
- 不得把 Phase B、C、D、E 全部标记为完成；
- 可以做本地测试和短 smoke；
- 可以准备 Phase F 的隔离构建目录，但不得以此替代 Phase B–E 验收；
- 不得修改任何论文文件。

---

## 1. 强制约束

### 1.1 严禁修改论文

不得创建、修改、格式化、移动、删除或提交：

```text
paper/
*.tex（论文相关）
论文正文 Markdown
```

开始和结束时都必须运行：

```bash
git status --short
git diff --name-only <起始SHA>..HEAD
```

若输出中出现 `paper/`，立即停止，不得自行 reset 或覆盖；先向用户报告。

### 1.2 不得破坏已有实验和 DUT 工作区

- 不删除或覆盖现有 Pilot-A、smoke、readiness、Cascade 产物；
- 不执行 `git reset --hard`、`git clean -fd` 或面向共享目录的递归删除；
- 不修改服务器上的 `Android`、`work`、`ida-hcli`；
- 不在共享 DUT 源码树中直接做不可恢复修改；
- 新 smoke 必须写入新的、带版本号的目录；
- Cascade 不能移动或清空共享 `cascade-elfs` 根目录中的未知文件。

### 1.3 TDD 顺序

每个工作包必须严格执行：

1. 先写能够复现问题的测试；
2. 运行测试并保存 RED 输出；
3. 修改生产代码；
4. 运行定向测试并达到 GREEN；
5. 运行全量测试；
6. 每个工作包单独提交；
7. 在进度报告中记录测试命令、测试数、commit SHA 和实际输出路径。

不要写“允许为空也算通过”“两种选择可以相同”“只要返回 list 即通过”之类弱断言。

### 1.4 完成定义

“代码存在”“模块能导入”“测试数量增加”不等于完成。只有同时满足以下三项才可打勾：

- 对应真实缺陷有 RED→GREEN 测试；
- 短 smoke 产生符合数据契约的真实产物；
- validator 对产物给出 `error_count=0`。

---

## 2. 开始前保存状态

在本机和服务器分别记录：

```bash
git branch --show-current
git rev-parse HEAD
git status --short
git log -8 --oneline
```

预期本机起点为：

```text
branch: feature/evaluation-pipeline-v2
HEAD: a1fa432a697b24607812197a240d78cdb1c3e536
```

如果 HEAD 已变化，不要强行回退。记录新 SHA，列出 `a1fa432..HEAD` 的文件和提交，再继续。

创建本轮修复分支，名称建议：

```text
feature/evaluation-pipeline-v3-repair
```

不要把 `paper/` 加入版本控制。

---

## 3. 工作包 P0-1：修复真实 guided 黑盒反馈

### 3.1 当前缺陷

主要文件：

```text
scripts/evaluation/run_closed_loop_campaign.py
pmpfuzz/coverage_qualification.py
tests/test_closed_loop_campaign.py
tests/test_evaluation_data_contract.py
```

当前三个 coverage-gap 函数调用：

```python
collect_execution_evidence(run_dirs, dut="unknown")
```

而 `collect_execution_evidence()` 会过滤掉 `result["dut"] != dut` 的结果。真实 `spike`、`rocket-clean`、`boom-clean` 结果因此全部被排除。当前 guided 不是根据实际执行结果闭环调度。

此外，greedy 选择在覆盖缺口无法继续增加时会直接返回短列表，不能保证补足 `round_size`，甚至可能在候选池未耗尽时返回空列表并提前结束 campaign。

### 3.2 必须修改

1. 修改 `_coverage_gap_semantic()`、`_coverage_gap_predicates()` 和 `_coverage_gap_combo()`，显式接收 `dut`。
2. `_select_guided()` 必须从 `state.dut` 传递真实 DUT。
3. 所有 coverage gap 只能使用 `qualify_result_for_coverage(...).eligible == True` 的结果。
4. 不允许其他 DUT 的 result 污染当前 DUT 覆盖率。
5. greedy 选择结束后，如果选中数少于 `count`，必须从剩余未执行候选中使用确定性的 seeded fallback 补足。
6. 如果未执行候选数不少于 `count`，返回数必须等于 `count`。
7. tie-breaking 必须稳定。相同 seed、相同候选池、相同历史结果必须产生相同顺序。
8. 每个调度条目记录：

```text
candidate_id
selection_source = random | blackbox | whitebox | fallback
estimated_new_bins
round_index
```

9. `bb` 必须只消费黑盒 execution-qualified coverage；不能读取白盒 schedule。

### 3.3 必须先增加的测试

测试必须创建真实临时目录结构：

```text
round_0000/
├── cases/<case>/case.json
└── results/<case>/result.json
```

至少增加以下断言：

1. `dut=spike` 时，一个有效 Spike result 会从缺口集合中移除对应 bins；
2. 同一目录中的 Rocket result 不会影响 Spike 缺口；
3. `observation_valid=false` 的结果不影响缺口；
4. `oracle_applicability != valid` 的结果不影响缺口；
5. guided 第一轮之后优先选择能覆盖未覆盖 bin 的候选；
6. random 与 guided 在构造出的确定性场景中必须产生不同选择；不能写“可能相同”；
7. guided 返回完整 `round_size`；
8. 候选不足时返回全部剩余候选；
9. guided 不重复已执行 candidate；
10. 两次相同 seed 的选择顺序完全一致；
11. `bb` 不调用 `_whitebox_schedule()`，可通过 mock 明确断言调用次数为零。

### 3.4 验收标准

- 不再出现任何 `dut="unknown"` 的 execution-feedback 调用；
- 三轮 guided 集成测试中第二、三轮选择确实依赖前一轮有效 result；
- guided 每轮在候选充足时选满；
- valid 与 invalid result 的反馈边界由测试锁定；
- schedule JSON 可以解释每个 case 为何被选中。

---

## 4. 工作包 P0-2：修复真实 case 完成顺序与时间—覆盖率曲线

### 4.1 当前缺陷

`_ingest_round_results()` 在整个子进程结束后遍历 `result.json`，并为每个结果重新读取当前 `time.monotonic()`。这会导致：

- 同一轮的 case 时间集中在轮末；
- 结果遍历顺序替代实际完成顺序；
- 时间—覆盖率曲线呈阶梯式批量跳变；
- 无法用于论文 Figure：coverage over wall-clock time。

### 4.2 推荐实现

保留子进程模式，但把每轮原始 Timeline 作为完成顺序的权威来源。

1. 子进程继续在每个 case 完成回调中写：

```text
round_dir/metrics/coverage_timeline.jsonl
```

2. driver 在启动 campaign 时保存唯一的 campaign monotonic origin。
3. 将该 origin 或等价的全局时间偏移显式传给子进程，使子进程每个 completion 行能够记录相对于整个 campaign 起点的 `elapsed_wall_seconds`。
4. 不要在父进程 ingest 阶段重新生成 case 完成时间。
5. `_ingest_round_results()` 按子轮 Timeline 的 `completion_seq` 顺序处理非 baseline 行。
6. 用 Timeline 的 `case_id` 查找对应 `case.json` 和 `result.json`。
7. 父级 `CampaignState` 重新分配全局连续 `completion_seq`，但保留：

```text
round_index
round_completion_seq
elapsed_wall_seconds
case_elapsed_seconds
```

8. schedule、子进程启动、coverage 后处理和轮间开销必须自然包含在后续 case 的全局 wall time 中。
9. 顶层 Timeline 只保留一个 `completion_seq=0` baseline。
10. 顶层 Timeline 的最后时间不能早于最后一个子轮完成时间。

如果选择其他实现，也必须满足“每个 case 实际完成时刻”“实际完成顺序”“全 campaign 时钟不重置”三个条件。

### 4.3 必须增加的测试

新增真正的 fake-runner 端到端测试。测试必须调用 `run_closed_loop()` 或脚本入口，而不是只手工调用 `CampaignState`。

fake runner 应生成至少三轮子 Timeline，例如：

```text
round 0: case B 在 1.0s 完成，case A 在 2.0s 完成
round 1: case D 在 4.5s 完成，case C 在 6.0s 完成
round 2: case E 在 8.0s 完成
```

断言：

1. 顶层顺序为 `B, A, D, C, E`，不能按 case 名排序；
2. 全局 `completion_seq` 为 `0,1,2,3,4,5`；
3. `elapsed_wall_seconds` 严格或非严格单调；
4. 时间值与 fake runner 指定值一致，不能全部集中在轮末；
5. 覆盖率在对应 case 完成点增长；
6. 中间 schedule 延迟会反映到下一轮时间；
7. 中断后已有 JSONL 可逐行解析；
8. resume 或恢复逻辑不会覆盖原有行；若暂不支持 resume，删除虚假的 resume 完成声明并明确标为未实现。

### 4.4 验收标准

- 每轮至少两个 case 的 completion time 可区分；
- 顶层 case 顺序等于真实完成顺序；
- `plot_coverage_time.py` 直接读取规范化 CSV 即可重建曲线；
- validator 能检测人为打乱或回退的时间线；
- Spike 三轮 smoke 的曲线不是每轮只出现一个批量跳点。

---

## 5. 工作包 P0-3：修复 round 失败传播与停止规则

### 5.1 当前缺陷

`_run_round()` 在子进程返回非零时记录一次失败，但最终只返回 `_ingest_round_results()` 的结果。这可能导致：

- 子进程失败但 ingest 成功，调用者收到 `success=True`；
- 同一轮同时出现 failure 和 success 记录；
- bootstrap 子进程失败后仍继续 main loop；
- campaign 失败原因无法稳定归类。

### 5.2 必须修改

1. 分开记录：

```text
process_success
ingest_success
round_success = process_success and ingest_success
```

2. `_run_round()` 只能返回 `round_success` 或结构化 `RoundResult`，不能丢弃 subprocess 状态。
3. 一轮只写一条最终 round result。
4. bootstrap failure 必须终止 campaign 并标记 invalid。
5. 普通 round 的不可恢复 infrastructure failure 必须按照预先固定阈值停止；阈值写入 metadata。
6. 单个 case timeout 记录为 case 结果，不自动等同于整个 round infrastructure failure。
7. 缺失预期 result、orphan result、重复 result 必须明确区分。

### 5.3 测试

- subprocess 非零、ingest 成功：round 必须失败；
- subprocess 为零、缺失 result：round 必须失败；
- bootstrap 失败：不得创建后续 round；
- case timeout 但其余结果完整：按声明规则处理，不能静默丢失；
- round result 不得出现相互矛盾的两条状态。

---

## 6. 工作包 P0-4：修复白盒反馈资格、16+16 合并与事件时间线

### 6.1 当前缺陷

当前 `_whitebox_schedule()` 和 `_ingest_round_results()` 会从所有 result 提取白盒事件，没有先检查 execution qualification。无效 observation 可能影响：

- `whitebox_distinct_events`；
- `new_whitebox_events`；
- BB+WB 下一轮调度。

此外，现有测试允许白盒 schedule 为空，且没有证明 `bb` 与 `bb-wb` 的真实选择不同。

### 6.2 必须修改

1. 原始白盒信号可以归档，但只有 `qual.eligible == True` 的 result 可以进入调度反馈集合。
2. `bb` 和 `bb-wb` 必须使用相同 instrumented DUT、相同日志开关、相同资源预算。
3. `bb` 忽略白盒反馈，但仍可离线采集日志。
4. `bb-wb` 每轮最多 16 个 whitebox 候选，其余由 blackbox 补足到 `round_size`。
5. 白盒为空或不足时必须全部由 blackbox/fallback 补足。
6. 合并后必须按 `candidate_id` 去重并排除已执行候选。
7. 每个条目记录 `selection_source`。
8. 每轮 metadata 至少记录：

```text
whitebox_candidate_count
blackbox_candidate_count
fallback_candidate_count
deduplicated_count
already_executed_excluded_count
final_selected_count
```

9. 每个有效白盒事件必须能够进入 `security_event_timeseries.jsonl`，并与对应 case completion 对齐。
10. 不要用裸 `except Exception: pass` 静默吞掉白盒提取错误。单 case 提取失败可不中断 campaign，但必须记录结构化 warning 和计数。

### 6.3 测试

新增：

```text
tests/test_incremental_whitebox_timeline.py
```

至少覆盖：

- 新事件使 distinct count 增加；
- 重复事件不增加；
- invalid observation 的原始信号可归档，但不增加 feedback count；
- 不同 DUT 的日志标签不改变 result 的真实 DUT；
- `bb` 不调用白盒 scheduler；
- `bb-wb` 在构造场景中确实产生与 `bb` 不同的选择；
- 白盒最多 16 个；
- 白盒不足时仍选满 32 个；
- event 时间线和 case completion_seq 对齐；
- 时间—白盒事件曲线单调不减。

---

## 7. 工作包 P0-5：完成 Phase D 标准数据契约

### 7.1 必须生成的文件

修改：

```text
scripts/evaluation/aggregate_results.py
scripts/evaluation/validate_timeline.py
scripts/evaluation/plot_coverage_time.py
tests/test_evaluation_data_contract.py
tests/test_evaluation_scripts.py
```

必须生成任务书要求的完整输出：

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

可以保留旧的 `aggregate/campaign_index.csv` 和 `aggregate/coverage_final.csv` 作为兼容输出，但不能用它们冒充上述标准文件。

### 7.2 数据规则

1. 规范化 CSV 不包含 synthetic baseline 行；第一条真实完成记录从 `completion_seq=1` 开始。
2. 缺失值使用空字段或 JSON `null`，不能用假 `0`。
3. PMPFuzz 独有覆盖字段在 Cascade/riscv-dv baseline 中必须为空，不得伪造零覆盖。
4. 时间序列主键至少能唯一标识：

```text
experiment_id + campaign_id + completion_seq
```

5. security event 表要额外区分同一 case 的多个 event，例如 `event_index` 或稳定 `event_id`。
6. exclusions 必须在聚合前生效；被排除的旧 Pilot-A 不进入主统计。
7. threshold time 必须保留未达到阈值的 right-censored 记录。
8. 每个表的字段、类型、单位、是否允许为空、来源写入 `data_dictionary.md`。
9. artifact hash 文件覆盖用于绘图和论文统计的全部规范化/聚合文件。

### 7.3 Validator 必须真正递归检查

闭环 campaign 的 case/result 位于 `rounds/round_xxxx/`。validator 必须递归检查，而不是只确认子轮 Timeline 存在。

必须检测：

- 顶层 Timeline 的每个 case 在对应 round 中存在 case.json 和 result.json；
- result 的 case_id/name、DUT 与 Timeline 一致；
- duplicate、orphan、missing result；
- 全局 completion_seq 连续唯一；
- completed/eligible 终值与逐行累计一致；
- coverage numerator、denominator、rate 一致；
- 各覆盖率和白盒事件累计值不回退；
- source SHA、DUT source SHA、DUT binary SHA、patch SHA、capability fingerprint 完整；
- environment、commands、metadata 和 binary manifest 完整；
- raw/normalized 主键无重复；
- exclusions 没有进入主统计；
- 规范化 CSV 能重建最终覆盖率和时间曲线；
- artifact hash 可以重新计算并匹配。

正式 campaign 中缺少关键 SHA、manifest、case/result 或标准输出必须是 error，不能只是 warning。

### 7.4 闭环 metadata 必须补齐

`run_closed_loop_campaign.py` 当前 metadata 没有完整写入以下字段，必须从真实环境采集：

```text
source_sha
dut_source_sha
dut_binary_sha256
instrumentation_patch_sha256
capability_fingerprint
toolchain_versions
command_line
hostname
jobs
time_budget_seconds
per_case_timeout_seconds
stopping_reason
invalid_reason
```

无法获取时不得填假值。短 smoke 可以明确标为 invalid/incomplete；正式数据不得通过 validator。

### 7.5 测试要求

现有测试只检查五个旧文件，必须改成精确断言全部标准输出。

至少加入负面测试：

- 删除一个 result 后 validator 失败；
- 增加 orphan result 后失败；
- 重复 completion_seq 后失败；
- 清空 source SHA 后失败；
- 把被排除 campaign 加入主统计后失败；
- 篡改 normalized CSV 后 hash 或重建检查失败；
- Cascade 的 semantic 字段为 `0` 而不是空时失败。

---

## 8. 工作包 P0-6：完成 Cascade baseline adapter

### 8.1 必须修改的文件

```text
scripts/evaluation/baseline_adapters/cascade.py
tests/test_baseline_adapters.py
tests/test_evaluation_data_contract.py
```

不要继续把 Cascade 测试只写成“模块能导入”或“手工算出的 hash 相等”。

### 8.2 ELF 生成隔离

1. 每个 campaign 使用唯一生成目录，例如：

```text
/cascade-mountdir/cascade-elfs/<campaign_id>/
```

2. host 侧对应目录也必须唯一。
3. 不遍历、移动或删除共享 `cascade-elfs` 根目录中的所有文件。
4. 只复制或移动本 campaign 明确生成的 ELF。
5. 验证生成数量、文件名、非零大小和 ELF magic。
6. generator 返回 0 但没有生成预期 ELF 时，必须判定 generation failure。
7. 记录生成开始/结束时间、容器 ID、镜像 digest 和 Cascade source SHA。

### 8.3 每 case 原始日志

为每个 ELF 创建：

```text
logs/<case_id>.stdout.log
logs/<case_id>.stderr.log
results/<case_id>/result.json
```

不得只保存在内存中。security-event 提取直接使用本次执行得到的 stdout/stderr，写盘用于复核，不要在事后读取一个从未创建的 `logs/<case>.log`。

### 8.4 终态分类

必须把分类规则写成独立函数并测试。建议字段：

```text
status
termination_reason
returncode
host_timeout
simlen_reached
probe_event_count
observation_valid
failure_class
```

最低规则：

- `TimeoutExpired`：`timeout`；
- simulator 不存在、无法启动、ELF 损坏、I/O 错误：`infra_failure`；
- 有可解析 probe，且终止方式符合预先声明的 Cascade simlen 规则：`completed`；
- 运行结束但没有可解析 probe，或终止原因无法确认：`inconclusive`；
- 不能仅因为出现 probe 就忽略任意非零 return code；
- 已知的 255 只有在日志能够证明它对应预期 simlen 停止时才可接受，不能全局硬编码为成功。

### 8.5 Security event 时间线

1. `completion_seq` 表示 case 完成序号，同一 case 的多个事件共享该序号。
2. 用单独的 `event_index` 区分同一 case 的多个事件。
3. `elapsed_wall_seconds` 使用该 case 的真实完成时间。
4. event ID 来自稳定、语义化的 probe 字段，不包含 case_id。
5. 不要把每个原始地址都默认定义为新的安全语义事件；地址可作为 evidence 字段。若地址确实属于 event identity，必须在 data dictionary 中说明原因。
6. parser 优先使用已解析的 `fields["chain"]`、`fields["stage"]`、`fields["prv"]`，不要依赖字段固定出现顺序的单一正则。
7. 输出必须进入标准 `normalized/security_event_timeseries.csv`。

### 8.6 标准输出和预算公平性

Cascade 必须生成或供聚合脚本生成：

```text
normalized/campaigns.csv
normalized/security_event_timeseries.csv
aggregate/overhead.csv
```

记录：

- ELF 生成时间；
- 总执行时间；
- 每 case 执行时间；
- completed/timeout/inconclusive/infra_failure 数；
- 实际使用的时间、simlen、core/jobs 预算；
- Rocket/BOOM binary SHA。

与 PMPFuzz 比较时必须使用同一 DUT、同一 wall-clock 或预先声明的等价预算。不要用生成 ELF 数量代替执行预算。

### 8.7 测试与短 smoke

本地测试使用 mock subprocess，但必须调用真实 adapter 函数并检查完整目录和输出，不得只测试 helper。

服务器短 smoke 在代码全部通过后执行：

```bash
python3 scripts/evaluation/baseline_adapters/cascade.py \
  --dut rocket-clean \
  --num-elfs 3 \
  --simlen 50000 \
  --timeout 60 \
  --seed 1 \
  --out /home/dubhe/wjs/pmpfuzz-eval-artifacts/repair-smoke-v3/cascade/rocket/seed-0001
```

BOOM 再运行同样的 3 ELF smoke。这里只做 smoke，不扩大到正式 seed 矩阵。

验收时必须展示：

- 3 个 ELF 的路径和 SHA-256；
- 3 份 stdout/stderr 日志；
- 每 case result.json；
- 非空或有明确合理空值原因的 security-event 时间线；
- validator 报告；
- 两次并发 smoke 不互相移动或覆盖 ELF。

---

## 9. 工作包 P0-7：替换弱测试为真正的端到端测试

### 9.1 必须新增/整理的测试文件

```text
tests/test_closed_loop_campaign.py
tests/test_incremental_whitebox_timeline.py
tests/test_evaluation_data_contract.py
tests/test_baseline_adapters.py
```

### 9.2 真正的三轮闭环测试

测试入口必须是 `run_closed_loop()` 或 CLI main。可以注入 fake runner/subprocess，但 fake runner 必须真实写出：

```text
case.json
result.json
round coverage_timeline.jsonl
whitebox/source-probe log
```

至少运行：

- 三轮 random；
- 三轮 guided；
- 三轮 bb；
- 三轮 bb-wb。

断言：

- random/guided 使用相同 bootstrap candidate IDs；
- 后续 random 不读取反馈；
- guided 的后续选择由上一轮有效覆盖缺口决定；
- bb 不消费白盒反馈；
- bb-wb 消费白盒反馈且在构造场景中与 bb 不同；
- 每轮无重复，跨轮无重复；
- 全局 completion_seq 连续；
- wall time 真实单调；
- 最终 Timeline 与 coverage.json 一致；
- 一个子轮失败会使 campaign invalid；
- 中断后 JSONL 仍可解析。

### 9.3 删除或加强现有弱断言

必须修改以下类型的测试：

- “返回 list 即通过”；
- “白盒为空也算有效”；
- “random 与 guided 理论上可以相同”；
- 对 bb 和 bb-wb 调用同一个函数却声称比较二者；
- 手工计算 event hash 而不调用生产函数；
- 声称验证全部数据契约但只检查五个文件。

测试名称必须准确反映它实际验证的内容，不能把 API test 命名为 end-to-end integration。

---

## 10. 本地测试顺序

每个工作包先跑对应测试。全部修复后运行：

```bash
python -m unittest tests.test_closed_loop_campaign
python -m unittest tests.test_incremental_whitebox_timeline
python -m unittest tests.test_evaluation_data_contract
python -m unittest tests.test_baseline_adapters
python -m unittest tests.test_timeline tests.test_evaluation_scripts
python -m unittest tests.test_whitebox tests.test_source_probe tests.test_dut_coverage
python -m unittest discover -s tests
```

必须保存：

```text
artifacts/repair-validation/local-targeted-tests.log
artifacts/repair-validation/local-full-tests.log
```

测试数增加不是验收指标；重点报告上述关键断言是否实际覆盖。

---

## 11. 服务器最小 smoke 门槛

只有本地全量测试通过后，才同步到服务器的新分支。不要覆盖旧 artifact。

### 11.1 Spike 三轮闭环 smoke

为避免依赖“时间刚好跑三轮”，建议给 driver 增加仅用于测试/复现的 `--max-rounds` 参数，并写入 metadata。正式实验不依赖该参数停止。

分别运行 random 和 guided：

```bash
python3 scripts/evaluation/run_closed_loop_campaign.py \
  --experiment-id repair-smoke-v3 \
  --variant random \
  --coverage-mode semantic \
  --dut spike \
  --seed 1 \
  --bootstrap-size 4 \
  --round-size 4 \
  --time-budget 180 \
  --per-case-timeout 10 \
  --jobs 2 \
  --artifact-root /home/dubhe/wjs/pmpfuzz-eval-artifacts/repair-smoke-v3
```

guided 使用完全相同参数，只把 `--variant` 改为 `guided`。如果实现了 `--max-rounds 3`，两个命令都加入该参数。

必须验证：

- bootstrap IDs 完全相同；
- random/guided 后续 IDs 在可解释的 coverage-gap 场景中不同；
- guided schedule 记录 estimated new bins；
- 顶层 Timeline 每个 case 有不同或合理相同的真实完成时间；
- coverage 不回退；
- denominator 恒定；
- validator `error_count=0`。

### 11.2 Rocket 最小 BB/BB+WB smoke

在已有 instrumented Rocket binary 上各运行三轮、每轮 4 cases，仅验证闭环，不做性能结论。两者必须使用相同：

```text
binary SHA
bootstrap IDs
seed
jobs
time budget
timeout
whitebox logging setting
```

必须观察到至少一个有效 whitebox event，构造并证明 `bb-wb` 实际消费了白盒 schedule，而 `bb` 没有。

如果无法触发白盒事件，结果应为 smoke 未通过；不能把空白盒 schedule 记为成功验证 BB+WB。

### 11.3 Cascade smoke

按第 8.7 节只运行 Rocket/BOOM 各 3 ELF。不得直接启动正式 baseline campaign。

---

## 12. 自动验收脚本

建议新增：

```text
scripts/evaluation/check_pipeline_repair_gate.py
```

输入一个 artifact root，检查并以非零退出码拒绝：

- 缺少标准输出；
- validator 有 error；
- completion_seq 不连续；
- wall time 回退或整轮所有 case 被错误压在同一 ingest 时间；
- coverage 回退；
- denominator 改变；
- invalid result 贡献反馈；
- guided 没有记录 feedback source；
- bb 消费 whitebox；
- bb-wb smoke 没有有效 whitebox feedback；
- Cascade 缺少每 case 日志或事件表；
- SHA/manifest 不完整；
- 被排除 campaign 进入主统计。

这个脚本必须有单元测试，不能依赖人工肉眼判断。

---

## 13. 提交顺序

建议每个阶段单独提交：

```text
1. Test: reproduce real DUT coverage-feedback filtering bug
2. Fix: use DUT-qualified coverage feedback and fill guided rounds
3. Test: reproduce batched round-end campaign timestamps
4. Fix: preserve per-case completion order and global wall time
5. Fix: propagate subprocess and ingest failures consistently
6. Test: enforce qualified whitebox feedback and BB/BB+WB separation
7. Fix: implement qualified 16+16 feedback and event timeline
8. Test: require complete normalized evaluation data contract
9. Fix: generate full normalized outputs and recursive validation
10. Test: exercise Cascade adapter end to end with isolated artifacts
11. Fix: isolate Cascade generation, persist logs, normalize events
12. Test: add true three-round driver integration coverage
13. Docs: update truthful progress and completion report
```

不得把所有修改压成一个无法审计的大提交。

---

## 14. 最终验收门槛

以下全部满足后，才允许开始 Phase G 或重跑 Pilot-A：

- [ ] guided 使用真实 `state.dut` 的 execution-qualified result；
- [ ] invalid result 不贡献黑盒或白盒调度反馈；
- [ ] random、guided、bb、bb-wb 四种 variant 有真实差异测试；
- [ ] 每轮候选充足时选满 round size；
- [ ] 全 campaign completion_seq 连续唯一；
- [ ] 每个 case 按真实完成顺序记录；
- [ ] 时间—覆盖率曲线使用真实 wall-clock completion time；
- [ ] round subprocess failure 正确传播；
- [ ] 顶层 Timeline 与最终 coverage.json 一致；
- [ ] 完整标准数据契约全部生成；
- [ ] recursive validator 覆盖 rounds 下的 case/result；
- [ ] 缺少 SHA/manifest 会导致正式数据 validation error；
- [ ] exclusions 不进入主统计；
- [ ] Cascade 使用 campaign 独立 ELF 目录；
- [ ] Cascade 保存每 case stdout/stderr/result；
- [ ] Cascade security-event 时间线非伪造、可追溯；
- [ ] Cascade 标准 campaigns/event/overhead 数据完整；
- [ ] 真正的三轮 random/guided/bb/bb-wb 集成测试通过；
- [ ] 本地全量测试通过；
- [ ] 服务器 Spike 三轮 smoke 通过；
- [ ] Rocket BB/BB+WB 三轮 smoke 通过；
- [ ] Rocket/BOOM Cascade 3 ELF smoke 通过；
- [ ] repair gate 对所有 smoke 给出 `error_count=0`；
- [ ] `paper/` 完全未修改。

只要其中任意一项未满足，就必须在报告中标记为 pending 或 blocked，不能写“Phase B–E 全部完成”。

---

## 15. 最终交付报告格式

完成后输出：

```text
docs/EVALUATION_PIPELINE_V3_REPAIR_COMPLETION_REPORT.md
```

报告必须包含：

1. 起始/结束 branch 和 SHA；
2. 每个缺陷的根因、RED 测试、修复文件和 GREEN 结果；
3. 修改文件列表；
4. 本地定向和全量测试日志路径；
5. 服务器每个 smoke 的完整命令；
6. 每个 smoke 的 artifact 路径；
7. random/guided bootstrap 和后续 schedule 对比；
8. BB/BB+WB selection source 对比；
9. 时间—覆盖率数据的前十行和最后十行；
10. Cascade ELF、日志、result、event timeline 路径；
11. 标准输出文件清单和 SHA-256；
12. validator 和 repair gate 报告；
13. 尚未完成或失败的项目，不能隐藏；
14. `git status --short`；
15. 明确确认 `paper/` 未修改。

完成报告最后只给出以下三种结论之一：

```text
READY_FOR_PHASE_F_ONLY
READY_FOR_PHASE_G_AND_PILOT_SMOKE
NOT_READY
```

在本任务范围内，不得自行宣布 `READY_FOR_FORMAL_EXPERIMENTS`。正式实验仍需用户或 Codex 根据四 DUT readiness 与 Pilot 结果单独批准。
