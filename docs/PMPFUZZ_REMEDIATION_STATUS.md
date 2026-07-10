# PMPFuzz 整改续跑记录

更新时间：2026-07-10  
分支：`feature/real-whitebox-dut-coverage`  
RED 测试检查点：`e7cb550 test: add reproducers for PMP security verdict flaws`

## 本轮整改范围

1. PMP first-match 部分重叠语义。
2. 测试程序与 oracle 解耦，改为 DUT 原始事件上报、主机独立判定。
3. trap 判定从只看 `mcause` 扩展到 phase、`mcause`、`mtval` 指纹、`mepc` 页标签和 PTW 阶段证据。
4. 补全 Sv39 A/D 的 Svade 与硬件更新路径，并检查 PTE 更新写操作的 PMP 权限。
5. 空日志、编译失败、基础设施失败、单次 hang 不再通过或直接确认漏洞。
6. 白盒产物按 case/result/DUT 绑定，避免跨 DUT 串线。

## 已完成的代码改动

- `pmpfuzz/pmp.py`：最低编号 PMP 项只要覆盖访问的任意字节就取得优先权；若未覆盖全部字节，直接拒绝。
- `pmpfuzz/diagnostics.py`：新增 HTIF/Spike 安全的 30 位正数观测协议；退出值携带版本、事件类型、phase、cause、`mepc` 页标签和 17 位 `mtval` 指纹，完整 CSR 同时写入 `result` 内存。
- `pmpfuzz/emitter.py`：不再导入或嵌入 `evaluate_scenario`；汇编只区分 harness ecall 与实际 trap，并上报观测事件。stateful 用例上报最终 sentinel 状态。
- `pmpfuzz/judgment.py`：新增主机判定器；PTW 用例缺少阶段/地址证据时返回 `inconclusive`，证据矛盾时返回 `wrong_trap_stage`。
- `pmpfuzz/mmu.py`、`oracle.py`、`scenario.py`、`capabilities.py`：支持 Svade/hardware A/D 两种模式；硬件更新按 S-mode store 检查叶 PTE 地址；未知 DUT 能力标为 `capability_dependent`。
- `pmpfuzz/dut.py`、`runner.py`、`__main__.py`、`schema.py`：解析结构化观测并交由主机判定；空日志转为 `missing_completion_marker`；结果保存观测和阶段验证字段。
- `pmpfuzz/verdict.py`：基础设施类结果不再进入安全证据；单次异常只生成 `anomaly_candidate`；确认结论要求结构化观测和独立重放元数据。
- `pmpfuzz/whitebox.py`：只扫描当前 result 自己的产物目录；`covered=0` 不再生成覆盖信号。

## 当前验证状态

- 定向回归已经覆盖六个整改方向。
- 最终完整测试：`182/182` 通过。
- 最终覆盖率：总覆盖率 `84%`。
- 服务器编译验证目录：`/home/dubhe/wjs/pmpfuzz-verify-20260710`。
- 已用服务器 RISC-V GCC 12.2 编译 legacy、Sv39 PTW、stateful、hardware A/D 四类代表性汇编。
- 最终 30 位正数布局已在真实 Spike 上完成四类执行和主机解码；输出均为可解析的非负观测值。
- Spike 判定结果符合 fail-closed 设计：legacy/stateful 可判定，黑盒 PTW 缺少阶段证据时为 `inconclusive`，hardware A/D 与未知 DUT 模式不进入漏洞确认。
- 新协议已在 CVA6 PTW 用例上重放；实际 trap 不再因仅有相同/相近 cause 被接受，主机判定会拒绝不一致证据。

## 续跑顺序

1. 若继续修改观测协议，先运行定向测试：
   `python -m unittest tests.test_diagnostics tests.test_dut tests.test_judgment tests.test_emitter`
2. 需要复核 RTL 时，复用服务器验证目录中的 `verify_remote.sh`、`run_remote.sh` 和 `run_cva6_remote.sh`。
3. 继续实验时，保持 PTW 黑盒结果为 `inconclusive`，直到取得匹配的 source-probe 阶段和地址证据。
4. 运行完整回归：
   `python -m unittest discover -s tests`
5. 运行覆盖率：
   `python -m coverage run --source=pmpfuzz -m unittest discover -s tests`
   `python -m coverage report --show-missing`
6. 执行 `compileall`、`git diff --check`、差异审查，更新本文件。
7. 当前剩余动作：创建 GREEN 修复提交；不要提交用户原有的 `paper/` 目录。

## 工作区约束

- 不修改项目根规则文件。
- 不修改服务器 `Android`、`work`、`ida-hcli`。
- `paper/` 是用户原有未跟踪内容，本轮不得纳入提交。
