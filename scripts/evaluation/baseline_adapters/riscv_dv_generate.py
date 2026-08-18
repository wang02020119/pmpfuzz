#!/usr/bin/env python3
"""RISCV-DV baseline generator driver (PMPFuzz experiment tooling, NOT part of riscv-dv).

Purpose: run the official riscv-dv PyGen generator for the riscv-dv-baseline experiment
without modifying any riscv-dv source file.

Adaptation decisions (recorded in RUNLOG.md of the experiment repo):
1. Upstream pygen bug: riscv_asm_program_gen.gen_callstack() references
   self.callstack_gen, which is never initialized in __init__ (the SV version creates it
   in new()). On modern pyvsc this raises AttributeError. We do NOT modify riscv-dv;
   instead we pass the public config switch --num_of_sub_program 0, so the broken
   callstack path is not exercised. The main random instruction stream machinery
   (riscv_instr_sequence / riscv_rand_instr streams) is unchanged.
2. This subclass restores the directed instruction streams of the official
   riscv_rand_instr_test (load-store random stream, jal stream, load-store hazard
   stream at 4/1000 each) via the public add_directed_instr_stream API.
3. Upstream runs the test through multiprocessing.Pool(spawn); on Python 3.11 that
   deadlocks (task pickling blocks on the import lock while the worker re-imports the
   module tree whose module-level runner is re-entered). We keep upstream per-iteration
   semantics (one process per case, --num_of_tests loop in-process). run.py drives the
   same one-case-per-invocation pattern via --seed/--start_idx.
4. --gen_test must NOT equal riscv_instr_base_test, otherwise the module-level runner
   at the bottom of riscv_instr_base_test.py executes on import (upstream quirk); this
   driver passes its own name and invokes run_phase directly.

Invocation (cwd must be the riscv-dv checkout root):
  PYTHONDONTWRITEBYTECODE=1 <venv>/bin/python <path>/gen_rdv.py \
      --num_of_tests 1 --start_idx 0 --asm_file_name <prefix> --log_file_name <log> \
      --target rv64imc --gen_test riscv_rand_instr_nosub --seed S \
      --num_of_sub_program 0 --instr_cnt <N> --no_directed_instr 0
"""

import logging
import sys
import time

sys.path.insert(0, "pygen/")
sys.path.insert(0, "pygen/pygen_src")

from pygen_src.test.riscv_instr_base_test import riscv_instr_base_test  # noqa: E402
from pygen_src.riscv_instr_gen_config import cfg  # noqa: E402


class riscv_rand_instr_nosub_test(riscv_instr_base_test):
    """Official random-instruction test semantics minus sub-program callstack."""

    def apply_directed_instr(self):
        # Same directed streams as upstream pygen_src/test/riscv_rand_instr_test.py
        self.asm.add_directed_instr_stream("riscv_load_store_rand_instr_stream", 4)
        self.asm.add_directed_instr_stream("riscv_jal_instr", 4)
        self.asm.add_directed_instr_stream("riscv_load_store_hazard_instr_stream", 4)


def main():
    start_time = time.time()
    test = riscv_rand_instr_nosub_test()
    rets = []
    for i in range(cfg.num_of_tests):
        rets.append(test.run_phase(i))
    if 1 in rets:
        raise Exception("Test-generation jobs failed")
    end_time = time.time()
    logging.info("Total execution time: {}s".format(round(end_time - start_time)))


if __name__ == "__main__":
    main()
