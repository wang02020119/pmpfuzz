#!/usr/bin/env python3

import logging
import sys
import time

sys.path.insert(0, "pygen/")
sys.path.insert(0, "pygen/pygen_src")

from pygen_src.test.riscv_instr_base_test import riscv_instr_base_test
from pygen_src.riscv_instr_gen_config import cfg


class riscv_rand_instr_nosub_test(riscv_instr_base_test):

    def apply_directed_instr(self):

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
