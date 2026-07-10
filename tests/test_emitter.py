import inspect
import unittest

import pmpfuzz.emitter as emitter_module
from pmpfuzz.emitter import AssemblyEmitter
from pmpfuzz.scenario import MEM_BASE, ScenarioGenerator
from pmpfuzz.mmu import PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.pmp import Access, AddressMode, PmpEntry, Privilege
from pmpfuzz.scenario import AccessProbe, PmpScenario


class AssemblyEmitterTest(unittest.TestCase):
    def test_emitter_reports_observations_without_importing_oracle_decisions(self):
        source = inspect.getsource(emitter_module)

        self.assertNotIn("evaluate_scenario", source)
        self.assertNotIn("expected_cause", source)

    def test_emits_machine_mode_probe_with_trap_handler_and_tohost(self):
        scenario = PmpScenario(
            name="deny_s_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80002000, size=0x1000),
                    read=False,
                    write=False,
                    execute=False,
                    locked=False,
                )
            ],
            privilege=Privilege.S,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80002010,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
        )

        asm = AssemblyEmitter().emit(scenario)

        self.assertIn("_start:", asm)
        self.assertIn("mtvec", asm)
        self.assertIn("pmpaddr0", asm)
        self.assertIn("pmpcfg0", asm)
        self.assertIn("mret", asm)
        self.assertIn("tohost", asm)

    def test_sv39_emitter_sets_satp_and_emits_page_tables(self):
        scenario = PmpScenario(
            name="sv39_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x2000),
                    read=True,
                    write=False,
                    execute=True,
                    locked=True,
                ),
                PmpEntry(
                    index=1,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80002000, size=0x2000),
                    read=True,
                    write=True,
                    execute=False,
                    locked=True,
                ),
                PmpEntry(
                    index=2,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80004000, size=0x1000),
                    read=True,
                    write=False,
                    execute=True,
                    locked=False,
                ),
                PmpEntry(
                    index=3,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80010000, size=0x8000),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                ),
                PmpEntry(
                    index=4,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                ),
            ],
            privilege=Privilege.U,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80008000,
                virtual_address=0x80000000,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            translation=TranslationMode.SV39,
            sv39=Sv39Mapping(
                virtual_page=0x80000000,
                physical_page=0x80008000,
                root_table=0x80010000,
                walk_addresses=(0x80010010, 0x80011000, 0x80012000),
                pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=True, dirty=False),
            ),
        )

        asm = AssemblyEmitter().emit(scenario)

        self.assertIn("csrw satp", asm)
        self.assertIn("sfence.vma", asm)
        self.assertIn("sv39_root_table", asm)
        self.assertIn("li t0, 0x80000000", asm)

    def test_cascade_mmio_backend_emits_result_dump_and_stop_registers(self):
        scenario = PmpScenario(
            name="allow_m_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x20000),
                    read=True,
                    write=True,
                    execute=True,
                    locked=False,
                )
            ],
            privilege=Privilege.M,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80008000,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            profile="bare-pmp",
        )

        asm = AssemblyEmitter().emit(scenario, backend="cascade-mmio")

        self.assertIn("0x60000010", asm)
        self.assertIn("0x60000000", asm)
        self.assertNotIn("sd a0, 0(t0)\n1:  j 1b", asm)

    def test_cascade_mmio_legacy_backend_keeps_runtime_storage_labels(self):
        scenario = PmpScenario(
            name="legacy_allow_m_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x20000),
                    read=True,
                    write=True,
                    execute=True,
                    locked=False,
                )
            ],
            privilege=Privilege.M,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80008000,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
        )

        asm = AssemblyEmitter().emit(scenario, backend="cascade-mmio")

        self.assertIn("stack_top:", asm)
        self.assertIn("result:", asm)
        self.assertIn("0x60000010", asm)

    def test_fetch_target_uses_single_ecall_for_na4_boundary_probe(self):
        scenario = ScenarioGenerator(seed=20260629, include_smepmp=False, profile="pmp-boundary").generate_batch(19)[18]

        self.assertEqual(scenario.probe.access, Access.FETCH)
        asm = AssemblyEmitter().emit(scenario)
        target_offset = scenario.probe.physical_address - MEM_BASE

        self.assertIn(f"    .org 0x{target_offset:x}\ntarget_region:\n    la t0, observation_phase", asm)
        self.assertIn("    li t1, 2\n    sw t1, 0(t0)\n    li a0, 0x51\n    ecall", asm)

    def test_xiangshan_goodtrap_backend_uses_xstrap_words_not_ebreak(self):
        scenario = ScenarioGenerator(seed=20260628, include_smepmp=False, profile="legacy-data").generate_batch(3)[2]

        asm = AssemblyEmitter().emit(scenario, backend="xiangshan-goodtrap")

        self.assertIn(".word 0x0000006b", asm)
        self.assertIn(".word 0x0000806b", asm)
        self.assertNotIn("ebreak", asm)

    def test_stateful_side_effect_harness_emits_phase_and_sentinel_checks(self):
        scenario = ScenarioGenerator(seed=71, include_smepmp=False, profile="pmp-side-effect").generate_batch(count=1)[0]

        asm = AssemblyEmitter().emit(scenario)

        self.assertIn("stateful_phase:", asm)
        self.assertIn("sentinel_word:", asm)
        self.assertIn("apply_stateful_mutation:", asm)
        self.assertIn("stateful_final_probe:", asm)
        self.assertIn("stateful_sentinel_initial:", asm)
        self.assertIn("stateful_sentinel_modified:", asm)
        self.assertIn("stateful_report_trap:", asm)
        self.assertIn("stateful_report_completion:", asm)
        self.assertNotIn("fail_forbidden_side_effect:", asm)

    def test_stateful_stale_harness_emits_mutation_and_optional_sfence(self):
        with_fence = ScenarioGenerator(seed=73, include_smepmp=False, profile="tlb-stale-pte").generate_batch(count=1)[0]
        no_fence = ScenarioGenerator(seed=73, include_smepmp=False, profile="tlb-stale-pte").generate_batch(count=2)[1]

        with_fence_asm = AssemblyEmitter().emit(with_fence)
        no_fence_asm = AssemblyEmitter().emit(no_fence)

        self.assertIn("apply_stateful_mutation:", with_fence_asm)
        self.assertIn("sd t1, 0(t0)", with_fence_asm)
        self.assertIn("sfence.vma", with_fence_asm)
        self.assertIn("no_fence_experimental:", no_fence_asm)


if __name__ == "__main__":
    unittest.main()
