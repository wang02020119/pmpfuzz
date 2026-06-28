from __future__ import annotations

from dataclasses import dataclass, field
from random import Random

from .mmu import PageTableEntry, Sv39Mapping, TranslationMode
from .pmp import Access, AddressMode, Mseccfg, PmpEntry, Privilege


MEM_BASE = 0x80000000
M_TEXT_BASE = 0x80000000
M_TEXT_SIZE = 0x2000
M_DATA_BASE = 0x80002000
M_DATA_SIZE = 0x2000
SU_CODE_BASE = 0x80004000
SU_CODE_SIZE = 0x1000
TARGET_BASE = 0x80008000
TARGET_SIZE = 0x1000
PAGE_TABLE_BASE = 0x80010000
PAGE_TABLE_SIZE = 0x8000
PROBE_VA = 0x40000000
TARGET_VA = 0x80000000


@dataclass(frozen=True)
class AccessProbe:
    access: Access
    physical_address: int
    size: int
    offset_name: str
    virtual_address: int | None = None

    def effective_address(self) -> int:
        return self.virtual_address if self.virtual_address is not None else self.physical_address


@dataclass(frozen=True)
class PmpScenario:
    name: str
    entries: list[PmpEntry]
    privilege: Privilege
    probe: AccessProbe
    mprv: bool
    mpp: Privilege
    mseccfg: Mseccfg = Mseccfg()
    translation: TranslationMode = TranslationMode.BARE
    sv39: Sv39Mapping | None = None
    profile: str = "legacy"
    sum_enabled: bool = False
    mxr: bool = False
    sfence_vma: bool = True
    coverage_tags: tuple[str, ...] = ()
    ptw_fault_level: str | None = None
    preload_mode: str | None = None
    pmp_match_mode: str | None = None
    pte_permissions: dict[str, object] = field(default_factory=dict)
    security_focus: str | None = None
    stateful_sequence: dict[str, object] | None = None


class ScenarioGenerator:
    def __init__(self, seed: int | None = None, include_smepmp: bool = True, profile: str = "legacy") -> None:
        self.random = Random(seed)
        self.include_smepmp = include_smepmp
        self.profile = profile

    def generate_batch(self, count: int) -> list[PmpScenario]:
        return [self._generate_one(index) for index in range(count)]

    def _generate_one(self, index: int) -> PmpScenario:
        if self.profile == "legacy-data":
            return self._generate_legacy(index, accesses=(Access.LOAD, Access.STORE), profile="legacy-data")
        if self.profile == "legacy-fetch-experimental":
            return self._generate_legacy(index, accesses=(Access.FETCH,), profile="legacy-fetch-experimental")
        if self.profile == "smepmp-table":
            return self._generate_smepmp_table(index)
        if self.profile == "pmp-boundary":
            return self._generate_pmp_boundary(index)
        if self.profile == "sv39-final-pmp":
            return self._generate_sv39(index, deny_page_walk=False, sfence_vma=True)
        if self.profile == "sv39-ptw-pmp":
            return self._generate_sv39(index, deny_page_walk=True, sfence_vma=True)
        if self.profile == "sv39-perm-matrix":
            return self._generate_sv39_perm_matrix(index)
        if self.profile == "sv39-ptw-pmp-matrix":
            return self._generate_sv39_ptw_pmp_matrix(index)
        if self.profile == "boom-ptw-pmp-regression":
            return self._generate_boom_ptw_pmp_regression(index)
        if self.profile == "pmp-side-effect":
            return self._generate_pmp_side_effect(index)
        if self.profile == "tlb-stale-pte":
            return self._generate_tlb_stale_pte(index)
        if self.profile == "tlb-stale-pmp":
            return self._generate_tlb_stale_pmp(index)
        if self.profile == "ptw-stale-pmp":
            return self._generate_ptw_stale_pmp(index)
        if self.profile == "tlb-fence":
            return self._generate_sv39(index, deny_page_walk=False, sfence_vma=index % 2 == 0)
        if self.profile == "mixed-smepmp-mmu":
            selector = index % 3
            if selector == 0:
                return self._generate_smepmp_table(index)
            if selector == 1:
                return self._generate_sv39(index, deny_page_walk=False, sfence_vma=True)
            return self._generate_sv39(index, deny_page_walk=True, sfence_vma=True)
        if self.profile != "legacy":
            raise ValueError(f"unsupported scenario profile: {self.profile}")
        return self._generate_legacy(index, accesses=(Access.LOAD, Access.STORE, Access.FETCH), profile="legacy")

    def _generate_legacy(self, index: int, *, accesses: tuple[Access, ...], profile: str) -> PmpScenario:
        base = 0x80004000 + (index % 8) * 0x2000
        size = 0x1000
        address_mode = AddressMode.TOR if index % 2 == 0 else AddressMode.NAPOT
        privilege = [Privilege.S, Privilege.U, Privilege.M][index % 3]
        access = accesses[index % len(accesses)]
        offset_name, address = self._probe_address(base, size, index)
        legacy_mml = self.include_smepmp and index % 13 == 0

        if address_mode == AddressMode.TOR:
            entries = [
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.OFF,
                    pmpaddr=base >> 2,
                    read=False,
                    write=False,
                    execute=False,
                    locked=False,
                ),
                self._entry(
                    index=1,
                    base=base,
                    size=size,
                    address_mode=address_mode,
                    salt=index,
                    allow_write_without_read=legacy_mml,
                ),
            ]
        else:
            entries = [
                self._entry(
                    index=0,
                    base=base,
                    size=size,
                    address_mode=address_mode,
                    salt=index,
                    allow_write_without_read=legacy_mml,
                )
            ]
        entries.append(self._harness_entry())

        return PmpScenario(
            name=f"scenario_{index:04d}",
            entries=entries,
            privilege=privilege,
            probe=AccessProbe(access=access, physical_address=address, size=4, offset_name=offset_name),
            mprv=index % 7 == 0,
            mpp=[Privilege.S, Privilege.U, Privilege.M][(index + 1) % 3],
            mseccfg=Mseccfg(
                mmwp=self.include_smepmp and index % 11 == 0,
                mml=legacy_mml,
            ),
            profile=profile,
            coverage_tags=("pmp", "legacy", access.value, privilege.value),
            pmp_match_mode=address_mode.name.lower(),
        )

    def _generate_pmp_boundary(self, index: int) -> PmpScenario:
        variants = (
            ("tor", "inside", True),
            ("tor", "upper_bound", False),
            ("na4", "inside", True),
            ("na4", "upper_bound", False),
            ("napot", "last_byte", True),
            ("napot", "upper_bound", False),
            ("first-match-overlap", "inside", False),
            ("first-match-overlap", "inside", True),
        )
        mode, offset_kind, allow = variants[index % len(variants)]
        access = [Access.LOAD, Access.STORE, Access.FETCH][(index // len(variants)) % 3]
        privilege = [Privilege.U, Privilege.S, Privilege.M][(index // (len(variants) * 3)) % 3]
        base = TARGET_BASE + ((index // (len(variants) * 3 * 3 * 2)) % 2) * 0x2000
        size = 0x1000
        locked = bool((index // (len(variants) * 3 * 3)) % 2)

        if mode == "tor":
            offset_name, address = ("inside", base + 0x100) if offset_kind == "inside" else ("upper_bound", base + size)
            entry = PmpEntry(
                index=1,
                address_mode=AddressMode.TOR,
                pmpaddr=(base + size) >> 2,
                read=True,
                write=True,
                execute=True,
                locked=locked,
            )
            entries = [
                PmpEntry(0, AddressMode.OFF, base >> 2, False, False, False, False),
                self._permissions_for_access(entry, access, allow),
            ]
        elif mode == "na4":
            offset_name, address = ("inside", base) if offset_kind == "inside" else ("upper_bound", base + 4)
            entries = [
                self._permissions_for_access(
                    PmpEntry(
                        index=0,
                        address_mode=AddressMode.NA4,
                        pmpaddr=base >> 2,
                        read=True,
                        write=True,
                        execute=True,
                        locked=locked,
                    ),
                    access,
                    allow,
                )
            ]
        elif mode == "napot":
            offset_name, address = ("last_byte", base + size - 4) if offset_kind == "last_byte" else ("upper_bound", base + size)
            entries = [
                self._permissions_for_access(
                    PmpEntry(
                        index=0,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=base, size=size),
                        read=True,
                        write=True,
                        execute=True,
                        locked=locked,
                    ),
                    access,
                    allow,
                )
            ]
        else:
            offset_name, address = "inside", base + 0x100
            entries = [
                self._permissions_for_access(
                    PmpEntry(
                        index=0,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=base, size=size),
                        read=True,
                        write=True,
                        execute=True,
                        locked=locked,
                    ),
                    access,
                    allow,
                ),
                self._permissions_for_access(
                    PmpEntry(
                        index=1,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=base, size=0x2000),
                        read=True,
                        write=True,
                        execute=True,
                        locked=False,
                    ),
                    access,
                    not allow,
                ),
            ]

        entries.append(self._su_harness_entry())
        entries.append(self._harness_entry())
        return PmpScenario(
            name=f"scenario_{index:04d}",
            entries=entries,
            privilege=privilege,
            probe=AccessProbe(access=access, physical_address=address, size=4, offset_name=offset_name),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(),
            profile="pmp-boundary",
            coverage_tags=(
                "pmp",
                "boundary",
                mode,
                access.value,
                privilege.value,
                "locked" if locked else "unlocked",
                "allow" if allow else "deny",
                offset_name,
            ),
            pmp_match_mode=mode,
            security_focus="pmp-boundary",
        )

    def _generate_smepmp_table(self, index: int) -> PmpScenario:
        encoding = index % 16
        locked = bool(encoding & 0x8)
        read = bool(encoding & 0x4)
        write = bool(encoding & 0x2)
        execute = bool(encoding & 0x1)
        access = [Access.LOAD, Access.STORE, Access.FETCH][index % 3]
        privilege = [Privilege.M, Privilege.S, Privilege.U][(index // 3) % 3]

        return PmpScenario(
            name=f"scenario_{index:04d}",
            entries=self._mml_harness_entries()
            + [
                PmpEntry(
                    index=4,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE),
                    read=read,
                    write=write,
                    execute=execute,
                    locked=locked,
                )
            ],
            privilege=privilege,
            probe=AccessProbe(
                access=access,
                physical_address=TARGET_BASE,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(rlb=self.include_smepmp, mml=self.include_smepmp, mmwp=self.include_smepmp),
            profile=self.profile,
        )

    def _generate_sv39(self, index: int, *, deny_page_walk: bool, sfence_vma: bool) -> PmpScenario:
        access = [Access.LOAD, Access.STORE, Access.FETCH][index % 3]
        privilege = [Privilege.U, Privilege.S][index % 2]
        pte = PageTableEntry(
            read=access in {Access.LOAD, Access.STORE},
            write=access == Access.STORE,
            execute=access == Access.FETCH,
            user=privilege == Privilege.U,
            accessed=True,
            dirty=access == Access.STORE,
        )
        return self._generate_sv39_custom(
            index=index,
            profile=self.profile,
            access=access,
            privilege=privilege,
            pte=pte,
            deny_page_walk=deny_page_walk,
            deny_walk_index=1,
            deny_locked=True,
            sfence_vma=sfence_vma,
            sum_enabled=privilege == Privilege.S,
            mxr=index % 5 == 0,
            preload_mode="cold" if deny_page_walk else None,
            security_focus="ptw-pmp" if deny_page_walk else "final-pmp",
        )

    def _generate_sv39_custom(
        self,
        *,
        index: int,
        profile: str,
        access: Access,
        privilege: Privilege,
        pte: PageTableEntry,
        deny_page_walk: bool,
        deny_walk_index: int = 1,
        deny_locked: bool = True,
        sfence_vma: bool = True,
        sum_enabled: bool = False,
        mxr: bool = False,
        preload_mode: str | None = None,
        security_focus: str | None = None,
    ) -> PmpScenario:
        mapping = self._target_mapping(pte)
        entries = self._mml_harness_entries()

        if deny_page_walk:
            deny_address = mapping.walk_addresses[deny_walk_index]
            deny_size = 8 if deny_walk_index == 0 else 0x1000
            deny_base = deny_address if deny_walk_index == 0 else deny_address & ~0xFFF
            entries.append(
                PmpEntry(
                    index=3,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=deny_base, size=deny_size),
                    read=False,
                    write=False,
                    execute=False,
                    locked=deny_locked,
                )
            )
            entries.append(
                PmpEntry(
                    index=4,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=PAGE_TABLE_BASE, size=PAGE_TABLE_SIZE),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                )
            )
            target_index = 5
            target_read = target_write = target_execute = True
        else:
            entries.append(
                PmpEntry(
                    index=3,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=PAGE_TABLE_BASE, size=PAGE_TABLE_SIZE),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                )
            )
            target_index = 4
            denied = index % 4 == 0
            target_read = access == Access.LOAD and not denied
            target_write = access == Access.STORE and not denied
            target_execute = access == Access.FETCH and not denied
            if target_write and not self.include_smepmp:
                target_read = True

        entries.append(
            PmpEntry(
                index=target_index,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE),
                read=target_read,
                write=target_write,
                execute=target_execute,
                locked=False,
            )
        )

        return PmpScenario(
            name=f"scenario_{index:04d}",
            entries=entries,
            privilege=privilege,
            probe=AccessProbe(
                access=access,
                physical_address=TARGET_BASE,
                virtual_address=TARGET_VA,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(rlb=self.include_smepmp, mml=self.include_smepmp, mmwp=self.include_smepmp),
            translation=TranslationMode.SV39,
            sv39=mapping,
            profile=profile,
            sum_enabled=sum_enabled,
            mxr=mxr,
            sfence_vma=sfence_vma,
            coverage_tags=self._sv39_coverage_tags(profile, access, privilege, pte, deny_page_walk, deny_walk_index),
            ptw_fault_level=("L2", "L1", "L0")[deny_walk_index] if deny_page_walk else None,
            preload_mode=preload_mode,
            pmp_match_mode=f"ptw-deny-{('L2', 'L1', 'L0')[deny_walk_index]}" if deny_page_walk else "final-pmp",
            pte_permissions=self._pte_permission_metadata(pte),
            security_focus=security_focus,
        )

    def _generate_sv39_perm_matrix(self, index: int) -> PmpScenario:
        pte_variants = [
            PageTableEntry(read=True, write=False, execute=False, user=True, accessed=True, dirty=False),
            PageTableEntry(read=True, write=True, execute=False, user=True, accessed=True, dirty=True),
            PageTableEntry(read=False, write=False, execute=True, user=True, accessed=True, dirty=False),
            PageTableEntry(read=False, write=True, execute=False, user=True, accessed=True, dirty=True),
            PageTableEntry(read=True, write=False, execute=True, user=False, accessed=True, dirty=False),
            PageTableEntry(read=True, write=True, execute=False, user=True, accessed=True, dirty=False),
            PageTableEntry(read=True, write=False, execute=False, user=True, accessed=False, dirty=False),
        ]
        pte = pte_variants[index % len(pte_variants)]
        access = [Access.LOAD, Access.STORE, Access.FETCH][(index // len(pte_variants)) % 3]
        privilege = [Privilege.U, Privilege.S][(index // (len(pte_variants) * 3)) % 2]
        sum_enabled = bool((index // (len(pte_variants) * 3 * 2)) % 2)
        mxr = bool((index // (len(pte_variants) * 3 * 2 * 2)) % 2)
        return self._generate_sv39_custom(
            index=index,
            profile="sv39-perm-matrix",
            access=access,
            privilege=privilege,
            pte=pte,
            deny_page_walk=False,
            sum_enabled=sum_enabled,
            mxr=mxr,
            security_focus="sv39-permission",
        )

    def _generate_sv39_ptw_pmp_matrix(self, index: int) -> PmpScenario:
        access = [Access.LOAD, Access.STORE, Access.FETCH][index % 3]
        privilege = [Privilege.U, Privilege.S][(index // 3) % 2]
        deny_walk_index = (index // (3 * 2)) % 3
        preload_modes = ("cold", "root-target", "denied-l1", "all")
        preload_mode = preload_modes[(index // (3 * 2 * 3)) % len(preload_modes)]
        deny_locked = bool((index // (3 * 2 * 3 * len(preload_modes))) % 2)
        mxr = not bool((index // (3 * 2 * 3 * len(preload_modes) * 2)) % 2)
        pte = PageTableEntry(
            read=access in {Access.LOAD, Access.STORE},
            write=access == Access.STORE,
            execute=access == Access.FETCH or mxr,
            user=privilege == Privilege.U,
            accessed=True,
            dirty=access == Access.STORE,
        )
        return self._generate_sv39_custom(
            index=index,
            profile="sv39-ptw-pmp-matrix",
            access=access,
            privilege=privilege,
            pte=pte,
            deny_page_walk=True,
            deny_walk_index=deny_walk_index,
            deny_locked=deny_locked,
            sum_enabled=privilege == Privilege.S,
            mxr=mxr,
            preload_mode=preload_mode,
            security_focus="ptw-pmp-matrix",
        )

    def _generate_boom_ptw_pmp_regression(self, index: int) -> PmpScenario:
        variants = [
            ("boom-ptw-pmp-hang", True, "cold", Privilege.U),
            ("mxr-off-control", False, "cold", Privilege.U),
            ("preload-root-target-control", True, "root-target", Privilege.U),
            ("preload-denied-l1-control", True, "denied-l1", Privilege.U),
            ("s-mode-wrong-mcause-control", True, "cold", Privilege.S),
            ("u-mode-wrong-mcause-control", True, "cold", Privilege.U),
        ]
        security_focus, mxr, preload_mode, privilege = variants[index % len(variants)]
        pte = PageTableEntry(read=True, write=False, execute=False, user=privilege == Privilege.U, accessed=True, dirty=False)
        return self._generate_sv39_custom(
            index=index,
            profile="boom-ptw-pmp-regression",
            access=Access.LOAD,
            privilege=privilege,
            pte=pte,
            deny_page_walk=True,
            deny_walk_index=1,
            deny_locked=True,
            sum_enabled=privilege == Privilege.S,
            mxr=mxr,
            preload_mode=preload_mode,
            security_focus=security_focus,
        )

    def _generate_pmp_side_effect(self, index: int) -> PmpScenario:
        allowed_control = index % 2 == 1
        privilege = [Privilege.U, Privilege.S][(index // 2) % 2]
        locked = bool((index // 4) % 2)
        target = PmpEntry(
            index=3,
            address_mode=AddressMode.NAPOT,
            pmpaddr=PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE),
            read=True,
            write=allowed_control,
            execute=False,
            locked=locked,
        )
        expected_final = "store_side_effect" if allowed_control else "trap_no_side_effect"
        return PmpScenario(
            name=f"scenario_{index:04d}",
            entries=self._mml_harness_entries() + [target],
            privilege=privilege,
            probe=AccessProbe(
                access=Access.STORE,
                physical_address=TARGET_BASE,
                size=4,
                offset_name="sentinel",
            ),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(),
            profile="pmp-side-effect",
            coverage_tags=(
                "pmp",
                "side-effect",
                privilege.value,
                "store",
                expected_final,
                "locked" if locked else "unlocked",
            ),
            pmp_match_mode="side-effect-target",
            security_focus="memory-side-effect",
            stateful_sequence=self._stateful_sequence(
                kind="pmp-side-effect",
                warmup=False,
                mutation="none",
                fence="none",
                expected_final=expected_final,
                expected_cause=7 if not allowed_control else None,
                stale_failure_class=None,
            ),
        )

    def _generate_tlb_stale_pte(self, index: int) -> PmpScenario:
        fence = "with-sfence" if index % 2 == 0 else "no-fence-experimental"
        privilege = [Privilege.U, Privilege.S][(index // 2) % 2]
        pte = PageTableEntry(read=True, write=False, execute=False, user=privilege == Privilege.U, accessed=True, dirty=False)
        return self._generate_stateful_sv39(
            index=index,
            profile="tlb-stale-pte",
            privilege=privilege,
            pte=pte,
            mutation="pte-deny-leaf",
            fence=fence,
            expected_cause=13,
            stale_failure_class="STALE_TLB_PERMISSION",
            tags=("stale-pte", fence),
        )

    def _generate_tlb_stale_pmp(self, index: int) -> PmpScenario:
        fence = "with-sfence" if index % 2 == 0 else "no-fence-experimental"
        privilege = [Privilege.U, Privilege.S][(index // 2) % 2]
        pte = PageTableEntry(read=True, write=False, execute=False, user=privilege == Privilege.U, accessed=True, dirty=False)
        return self._generate_stateful_sv39(
            index=index,
            profile="tlb-stale-pmp",
            privilege=privilege,
            pte=pte,
            mutation="pmpcfg-deny-target",
            fence=fence,
            expected_cause=5,
            stale_failure_class="STALE_PMP_PERMISSION",
            tags=("stale-pmp", fence),
        )

    def _generate_ptw_stale_pmp(self, index: int) -> PmpScenario:
        fence = "with-sfence" if index % 2 == 0 else "no-fence-experimental"
        privilege = [Privilege.U, Privilege.S][(index // 2) % 2]
        pte = PageTableEntry(read=True, write=False, execute=False, user=privilege == Privilege.U, accessed=True, dirty=False)
        return self._generate_stateful_sv39(
            index=index,
            profile="ptw-stale-pmp",
            privilege=privilege,
            pte=pte,
            mutation="pmpcfg-deny-ptw",
            fence=fence,
            expected_cause=5,
            stale_failure_class="STALE_PTW_PERMISSION",
            tags=("stale-ptw-pmp", fence),
        )

    def _generate_stateful_sv39(
        self,
        *,
        index: int,
        profile: str,
        privilege: Privilege,
        pte: PageTableEntry,
        mutation: str,
        fence: str,
        expected_cause: int,
        stale_failure_class: str,
        tags: tuple[str, ...],
    ) -> PmpScenario:
        mapping = self._target_mapping(pte)
        entries = self._mml_harness_entries()
        entries.append(
            PmpEntry(
                index=3,
                address_mode=AddressMode.OFF,
                pmpaddr=0,
                read=False,
                write=False,
                execute=False,
                locked=False,
            )
        )
        entries.append(
            PmpEntry(
                index=4,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=PAGE_TABLE_BASE, size=PAGE_TABLE_SIZE),
                read=True,
                write=False,
                execute=False,
                locked=False,
            )
        )
        entries.append(
            PmpEntry(
                index=5,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE),
                read=True,
                write=False,
                execute=False,
                locked=False,
            )
        )

        sequence = self._stateful_sequence(
            kind=profile,
            warmup=True,
            mutation=mutation,
            fence=fence,
            expected_final="trap_after_mutation",
            expected_cause=expected_cause,
            stale_failure_class=stale_failure_class,
        )
        if mutation == "pmpcfg-deny-target":
            sequence.update(self._pmp_mutation_sequence(entries, deny_target=True, deny_ptw=False))
        if mutation == "pmpcfg-deny-ptw":
            sequence.update(self._pmp_mutation_sequence(entries, deny_target=False, deny_ptw=True))
        if mutation == "pte-deny-leaf":
            sequence["pte_after"] = "0x0"

        return PmpScenario(
            name=f"scenario_{index:04d}",
            entries=entries,
            privilege=privilege,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=TARGET_BASE,
                virtual_address=TARGET_VA,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(),
            translation=TranslationMode.SV39,
            sv39=mapping,
            profile=profile,
            sum_enabled=privilege == Privilege.S,
            mxr=False,
            sfence_vma=True,
            coverage_tags=("sv39", "stateful", "load", privilege.value, *tags),
            ptw_fault_level="L1" if mutation == "pmpcfg-deny-ptw" else None,
            preload_mode="warmup",
            pmp_match_mode=mutation,
            pte_permissions=self._pte_permission_metadata(pte),
            security_focus=profile,
            stateful_sequence=sequence,
        )

    def _mml_harness_entries(self) -> list[PmpEntry]:
        return [
            PmpEntry(
                index=0,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=M_TEXT_BASE, size=M_TEXT_SIZE),
                read=True,
                write=False,
                execute=True,
                locked=True,
            ),
            PmpEntry(
                index=1,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=M_DATA_BASE, size=M_DATA_SIZE),
                read=True,
                write=True,
                execute=False,
                locked=True,
            ),
            PmpEntry(
                index=2,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE),
                read=True,
                write=False,
                execute=True,
                locked=False,
            ),
        ]

    def _target_mapping(self, pte: PageTableEntry) -> Sv39Mapping:
        return Sv39Mapping(
            virtual_page=TARGET_VA,
            physical_page=TARGET_BASE,
            root_table=PAGE_TABLE_BASE,
            walk_addresses=(PAGE_TABLE_BASE + 0x10, PAGE_TABLE_BASE + 0x3000, PAGE_TABLE_BASE + 0x4000),
            pte=pte,
        )

    def _entry(
        self,
        *,
        index: int,
        base: int,
        size: int,
        address_mode: AddressMode,
        salt: int,
        allow_write_without_read: bool = False,
    ) -> PmpEntry:
        if address_mode == AddressMode.TOR:
            pmpaddr = (base + size) >> 2
        elif address_mode == AddressMode.NAPOT:
            pmpaddr = PmpEntry.encode_napot(base=base, size=size)
        else:
            raise ValueError("stage 1 generator only emits TOR and NAPOT regions")

        permissions = salt % 7
        read = bool(permissions & 0x1)
        write = bool(permissions & 0x2)
        execute = bool(permissions & 0x4)
        if write and not read and not allow_write_without_read:
            read = True
        return PmpEntry(
            index=index,
            address_mode=address_mode,
            pmpaddr=pmpaddr,
            read=read,
            write=write,
            execute=execute,
            locked=salt % 4 == 0,
        )

    def _permissions_for_access(self, entry: PmpEntry, access: Access, allow: bool) -> PmpEntry:
        if not allow:
            return PmpEntry(entry.index, entry.address_mode, entry.pmpaddr, False, False, False, entry.locked)
        read = access == Access.LOAD or access == Access.STORE
        write = access == Access.STORE
        execute = access == Access.FETCH
        return PmpEntry(entry.index, entry.address_mode, entry.pmpaddr, read, write, execute, entry.locked)

    def _stateful_sequence(
        self,
        *,
        kind: str,
        warmup: bool,
        mutation: str,
        fence: str,
        expected_final: str,
        expected_cause: int | None,
        stale_failure_class: str | None,
    ) -> dict[str, object]:
        return {
            "kind": kind,
            "warmup": warmup,
            "mutation": mutation,
            "fence": fence,
            "final_probe": "repeat",
            "sentinel": {
                "physical_address": f"0x{TARGET_BASE:x}",
                "initial": "0x11223344",
                "store": "0x5a5a5a5a",
            },
            "expected_final": expected_final,
            "expected_cause": expected_cause,
            "stale_failure_class": stale_failure_class,
        }

    def _pmp_mutation_sequence(
        self,
        entries: list[PmpEntry],
        *,
        deny_target: bool,
        deny_ptw: bool,
    ) -> dict[str, object]:
        after = list(entries)
        writes: list[dict[str, object]] = []
        if deny_target:
            after = [
                PmpEntry(entry.index, entry.address_mode, entry.pmpaddr, False, False, entry.execute, entry.locked)
                if entry.index == 5
                else entry
                for entry in after
            ]
        if deny_ptw:
            deny_base = (PAGE_TABLE_BASE + 0x3000) & ~0xFFF
            deny_entry = PmpEntry(
                index=3,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=deny_base, size=0x1000),
                read=False,
                write=False,
                execute=False,
                locked=False,
            )
            after = [deny_entry if entry.index == 3 else entry for entry in after]
            writes.append({"index": 3, "pmpaddr": f"0x{deny_entry.pmpaddr:x}"})
        return {
            "pmpaddr_writes": writes,
            "pmpcfg0_after": f"0x{self._pmpcfg0(after):x}",
        }

    def _pmpcfg0(self, entries: list[PmpEntry]) -> int:
        cfg0 = 0
        for entry in entries:
            cfg0 |= entry.cfg_byte() << (entry.index * 8)
        return cfg0

    def _sv39_coverage_tags(
        self,
        profile: str,
        access: Access,
        privilege: Privilege,
        pte: PageTableEntry,
        deny_page_walk: bool,
        deny_walk_index: int,
    ) -> tuple[str, ...]:
        tags = ["sv39", access.value, privilege.value, self._pte_permission_metadata(pte)["rwx"]]
        if deny_page_walk:
            tags.extend(["ptw-pmp", ("L2", "L1", "L0")[deny_walk_index]])
        if profile == "boom-ptw-pmp-regression":
            tags.append("boom-regression")
        if profile == "sv39-perm-matrix":
            tags.append("pte-permission")
        return tuple(tags)

    def _pte_permission_metadata(self, pte: PageTableEntry) -> dict[str, object]:
        return {
            "rwx": ("r" if pte.read else "-") + ("w" if pte.write else "-") + ("x" if pte.execute else "-"),
            "user": pte.user,
            "accessed": pte.accessed,
            "dirty": pte.dirty,
            "valid": pte.valid,
        }

    def _harness_entry(self) -> PmpEntry:
        return PmpEntry(
            index=7,
            address_mode=AddressMode.NAPOT,
            pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x4000),
            read=True,
            write=True,
            execute=True,
            locked=False,
        )

    def _su_harness_entry(self) -> PmpEntry:
        return PmpEntry(
            index=6,
            address_mode=AddressMode.NAPOT,
            pmpaddr=PmpEntry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE),
            read=True,
            write=False,
            execute=True,
            locked=False,
        )

    def _probe_address(self, base: int, size: int, index: int) -> tuple[str, int]:
        probes = [
            ("lower_bound", base),
            ("inside", base + self.random.randrange(4, size - 4, 4)),
            ("last_byte", base + size - 4),
            ("upper_bound", base + size),
        ]
        return probes[index % len(probes)]
