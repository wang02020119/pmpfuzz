from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .capabilities import DEFAULT_CAPABILITY_SCHEMA_VERSION, oracle_applicability_for_case


C910_NONPMP_TARGET = "c910-nonpmp"
C910_NONPMP_DUT = "c910-nonpmp"
C910_NONPMP_CAPABILITY_PROFILE = "c910-nonpmp-v1"
C910_NONPMP_PROFILES = (
    "c910-nonpmp-privilege",
    "c910-nonpmp-sv39",
    "c910-nonpmp-tlb",
    "c910-nonpmp-fetch",
    "c910-nonpmp-side-effect",
)
BOOTSTRAP_SEED = 20260727
_DEFAULT_C910_SERIAL_PORT = os.environ.get("PMPFUZZ_BOARD_SERIAL_PORT", "")
_DEFAULT_C910_LOGIN_USER = os.environ.get("PMPFUZZ_BOARD_LOGIN_USER", "")
_DEFAULT_C910_LOGIN_PASSWORD = os.environ.get("PMPFUZZ_BOARD_LOGIN_PASSWORD", "")

_REAL_MODE_RE = re.compile(
    r"\[nonpmp-chain\] real-mode record=(?P<record>\S+) "
    r"entry=(?P<entry>\S+) mpp=(?P<mpp>\d+) arg0=(?P<arg0>\S+) arg1=(?P<arg1>\S+) "
    r"satp=(?P<satp>\S+) extra=(?P<extra>\S+) result=(?P<result>\S+) "
    r"cause=(?P<cause>\S+) trap_name=(?P<trap_name>\S+) tval=(?P<tval>\S+) "
    r"mepc=(?P<mepc>\S+) payload_result=(?P<payload_result>\S+)"
)
_MPRV_RE = re.compile(
    r"\[security-chain\] (?P<op>mprv-load|mprv-store|mprv-amoadd) (?P<record>\S+) "
    r"addr=(?P<addr>\S+) mpp=(?P<mpp>\d+) extra=(?P<extra>\S+) result=(?P<result>\S+)"
    r"(?: cause=(?P<cause>\S+) trap_name=(?P<trap_name>\S+) tval=(?P<tval>\S+))?"
    r"(?: val=(?P<val>\S+))?(?: old=(?P<old>\S+))?"
)
_FETCH_TEST_RE = re.compile(
    r"\[security-chain\] fetch-test (?P<record>\S+) entry=(?P<entry>\S+) mpp=(?P<mpp>\d+) "
    r"satp=(?P<satp>\S+) sfence=(?P<sfence>\d+) fencei=(?P<fencei>\d+) result=(?P<result>\S+) "
    r"cause=(?P<cause>\S+) trap_name=(?P<trap_name>\S+) tval=(?P<tval>\S+) mepc=(?P<mepc>\S+)"
)
_UARCH_LOAD_RE = re.compile(
    r"\[uarch-chain\] load record=(?P<record>\S+) addr=(?P<addr>\S+) mpp=(?P<mpp>\d+) "
    r"extra=(?P<extra>\S+) satp=(?P<satp>\S+) result=(?P<result>\S+)"
    r"(?: cause=(?P<cause>\S+) trap_name=(?P<trap_name>\S+) tval=(?P<tval>\S+))?"
    r"(?: val=(?P<val>\S+))?"
)
_ALIAS_LOAD_RE = re.compile(
    r"\[uarch-chain\] alias-load record=(?P<record>\S+) addr=(?P<addr>\S+) mpp=(?P<mpp>\d+) "
    r"extra=(?P<extra>\S+) satp=(?P<satp>\S+) result=(?P<result>\S+)"
    r"(?: cause=(?P<cause>\S+) trap_name=(?P<trap_name>\S+) tval=(?P<tval>\S+))?"
    r"(?: val=(?P<val>\S+))? direct0=(?P<direct0>\S+) direct1=(?P<direct1>\S+)"
)
_UARCH_FETCH_RE = re.compile(
    r"\[uarch-chain\] fetch record=(?P<record>\S+) "
    r"(?:(?:entry=(?P<entry>\S+) mpp=(?P<mpp>\d+) satp=(?P<satp>\S+) watchdog_ticks=(?P<watchdog>\d+) "
    r"result=(?P<result>\S+) cause=(?P<cause>\S+) trap_name=(?P<trap_name>\S+) tval=(?P<tval>\S+) mepc=(?P<mepc>\S+))|"
    r"(?:status=skipped reason=(?P<skip_reason>\S+) entry=(?P<skip_entry>\S+) mpp=(?P<skip_mpp>\d+) satp=(?P<skip_satp>\S+)))"
)
_SUM_FETCH_RE = re.compile(
    r"\[uarch-chain\] sum-fetch record=(?P<record>\S+) entry=(?P<entry>\S+) marker_va=(?P<marker_va>\S+) "
    r"run_mpp=(?P<run_mpp>\d+) run_extra=(?P<run_extra>\S+) marker_mpp=(?P<marker_mpp>\d+) "
    r"marker_extra=(?P<marker_extra>\S+) satp=(?P<satp>\S+) init_marker=(?P<init_marker>\S+) "
    r"init_cause=(?P<init_cause>\S+) init_name=(?P<init_name>\S+) result=(?P<result>\S+) "
    r"cause=(?P<cause>\S+) trap_name=(?P<trap_name>\S+) tval=(?P<tval>\S+) mepc=(?P<mepc>\S+) "
    r"marker=(?P<marker>\S+) marker_read_cause=(?P<marker_read_cause>\S+) marker_read_name=(?P<marker_read_name>\S+) "
    r"marker_hit=(?P<marker_hit>\d+) verdict=(?P<verdict>\S+)"
)
_SIDE_EFFECT_RE = re.compile(
    r"\[(?:security-chain|uarch-chain)\] side-effect (?:record=)?(?P<record>\S+) (?P<rest>.+)"
)


_CASE_SPECS: tuple[dict[str, Any], ...] = (
    {"profile": "c910-nonpmp-privilege", "record": "guard-as-m", "parser": "mprv", "privilege": "M", "access": "load", "translation": "bare", "required_caps": [], "security_focus": "mprv_bare"},
    {"profile": "c910-nonpmp-privilege", "record": "guard-as-s", "parser": "mprv", "privilege": "S", "access": "load", "translation": "bare", "required_caps": ["s_mode"], "security_focus": "mprv_bare"},
    {"profile": "c910-nonpmp-privilege", "record": "guard-as-u", "parser": "mprv", "privilege": "U", "access": "load", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "mprv_bare"},
    {"profile": "c910-nonpmp-privilege", "record": "guard-store-as-u", "parser": "mprv", "privilege": "U", "access": "store", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "mprv_bare"},
    {
        "profile": "c910-nonpmp-privilege",
        "record": "bare-u-store",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "bare",
        "required_caps": ["u_mode"],
        "security_focus": "mprv_bare",
        "stateful": {"kind": "final_pa_observer", "mutation": "store", "fence": "none", "expected_final": "target_specific_final_pa"},
    },
    {"profile": "c910-nonpmp-privilege", "record": "misaligned-load-as-u", "parser": "mprv", "privilege": "U", "access": "load", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "misaligned"},
    {"profile": "c910-nonpmp-privilege", "record": "misaligned-store-as-u", "parser": "mprv", "privilege": "U", "access": "store", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "misaligned"},
    {"profile": "c910-nonpmp-privilege", "record": "bare-s-ecall-fw-text", "parser": "real-mode", "privilege": "S", "access": "fetch", "translation": "bare", "required_caps": ["s_mode"], "security_focus": "real_mode"},
    {"profile": "c910-nonpmp-privilege", "record": "bare-u-ecall-fw-text", "parser": "real-mode", "privilege": "U", "access": "fetch", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "real_mode"},
    {"profile": "c910-nonpmp-privilege", "record": "bare-s-load-fw-data", "parser": "real-mode", "privilege": "S", "access": "load", "translation": "bare", "required_caps": ["s_mode"], "security_focus": "real_mode"},
    {"profile": "c910-nonpmp-privilege", "record": "bare-u-load-fw-data", "parser": "real-mode", "privilege": "U", "access": "load", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "real_mode"},
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "real-u-store-fw-data",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "bare",
        "required_caps": ["u_mode"],
        "security_focus": "real_mode",
        "stateful": {"kind": "final_pa_observer", "mutation": "store", "fence": "none", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-privilege",
        "record": "real-u-amoadd-fw-data",
        "parser": "side-effect",
        "privilege": "U",
        "access": "amoadd",
        "translation": "bare",
        "required_caps": ["u_mode"],
        "security_focus": "real_mode",
        "stateful": {"kind": "final_pa_observer", "mutation": "amoadd", "fence": "none", "expected_final": "target_specific_final_pa"},
    },
    {"profile": "c910-nonpmp-privilege", "record": "bare-mprv-u-amoadd-fw-data", "parser": "mprv", "privilege": "U", "access": "amoadd", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "mprv_bare"},
    {
        "profile": "c910-nonpmp-privilege",
        "record": "mprv-u-amoadd-bare-fw-data",
        "parser": "side-effect",
        "privilege": "U",
        "access": "amoadd",
        "translation": "bare",
        "required_caps": ["u_mode"],
        "security_focus": "mprv_bare",
        "stateful": {"kind": "final_pa_observer", "mutation": "amoadd", "fence": "none", "expected_final": "target_specific_final_pa"},
    },
    {"profile": "c910-nonpmp-sv39", "record": "sv39-s-load-supervisor-page", "parser": "mprv", "privilege": "S", "access": "load", "translation": "sv39", "required_caps": ["sv39", "s_mode"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": False, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-u-load-supervisor-page", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": False, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-u-load-user-page", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-s-load-user-page-sum0", "parser": "mprv", "privilege": "S", "access": "load", "translation": "sv39", "required_caps": ["sv39", "s_mode"], "security_focus": "sv39_permissions", "sum_enabled": False, "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-s-load-user-page-sum1", "parser": "mprv", "privilege": "S", "access": "load", "translation": "sv39", "required_caps": ["sv39", "s_mode"], "security_focus": "sv39_permissions", "sum_enabled": True, "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-u-load-xonly-page-mxr0", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_permissions", "mxr": False, "pte_permissions": {"rwx": "--x", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-u-load-xonly-page-mxr1", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_permissions", "mxr": True, "pte_permissions": {"rwx": "--x", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-ad-load-u-a0", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_ad", "ad_update_mode": "hardware", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": False, "dirty": False, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-ad-store-u-d0", "parser": "mprv", "privilege": "U", "access": "store", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_ad", "ad_update_mode": "hardware", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": False, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-stale-fill", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_stale_permission", "preload_mode": "fill", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-stale-after-clear-nosfence", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_stale_permission", "preload_mode": "clear_r", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-stale-after-clear-sfence", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_stale_permission", "preload_mode": "clear_r_sfence", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-u-store-readonly-page", "parser": "mprv", "privilege": "U", "access": "store", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "r--", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "sv39-u-load-invalid-page", "parser": "mprv", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": False}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-fill-asid1", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_asid_global", "preload_mode": "asid1_fill", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-clear-nosfence", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_asid_global", "preload_mode": "asid1_clear_r_no_sfence", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-asid-switch", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_asid_global", "preload_mode": "asid_switch", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-asid-return-nosfence", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_asid_global", "preload_mode": "asid_return_no_sfence", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-asid-return-sfence-va", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_asid_global", "preload_mode": "asid_return_sfence_va", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-global-fill-asid1", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_global", "preload_mode": "global_fill", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-global-after-asid-switch", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_global", "preload_mode": "global_asid_switch", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-tlb", "record": "tlb-global-after-sfence-all", "parser": "uarch-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "tlb_global", "preload_mode": "global_after_sfence_all", "pte_permissions": {"rwx": "---", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-fetch", "record": "bare-u-exec-ecall", "parser": "fetch-test", "privilege": "U", "access": "fetch", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "fetch_execute"},
    {"profile": "c910-nonpmp-fetch", "record": "bare-s-exec-ecall", "parser": "fetch-test", "privilege": "S", "access": "fetch", "translation": "bare", "required_caps": ["s_mode"], "security_focus": "fetch_execute"},
    {"profile": "c910-nonpmp-fetch", "record": "sv39-u-exec-x-page-ecall-watchdog", "parser": "uarch-fetch", "privilege": "U", "access": "fetch", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "fetch_execute"},
    {"profile": "c910-nonpmp-fetch", "record": "sv39-u-exec-x-fwtext-ecall-watchdog", "parser": "uarch-fetch", "privilege": "U", "access": "fetch", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "fetch_execute"},
    {"profile": "c910-nonpmp-fetch", "record": "sv39-u-exec-nx-page", "parser": "fetch-test", "privilege": "U", "access": "fetch", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "fetch_execute"},
    {"profile": "c910-nonpmp-fetch", "record": "bare-u-exec-after-code-patch-fencei", "parser": "fetch-test", "privilege": "U", "access": "fetch", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "fence_i"},
    {"profile": "c910-nonpmp-fetch", "record": "bare-u-exec-illegal", "parser": "fetch-test", "privilege": "U", "access": "fetch", "translation": "bare", "required_caps": ["u_mode"], "security_focus": "illegal_fetch"},
    {"profile": "c910-nonpmp-fetch", "record": "fetch-x-fill-watchdog", "parser": "uarch-fetch", "privilege": "U", "access": "fetch", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "fetch_itlb_stale", "preload_mode": "x_fill"},
    {"profile": "c910-nonpmp-fetch", "record": "fetch-after-x-clear-nosfence-watchdog", "parser": "uarch-fetch", "privilege": "U", "access": "fetch", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "fetch_itlb_stale", "preload_mode": "x_clear_no_sfence"},
    {"profile": "c910-nonpmp-fetch", "record": "fetch-after-x-clear-sfence-watchdog", "parser": "uarch-fetch", "privilege": "U", "access": "fetch", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "fetch_itlb_stale", "preload_mode": "x_clear_sfence"},
    {
        "profile": "c910-nonpmp-fetch",
        "record": "s-fetch-u-page-sum0",
        "parser": "sum-fetch",
        "privilege": "S",
        "access": "fetch",
        "translation": "sv39",
        "required_caps": ["sv39", "s_mode"],
        "security_focus": "sum_fetch_user_page",
        "sum_enabled": False,
        "stateful": {"kind": "marker_watchdog", "mutation": "sum_fetch", "fence": "watchdog", "expected_final": "target_specific_marker"},
    },
    {
        "profile": "c910-nonpmp-fetch",
        "record": "s-fetch-u-page-sum1",
        "parser": "sum-fetch",
        "privilege": "S",
        "access": "fetch",
        "translation": "sv39",
        "required_caps": ["sv39", "s_mode"],
        "security_focus": "sum_fetch_user_page",
        "sum_enabled": True,
        "stateful": {"kind": "marker_watchdog", "mutation": "sum_fetch", "fence": "watchdog", "expected_final": "target_specific_marker"},
    },
    {
        "profile": "c910-nonpmp-fetch",
        "record": "u-fetch-u-page-control",
        "parser": "sum-fetch",
        "privilege": "U",
        "access": "fetch",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "sum_fetch_user_page",
        "stateful": {"kind": "marker_watchdog", "mutation": "sum_fetch", "fence": "watchdog", "expected_final": "target_specific_marker"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "translated-u-store-final-pa",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "translated_pa_side_effect",
        "stateful": {"kind": "final_pa_observer", "mutation": "store", "fence": "before_ciall", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "translated-u-store-after-ciall",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "translated_pa_side_effect",
        "stateful": {"kind": "final_pa_observer", "mutation": "store", "fence": "after_ciall", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "translated-u-amoadd-final-pa",
        "parser": "side-effect",
        "privilege": "U",
        "access": "amoadd",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "translated_pa_side_effect",
        "stateful": {"kind": "final_pa_observer", "mutation": "amoadd", "fence": "before_ciall", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "translated-u-amoadd-after-ciall",
        "parser": "side-effect",
        "privilege": "U",
        "access": "amoadd",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "translated_pa_side_effect",
        "stateful": {"kind": "final_pa_observer", "mutation": "amoadd", "fence": "after_ciall", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "store-stale-fill",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "store_stale",
        "stateful": {"kind": "final_pa_observer", "mutation": "fill", "fence": "none", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "store-stale-fill-after-ciall",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "store_stale",
        "stateful": {"kind": "final_pa_observer", "mutation": "fill", "fence": "after_ciall", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "store-stale-after-w-clear-nosfence",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "store_stale",
        "stateful": {"kind": "final_pa_observer", "mutation": "clear_w", "fence": "no_sfence", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "store-stale-after-w-clear-nosfence-after-ciall",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "store_stale",
        "stateful": {"kind": "final_pa_observer", "mutation": "clear_w", "fence": "no_sfence_after_ciall", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "store-stale-after-w-clear-sfence",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "store_stale",
        "stateful": {"kind": "final_pa_observer", "mutation": "clear_w", "fence": "sfence", "expected_final": "target_specific_final_pa"},
    },
    {
        "profile": "c910-nonpmp-side-effect",
        "record": "store-stale-after-w-clear-sfence-after-ciall",
        "parser": "side-effect",
        "privilege": "U",
        "access": "store",
        "translation": "sv39",
        "required_caps": ["sv39", "u_mode"],
        "security_focus": "store_stale",
        "stateful": {"kind": "final_pa_observer", "mutation": "clear_w", "fence": "sfence_after_ciall", "expected_final": "target_specific_final_pa"},
    },
    {"profile": "c910-nonpmp-side-effect", "record": "translated-initial-before-ciall", "parser": "alias-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "translated_pa_side_effect", "preload_mode": "initial_same_va"},
    {"profile": "c910-nonpmp-side-effect", "record": "translated-observer-initial-before-ciall", "parser": "alias-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "translated_pa_side_effect", "preload_mode": "initial_observer_va"},
    {"profile": "c910-nonpmp-side-effect", "record": "store-stale-initial", "parser": "alias-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "store_stale", "preload_mode": "initial_same_va"},
    {"profile": "c910-nonpmp-side-effect", "record": "store-stale-observer-initial", "parser": "alias-load", "privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39", "u_mode"], "security_focus": "store_stale", "preload_mode": "initial_observer_va"},
    # --- M-2 catalog expansion spike: M/S-mode bare target operations ---
    # Cover the previously-unreached (m,m) store/fetch and (s,s) store stimulus
    # and privilege-decision bins.  Dispatched by the probe via real_mode with
    # mpp=PRV_M/PRV_S (see security_chain_probe.c probe_nonpmp_privilege_switch_bare).
    {"profile": "c910-nonpmp-privilege", "record": "m-store-bare-fw-data", "parser": "real-mode", "privilege": "M", "access": "store", "translation": "bare", "required_caps": [], "security_focus": "real_mode"},
    {"profile": "c910-nonpmp-privilege", "record": "m-fetch-bare-fw-data", "parser": "real-mode", "privilege": "M", "access": "fetch", "translation": "bare", "required_caps": [], "security_focus": "real_mode"},
    {"profile": "c910-nonpmp-privilege", "record": "s-store-bare-fw-data", "parser": "real-mode", "privilege": "S", "access": "store", "translation": "bare", "required_caps": ["s_mode"], "security_focus": "real_mode"},
    # --- M-2 catalog expansion phase 2: M-mode MPRV + sv39 target operations ---
    # Cover the unreached (m,m) load/store sv39, (m,s)/(m,u) load/store bare+sv39,
    # and (s,s) store sv39 stimulus bins.  Dispatched by the probe via
    # print_load_result/print_store_result with mpp=PRV_M/PRV_S/PRV_U (see
    # probe_sv39_mmu_tlb and probe_mprv_bare).
    {"profile": "c910-nonpmp-sv39", "record": "m-load-sv39-fw-data", "parser": "mprv", "privilege": "M", "access": "load", "translation": "sv39", "required_caps": ["sv39"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": False, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "m-store-sv39-fw-data", "parser": "mprv", "privilege": "M", "access": "store", "translation": "sv39", "required_caps": ["sv39"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": False, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "m-mprv-s-load-sv39-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "S", "access": "load", "translation": "sv39", "required_caps": ["sv39"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": False, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "m-mprv-s-store-sv39-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "S", "access": "store", "translation": "sv39", "required_caps": ["sv39"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": False, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "m-mprv-u-load-sv39-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "U", "access": "load", "translation": "sv39", "required_caps": ["sv39"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "m-mprv-u-store-sv39-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "U", "access": "store", "translation": "sv39", "required_caps": ["sv39"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": True, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-sv39", "record": "s-store-sv39-fw-data", "parser": "mprv", "privilege": "S", "access": "store", "translation": "sv39", "required_caps": ["sv39", "s_mode"], "security_focus": "sv39_permissions", "pte_permissions": {"rwx": "rw-", "user": False, "accessed": True, "dirty": True, "valid": True}},
    {"profile": "c910-nonpmp-privilege", "record": "m-mprv-s-load-bare-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "S", "access": "load", "translation": "bare", "required_caps": [], "security_focus": "mprv_bare"},
    {"profile": "c910-nonpmp-privilege", "record": "m-mprv-s-store-bare-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "S", "access": "store", "translation": "bare", "required_caps": [], "security_focus": "mprv_bare"},
    {"profile": "c910-nonpmp-privilege", "record": "m-mprv-u-load-bare-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "U", "access": "load", "translation": "bare", "required_caps": [], "security_focus": "mprv_bare"},
    {"profile": "c910-nonpmp-privilege", "record": "m-mprv-u-store-bare-fw-data", "parser": "mprv", "privilege": "M", "effective_privilege": "U", "access": "store", "translation": "bare", "required_caps": [], "security_focus": "mprv_bare"},
)


def bootstrap_capability(
    *,
    available: bool = True,
    path: str = "serial",
    isa: str = "rv64gc",
) -> dict[str, Any]:
    return {
        "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
        "dut": C910_NONPMP_DUT,
        "available": bool(available),
        "path": str(path),
        "supported_capabilities": {
            "pmp": False,
            "smepmp": False,
            "smepmp_rlb": False,
            "sv39": True,
            "s_mode": True,
            "u_mode": True,
        },
        "finish_protocol": "uart-fixed-probe",
        "diagnostic_depth": "structured_uart_fixed_probe",
        "ad_update_mode": "hardware",
        "oracle_applicability": "valid" if available else "infra_unadapted",
        "smepmp": {
            "csr_access": False,
            "mml": False,
            "mmwp": False,
            "rlb": False,
            "warl_behavior": "not_applicable_non_pmp_profile",
            "probe_status": "unsupported",
        },
        "notes": [
            "TH1520 C910 non-PMP bootstrap capability profile",
            "PMP and Smepmp scenarios are excluded pre-execution",
        ],
        "isa": str(isa),
        "capability_profile": C910_NONPMP_CAPABILITY_PROFILE,
    }


def bootstrap_cases(*, capability: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    cases = [_build_case(spec, index) for index, spec in enumerate(_CASE_SPECS)]
    if capability is None:
        return cases
    return [case for case in cases if oracle_applicability_for_case(case, capability) == "valid"]


def parse_uart_records(text: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for pattern, kind in (
            (_REAL_MODE_RE, "real-mode"),
            (_MPRV_RE, "mprv"),
            (_FETCH_TEST_RE, "fetch-test"),
            (_UARCH_LOAD_RE, "uarch-load"),
            (_ALIAS_LOAD_RE, "alias-load"),
            (_UARCH_FETCH_RE, "uarch-fetch"),
            (_SUM_FETCH_RE, "sum-fetch"),
        ):
            match = pattern.search(line)
            if match:
                fields = {key: _parse_scalar(value) for key, value in match.groupdict().items() if value is not None}
                record = {"kind": kind, "raw": line} | fields
                record_name = str(fields.get("record") or "")
                if record_name:
                    records[record_name] = record
                break
        else:
            summary = _SIDE_EFFECT_RE.search(line)
            if not summary:
                continue
            record_name = summary.group("record")
            fields = _parse_kv_fields(summary.group("rest"))
            records[record_name] = {"kind": "side-effect", "record": record_name, "raw": line} | fields
    return records


def write_bootstrap_run(
    *,
    uart_log: Path,
    out_dir: Path,
    capability: dict[str, Any] | None = None,
    freeze_universe: bool = True,
) -> dict[str, str]:
    from .coverage import write_coverage
    from .coverage_universe import freeze_coverage_universes, write_coverage_universes
    from .schema import result_to_dict, write_aggregate, write_json
    from .triage import triage_run, write_report

    uart_log = Path(uart_log)
    out_dir = Path(out_dir)
    capability = capability or bootstrap_capability(path=str(uart_log))
    text = uart_log.read_text(encoding="utf-8", errors="replace")
    records = parse_uart_records(text)
    cases = bootstrap_cases(capability=capability)

    out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = out_dir / "cases"
    results_dir = out_dir / "results"
    artifacts_dir = out_dir / "artifacts"
    manifests_dir = out_dir / "manifests"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    copied_uart = artifacts_dir / "uart.log"
    copied_uart.write_text(text, encoding="utf-8")

    write_json(
        out_dir / "run.json",
        {
            "mode": "c910-nonpmp-bootstrap-analysis",
            "target": C910_NONPMP_TARGET,
            "dut": C910_NONPMP_DUT,
            "seed": BOOTSTRAP_SEED,
            "case_count": len(cases),
            "uart_log": str(copied_uart),
        },
    )
    write_json(
        out_dir / "dut_capabilities.json",
        {
            "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
            "duts": {C910_NONPMP_DUT: capability},
        },
    )
    if freeze_universe:
        universes = freeze_coverage_universes(
            target=C910_NONPMP_TARGET,
            capability=capability,
            include_experimental=False,
            seed=BOOTSTRAP_SEED,
        )
        write_coverage_universes(manifests_dir / "coverage_universes", universes)

    for case in cases:
        case_dir = cases_dir / case["name"]
        case_dir.mkdir(parents=True, exist_ok=True)
        write_json(case_dir / "case.json", case)

        record = records.get(str(case.get("uart_record") or case["probe_offset"]))
        result_payload = _result_from_case(case, record, copied_uart)
        result_dir = results_dir / case["name"]
        result_dir.mkdir(parents=True, exist_ok=True)
        write_json(result_dir / "result.json", result_payload)

    write_aggregate(out_dir)
    coverage_path = write_coverage(out_dir)
    triage_run(out_dir)
    report_path = write_report(out_dir)
    return {
        "dut": C910_NONPMP_DUT,
        "run_dir": str(out_dir),
        "coverage": str(coverage_path),
        "report": str(report_path),
        "uart_copy": str(copied_uart),
    }


def collect_and_write_bootstrap_run(
    *,
    out_dir: Path,
    sidecar_name: str,
    serial_script: Path,
    port: str = _DEFAULT_C910_SERIAL_PORT,
    baud: int = 115200,
    timeout_seconds: int = 420,
    login_user: str = _DEFAULT_C910_LOGIN_USER,
    login_password: str = _DEFAULT_C910_LOGIN_PASSWORD,
    linux_reboot_grace_seconds: int = 4,
    no_linux_reboot: bool = False,
) -> dict[str, str]:
    serial_script = Path(serial_script)
    if not serial_script.exists():
        raise FileNotFoundError(f"serial script not found: {serial_script}")
    pwsh = shutil.which("pwsh.exe") or shutil.which("pwsh")
    if not pwsh:
        raise FileNotFoundError("pwsh.exe is required to collect UART logs on Windows")

    out_dir = Path(out_dir)
    artifacts_dir = out_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    uart_log = artifacts_dir / "uart.log"
    args = [
        pwsh,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(serial_script),
        "-Port",
        str(port),
        "-Baud",
        str(int(baud)),
        "-TimeoutSeconds",
        str(int(timeout_seconds)),
        "-Output",
        str(uart_log),
        "-SidecarName",
        str(sidecar_name),
        "-LoginUser",
        str(login_user),
        "-LoginPassword",
        str(login_password),
        "-LinuxRebootGraceSeconds",
        str(int(linux_reboot_grace_seconds)),
    ]
    if no_linux_reboot:
        args.append("-NoLinuxReboot")
    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            "serial collection failed with exit code "
            f"{completed.returncode}: {(completed.stdout or '').strip()} {(completed.stderr or '').strip()}".strip()
        )
    return write_bootstrap_run(uart_log=uart_log, out_dir=out_dir)


def _build_case(spec: dict[str, Any], index: int) -> dict[str, Any]:
    profile = str(spec["profile"])
    record = str(spec["record"])
    stateful = spec.get("stateful")
    privilege = str(spec["privilege"])
    case = {
        "schema_version": 3 if stateful else 2,
        "target": C910_NONPMP_TARGET,
        "name": f"{profile}__{record}",
        "seed": BOOTSTRAP_SEED,
        "index": index,
        "profile": profile,
        "privilege": privilege,
        "access": str(spec["access"]),
        "translation": str(spec["translation"]),
        "mprv": False,
        "mpp": privilege,
        "sum_enabled": bool(spec.get("sum_enabled", False)),
        "mxr": bool(spec.get("mxr", False)),
        "sfence_vma": True,
        "ad_update_mode": str(spec.get("ad_update_mode", "hardware")),
        "mseccfg": {},
        "pmp_entries": [],
        "coverage_tags": [profile, str(spec["access"]), privilege, str(spec["translation"])],
        "ptw_fault_level": spec.get("ptw_fault_level"),
        "preload_mode": spec.get("preload_mode"),
        "pmp_match_mode": None,
        "pmp_match_result": None,
        "pmp_locked": None,
        "pmp_allow": None,
        "effective_privilege": str(spec.get("effective_privilege", privilege)),
        "expected_allowed": True,
        "pte_permissions": dict(spec.get("pte_permissions") or {}),
        "security_focus": spec.get("security_focus"),
        "smepmp_rule": None,
        "required_capabilities_override": sorted({str(item) for item in spec.get("required_caps", [])}),
        "required_capabilities": sorted({str(item) for item in spec.get("required_caps", [])}),
        "oracle_applicability": "valid",
        "uart_record": record,
        "uart_parser": str(spec["parser"]),
        "scenario_spec": {
            "schema_version": 1,
            "target": C910_NONPMP_TARGET,
            "profile": profile,
            "record": record,
            "parser": str(spec["parser"]),
        },
        "contract_trace": {},
        "expected": {
            "allowed": True,
            "trap_cause": None,
            "stage": "stateful_final" if stateful else "normal",
            "reason": f"capture structured observation for {record}",
            "physical_address": None,
        },
    }
    if stateful:
        case["stateful_sequence"] = {
            "kind": str(stateful.get("kind")),
            "mutation": str(stateful.get("mutation")),
            "fence": str(stateful.get("fence")),
            "expected_final": str(stateful.get("expected_final")),
        }
    case["scenario_hash"] = _case_hash(case["scenario_spec"])
    return case


def _case_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _parse_scalar(value: Any) -> Any:
    if value is None:
        return None
    text = str(value)
    if not text:
        return text
    if text.startswith(("0x", "0X")):
        try:
            return int(text, 16)
        except ValueError:
            return text
    if text.isdigit():
        try:
            return int(text, 10)
        except ValueError:
            return text
    return text


def _parse_kv_fields(text: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)", text):
        fields[key] = _parse_scalar(value)
    return fields


def _result_from_case(case: dict[str, Any], record: dict[str, Any] | None, log_path: Path) -> dict[str, Any]:
    from .schema import result_to_dict

    if record is None:
        return result_to_dict(
            case=case,
            dut=C910_NONPMP_DUT,
            status="inconclusive",
            elapsed_seconds=0.0,
            returncode=None,
            log=log_path,
            reason=f"missing UART record for {case['uart_record']}",
            failure_class="inconclusive_observation",
            oracle_applicability="valid",
        )

    if str(record.get("result") or record.get("status") or "") == "skipped":
        return result_to_dict(
            case=case,
            dut=C910_NONPMP_DUT,
            status="setup_unsupported",
            elapsed_seconds=0.0,
            returncode=None,
            log=log_path,
            reason=str(record.get("skip_reason") or "unsupported"),
            failure_class="setup_unsupported",
            oracle_applicability="unsupported",
        )

    observed_event, observed_phase = _observed_event_and_phase(case, record)
    observed_tohost = 0 if observed_event == "completion" else None
    payload = result_to_dict(
        case=case,
        dut=C910_NONPMP_DUT,
        status="pass",
        elapsed_seconds=0.0,
        returncode=0,
        log=log_path,
        reason=f"parsed {record.get('kind')} record {case['uart_record']}",
        observed_tohost=observed_tohost,
        observed_mcause=_as_int(record.get("cause")),
        observed_mtval=_as_int(record.get("tval")),
        observed_event=observed_event,
        observed_phase=observed_phase,
        observed_stage="final" if str(case.get("expected", {}).get("stage")) == "stateful_final" else "probe",
        observed_fault_address=_as_int(record.get("tval")) if observed_event == "trap" else None,
        observation_valid=True,
        stage_verified=True,
        oracle_applicability="valid",
    )
    payload["observed_mepc"] = _as_int(record.get("mepc"))
    payload["uart_record"] = str(case["uart_record"])
    payload["uart_parser"] = str(case["uart_parser"])
    payload["uart_raw"] = str(record.get("raw") or "")
    return payload


def _observed_event_and_phase(case: dict[str, Any], record: dict[str, Any]) -> tuple[str, str]:
    if str(case.get("expected", {}).get("stage")) == "stateful_final":
        return _stateful_event(record), _stateful_phase(record)
    result = str(record.get("result") or "")
    if result == "trap":
        return "trap", "probe"
    return "completion", "completed"


def _stateful_event(record: dict[str, Any]) -> str:
    result = str(record.get("result") or "")
    if result == "trap":
        return "trap"
    return "completion"


def _stateful_phase(record: dict[str, Any]) -> str:
    kind = str(record.get("kind") or "")
    if kind == "sum-fetch":
        verdict = str(record.get("verdict") or "")
        marker_hit = int(record.get("marker_hit") or 0)
        if marker_hit:
            return "final_sentinel_modified"
        if verdict in {"spec_fetch_page_fault", "no_trap", "control_pass"}:
            return "final_sentinel_initial"
        return "final_sentinel_other"

    if kind == "side-effect":
        if "value" in record and "expected_changed" in record:
            return (
                "final_sentinel_modified"
                if record.get("value") == record.get("expected_changed")
                else "final_sentinel_initial"
            )
        if "expected_changed" in record:
            expected = record.get("expected_changed")
            if any(record.get(field) == expected for field in ("direct", "same_va", "observer_va")):
                return "final_sentinel_modified"
        if int(record.get("observer_changed") or 0):
            return "final_sentinel_modified"
        if int(record.get("stale_allows_write_final_pa") or 0):
            return "final_sentinel_modified"
        if int(record.get("sfence_blocks_write_final_pa") or 0):
            return "final_sentinel_initial"
        return "final_sentinel_initial"

    return "final_sentinel_other"


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    try:
        return int(text, 0)
    except ValueError:
        return None
