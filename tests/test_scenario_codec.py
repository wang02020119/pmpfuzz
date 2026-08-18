
import json, math, unittest
from pathlib import Path
import sys

_script_dir = Path(__file__).resolve().parents[1]
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))

_SPEC_V1 = {"schema_version": 1, "entries": [],
            "probe": {"physical_address": 0, "size": 4, "offset_name": "x"}}






class TestHash(unittest.TestCase):
    def test_deterministic(self):
        from pmpfuzz.scenario_codec import scenario_hash
        s = {"profile": "t", "probe": {"physical_address": 0x80000000}}
        self.assertEqual(scenario_hash(s), scenario_hash(dict(s)))
        h = scenario_hash(s); self.assertEqual(len(h), 64)

    def test_same_spec_same_hash(self):
        from pmpfuzz.scenario_codec import scenario_hash
        self.assertEqual(scenario_hash({"profile": "x"}),
                         scenario_hash({"profile": "x"}))

    def test_different_spec_different_hash(self):
        from pmpfuzz.scenario_codec import scenario_hash
        self.assertNotEqual(scenario_hash({"profile": "x", "probe": {"physical_address": 0x80000000}}),
                            scenario_hash({"profile": "x", "probe": {"physical_address": 0x80000004}}))

    def test_top_level_excluded(self):
        from pmpfuzz.scenario_codec import scenario_hash
        base = {"profile": "t", "entries": []}
        derived = {**base, "name": "x", "case_id": "abc", "semantic_bins": ["b1"],
                   "expected_result": "PASS", "scenario_index": 42, "coverage_tags": ["tag"]}
        self.assertEqual(scenario_hash(base), scenario_hash(derived))

    def test_nested_name_not_excluded(self):
        from pmpfuzz.scenario_codec import scenario_hash
        self.assertNotEqual(
            scenario_hash({"profile": "t", "extra": {"name": "a"}}),
            scenario_hash({"profile": "t", "extra": {"name": "b"}}))

    def test_key_order_irrelevant(self):
        from pmpfuzz.scenario_codec import scenario_hash
        from collections import OrderedDict
        s1 = OrderedDict([("profile", "t"), ("probe", {"physical_address": 0})])
        s2 = OrderedDict([("probe", {"physical_address": 0}), ("profile", "t")])
        self.assertEqual(scenario_hash(dict(s1)), scenario_hash(dict(s2)))

    def test_nan_rejected(self):
        from pmpfuzz.scenario_codec import canonical_scenario_bytes
        with self.assertRaises(ValueError):
            canonical_scenario_bytes({"profile": "t", "val": float("nan")})






class TestRoundTrip(unittest.TestCase):
    def test_minimal(self):
        from pmpfuzz.scenario import PmpScenario, AccessProbe, Access
        from pmpfuzz.pmp import Privilege
        from pmpfuzz.scenario_codec import scenario_to_spec, scenario_from_spec
        orig = PmpScenario(name="t", entries=[], privilege=Privilege.M,
                           probe=AccessProbe(access=Access.LOAD, physical_address=0x80000000,
                                             size=4, offset_name="base"),
                           mprv=False, mpp=Privilege.M, profile="pmp-boundary")
        recon = scenario_from_spec(scenario_to_spec(orig))
        self.assertEqual(recon.profile, orig.profile)

    def test_with_entries(self):
        from pmpfuzz.scenario import PmpScenario, AccessProbe, Access
        from pmpfuzz.pmp import PmpEntry, AddressMode, Privilege
        from pmpfuzz.scenario_codec import scenario_to_spec, scenario_from_spec
        orig = PmpScenario(name="t",
            entries=[
                PmpEntry(index=0, address_mode=AddressMode.NAPOT,
                         pmpaddr=0x80000000 >> 2,
                         read=True, write=True, execute=False, locked=False),
                PmpEntry(index=1, address_mode=AddressMode.TOR,
                         pmpaddr=0xC0000000 >> 2,
                         read=False, write=False, execute=True, locked=False),
            ],
            privilege=Privilege.S,
            probe=AccessProbe(access=Access.STORE, physical_address=0x90000000,
                              size=8, offset_name="high"),
            mprv=False, mpp=Privilege.M, profile="pmp-boundary")
        recon = scenario_from_spec(scenario_to_spec(orig))
        self.assertEqual(len(recon.entries), 2)

    def test_sv39(self):
        from pmpfuzz.scenario import PmpScenario, AccessProbe, Access
        from pmpfuzz.pmp import Privilege
        from pmpfuzz.mmu import Sv39Mapping, PageTableEntry, TranslationMode
        from pmpfuzz.scenario_codec import scenario_to_spec, scenario_from_spec
        sv39 = Sv39Mapping(virtual_page=0x10000000, physical_page=0x20000000,
                           root_table=0x80000000,
                           walk_addresses=(0x80000000, 0x80001000),
                           pte=PageTableEntry(read=True, write=False, execute=True,
                                              user=True, accessed=True, dirty=False))
        orig = PmpScenario(name="sv", entries=[], privilege=Privilege.U,
                           probe=AccessProbe(access=Access.LOAD, physical_address=0x10000000,
                                             size=4, offset_name="p", virtual_address=0x10000000),
                           mprv=False, mpp=Privilege.M,
                           translation=TranslationMode.SV39, sv39=sv39,
                           sum_enabled=True, mxr=True, sfence_vma=True,
                           profile="sv39-final-pmp")
        recon = scenario_from_spec(scenario_to_spec(orig))
        self.assertIsNotNone(recon.sv39)
        self.assertEqual(recon.sv39.virtual_page, 0x10000000)

    def test_sv39_defaults(self):
        from pmpfuzz.scenario import PmpScenario, AccessProbe, Access
        from pmpfuzz.pmp import Privilege
        from pmpfuzz.mmu import Sv39Mapping, PageTableEntry, TranslationMode
        from pmpfuzz.scenario_codec import scenario_to_spec, scenario_from_spec
        sv39 = Sv39Mapping(virtual_page=0, physical_page=0, root_table=0,
                           walk_addresses=(),
                           pte=PageTableEntry(read=False, write=False, execute=False,
                                              user=False, accessed=False, dirty=False))
        orig = PmpScenario(name="sv39-d", entries=[], privilege=Privilege.M,
                           probe=AccessProbe(access=Access.LOAD, physical_address=0, size=4,
                                             offset_name="z"),
                           mprv=False, mpp=Privilege.M,
                           translation=TranslationMode.SV39, sv39=sv39, profile="sv39-final-pmp")
        recon = scenario_from_spec(scenario_to_spec(orig))
        self.assertTrue(recon.sv39.pte.valid)
        self.assertFalse(recon.sv39.pte.global_mapping)

    def test_hash_ignores_name(self):
        from pmpfuzz.scenario import PmpScenario, AccessProbe, Access
        from pmpfuzz.pmp import Privilege
        from pmpfuzz.scenario_codec import scenario_to_spec, scenario_hash
        mk = lambda n: PmpScenario(name=n, entries=[], privilege=Privilege.M,
                                   probe=AccessProbe(access=Access.LOAD, physical_address=0x80000000,
                                                     size=4, offset_name="x"),
                                   mprv=False, mpp=Privilege.M)
        self.assertEqual(scenario_hash(scenario_to_spec(mk("a"))),
                         scenario_hash(scenario_to_spec(mk("b"))))






class TestSchema(unittest.TestCase):
    def _reject(self, sv):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises((ValueError, TypeError)):
            scenario_from_spec({"schema_version": sv, "entries": [],
                                "probe": {"physical_address": 0, "size": 4, "offset_name": "x"}})

    def test_accept_1(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        scenario_from_spec({"schema_version": 1, "entries": [],
                            "probe": {"physical_address": 0, "size": 4, "offset_name": "x"}})

    def test_reject_str(self): self._reject("1")
    def test_reject_float(self): self._reject(1.0)
    def test_reject_true(self): self._reject(True)
    def test_reject_false(self): self._reject(False)
    def test_reject_0(self): self._reject(0)
    def test_reject_99(self): self._reject(99)
    def test_reject_non_dict(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        for bad in [None, [], "x"]:
            with self.assertRaises((ValueError, TypeError)):
                scenario_from_spec(bad)






class TestBooleans(unittest.TestCase):
    def test_mprv_null_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "mprv": None})

    def test_sfence_vma_null_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "sfence_vma": None})

    def test_sv39_pte_valid_null_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "sv39": {"pte": {"read": False, "write": False, "execute": False,
                                  "user": False, "accessed": False, "dirty": False,
                                  "valid": None}}})

    def test_strings_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        for bad in ["true", "false"]:
            with self.assertRaises(ValueError):
                scenario_from_spec({**_SPEC_V1, "mprv": bad})

    def test_ints_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        for bad in [0, 1]:
            with self.assertRaises(ValueError):
                scenario_from_spec({**_SPEC_V1, "mprv": bad})






class TestIntegers(unittest.TestCase):
    def test_probe_size_str_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "probe": {"physical_address": 0, "size": "4", "offset_name": "z"}})

    def test_probe_size_float_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "probe": {"physical_address": 0, "size": 4.0, "offset_name": "z"}})

    def test_probe_size_true_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "probe": {"physical_address": 0, "size": True, "offset_name": "z"}})

    def test_probe_size_null_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "probe": {"physical_address": 0, "size": None, "offset_name": "z"}})

    def test_probe_size_zero_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "probe": {"physical_address": 0, "size": 0, "offset_name": "z"}})

    def test_probe_size_negative_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "probe": {"physical_address": 0, "size": -1, "offset_name": "z"}})

    def test_entry_index_true_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "entries": [{"index": True, "address_mode": 0, "pmpaddr": 0,
                             "read": False, "write": False, "execute": False, "locked": False}]})

    def test_entry_pmpaddr_float_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "entries": [{"index": 0, "address_mode": 0, "pmpaddr": 1.9,
                             "read": False, "write": False, "execute": False, "locked": False}]})

    def test_virtual_address_null_ok(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        recon = scenario_from_spec({**_SPEC_V1,
            "probe": {"physical_address": 0, "size": 4, "offset_name": "z", "virtual_address": None}})
        self.assertIsNone(recon.probe.virtual_address)

    def test_virtual_address_str_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "probe": {"physical_address": 0, "size": 4, "offset_name": "z",
                          "virtual_address": "123"}})






class TestStrings(unittest.TestCase):
    def test_name_dict_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "name": {}})

    def test_profile_list_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "profile": []})






class TestTuples(unittest.TestCase):
    def test_coverage_tags_str_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "coverage_tags": "abc"})

    def test_coverage_tags_mixed_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "coverage_tags": ["a", 1]})

    def test_coverage_tags_empty_ok(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        recon = scenario_from_spec({**_SPEC_V1, "coverage_tags": []})
        self.assertEqual(recon.coverage_tags, ())

    def test_walk_addresses_str_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "sv39": {"pte": {"read": False, "write": False, "execute": False,
                                  "user": False, "accessed": False, "dirty": False},
                          "walk_addresses": "abc"}})

    def test_walk_addresses_mixed_rejected(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1,
                "sv39": {"pte": {"read": False, "write": False, "execute": False,
                                  "user": False, "accessed": False, "dirty": False},
                          "walk_addresses": [1, "2"]}})






class TestEnum(unittest.TestCase):
    def test_invalid_translation(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "translation": "invalid-mode"})

    def test_invalid_privilege(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "privilege": "X"})

    def test_missing_uses_default(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        from pmpfuzz.pmp import Privilege, AddressMode, Access
        from pmpfuzz.mmu import TranslationMode
        from pmpfuzz.scenario import AdUpdateMode
        spec = {**_SPEC_V1,
            "entries": [{"index": 0, "address_mode": None, "pmpaddr": 0,
                         "read": False, "write": False, "execute": False, "locked": False}],
            "probe": {"access": None, "physical_address": 0, "size": 4, "offset_name": ""},
            "privilege": None, "mpp": None,
            "translation": None, "ad_update_mode": None, "mseccfg": {}}
        recon = scenario_from_spec(spec)
        self.assertEqual(recon.privilege, Privilege.M)
        self.assertEqual(recon.translation, TranslationMode.BARE)
        self.assertEqual(recon.ad_update_mode, AdUpdateMode.SVADE)
        self.assertEqual(recon.probe.access, Access.LOAD)
        self.assertEqual(recon.entries[0].address_mode, AddressMode.OFF)






class TestSerialization(unittest.TestCase):
    def test_non_pmp_scenario_rejected(self):
        from pmpfuzz.scenario_codec import scenario_to_spec
        for bad in [None, {}, object()]:
            with self.assertRaises(TypeError):
                scenario_to_spec(bad)






class TestStructural(unittest.TestCase):
    def test_entries_not_list(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "entries": "bad"})

    def test_entry_not_dict(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "entries": ["bad"]})

    def test_probe_not_dict(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "probe": "bad"})

    def test_mseccfg_not_dict(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "mseccfg": "bad"})

    def test_sv39_not_dict_or_null(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "sv39": "bad"})

    def test_pte_permissions_not_dict(self):
        from pmpfuzz.scenario_codec import scenario_from_spec
        with self.assertRaises(ValueError):
            scenario_from_spec({**_SPEC_V1, "pte_permissions": "bad"})


if __name__ == "__main__":
    raise SystemExit(
        0 if unittest.main(verbosity=2, exit=False).result.wasSuccessful() else 1)
