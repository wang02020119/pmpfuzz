from __future__ import annotations

import copy
import re
from typing import Any


BOOT_CHAIN_POLICY_KIND = "u74-sdio3-boot-chain-policy-v1"
BOOT_CHAIN_DEVICE = "/dev/mmcblk1"
BOOT_CHAIN_P1_DEVICE = "/dev/mmcblk1p1"
BOOT_CHAIN_P2_DEVICE = "/dev/mmcblk1p2"
BOOT_CHAIN_P1_TYPE_GUID = "2e54b353-1271-4842-806f-e436d6af6985"
BOOT_CHAIN_P2_TYPE_GUID = "5b193300-fc78-40cd-8002-e86c45580b47"
BOOT_CHAIN_P1_SIZE_BYTES = 2 * 1024 * 1024
BOOT_CHAIN_P2_SIZE_BYTES = 4 * 1024 * 1024


def _hex64(value: object) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _norm_guid(value: object) -> str:
    return str(value or "").strip().lower()


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def parse_boot_chain_evidence_text(text: str) -> dict[str, Any]:
    values: dict[str, str] = {}
    partitions: dict[str, dict[str, Any]] = {}
    p2_prefix_bytes = None
    p2_prefix_sha256 = ""

    part_re = re.compile(
        r"^/dev/mmcblk1p(?P<part>[12])\s*:\s*start=\s*(?P<start>\d+),\s*"
        r"size=\s*(?P<size>\d+),\s*type=(?P<type>[0-9a-fA-F-]+),\s*"
        r"uuid=(?P<uuid>[0-9a-fA-F-]+)"
    )
    prefix_re = re.compile(r"^mmcblk1p2_prefix_(?P<bytes>\d+)_sha256$")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("==="):
            continue
        part_match = part_re.match(line)
        if part_match:
            part = f"p{part_match.group('part')}"
            partitions[part] = {
                "device": f"/dev/mmcblk1{part}",
                "start_sector": int(part_match.group("start")),
                "size_sectors": int(part_match.group("size")),
                "type_guid": _norm_guid(part_match.group("type")),
                "partuuid": _norm_guid(part_match.group("uuid")),
            }
            continue
        if line.startswith("/dev/mmcblk1:"):
            match = re.search(r'PTUUID="(?P<ptuuid>[0-9a-fA-F-]+)"', line)
            if match:
                values["disk_ptuuid"] = _norm_guid(match.group("ptuuid"))
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower().replace("/dev/", "")
        value = value.strip()
        values[key] = value
        if key == "label-id":
            values["disk_ptuuid"] = _norm_guid(value)
        prefix_match = prefix_re.match(key)
        if prefix_match:
            p2_prefix_bytes = int(prefix_match.group("bytes"))
            p2_prefix_sha256 = value.lower()

    p1 = partitions.setdefault("p1", {"device": BOOT_CHAIN_P1_DEVICE})
    p2 = partitions.setdefault("p2", {"device": BOOT_CHAIN_P2_DEVICE})
    p1["size_bytes"] = _int_or_none(values.get("mmcblk1p1_size_bytes"))
    p2["size_bytes"] = _int_or_none(values.get("mmcblk1p2_size_bytes"))

    return {
        "schema_version": 1,
        "evidence_kind": "u74-sdio3-boot-chain-evidence-v1",
        "card": {
            "cid": str(values.get("cid") or ""),
            "csd": str(values.get("csd") or ""),
            "name": str(values.get("name") or ""),
            "oemid": str(values.get("oemid") or ""),
            "manfid": str(values.get("manfid") or ""),
            "date": str(values.get("date") or ""),
            "serial": str(values.get("serial") or ""),
            "hwrev": str(values.get("hwrev") or ""),
            "fwrev": str(values.get("fwrev") or ""),
        },
        "disk": {
            "device": BOOT_CHAIN_DEVICE,
            "ptuuid": _norm_guid(values.get("disk_ptuuid")),
            "size_bytes": _int_or_none(values.get("mmcblk1_size_bytes")),
        },
        "partitions": partitions,
        "hashes": {
            "p1_full_sha256": str(values.get("mmcblk1p1_full_sha256") or "").lower(),
            "p2_prefix_bytes": p2_prefix_bytes,
            "p2_prefix_sha256": p2_prefix_sha256,
            "p2_full_sha256": str(values.get("mmcblk1p2_full_sha256") or "").lower(),
            "gpt_first_34_sectors_sha256": str(
                values.get("mmcblk1_first_34_sectors_sha256") or ""
            ).lower(),
        },
    }


def build_boot_chain_policy(
    evidence: dict[str, Any],
    *,
    expected_fit_sha256: str,
    expected_fit_bytes: int,
    raw_evidence_sha256: str = "",
    raw_evidence_bytes: int = 0,
    spl_image_sha256: str = "",
    spl_image_bytes: int = 0,
) -> dict[str, Any]:
    p1 = dict((evidence.get("partitions") or {}).get("p1") or {})
    p2 = dict((evidence.get("partitions") or {}).get("p2") or {})
    hashes = dict(evidence.get("hashes") or {})
    return {
        "schema_version": 1,
        "policy_kind": BOOT_CHAIN_POLICY_KIND,
        "boot_mode": "sdio3",
        "device": BOOT_CHAIN_DEVICE,
        "card": dict(evidence.get("card") or {}),
        "disk": dict(evidence.get("disk") or {}),
        "p1_spl": {
            "device": BOOT_CHAIN_P1_DEVICE,
            "type_guid": _norm_guid(p1.get("type_guid")),
            "partuuid": _norm_guid(p1.get("partuuid")),
            "size_bytes": _int_or_none(p1.get("size_bytes")),
            "sha256": str(hashes.get("p1_full_sha256") or "").lower(),
            "image_sha256": str(spl_image_sha256 or "").lower(),
            "image_bytes": int(spl_image_bytes or 0),
        },
        "p2_fit": {
            "device": BOOT_CHAIN_P2_DEVICE,
            "type_guid": _norm_guid(p2.get("type_guid")),
            "partuuid": _norm_guid(p2.get("partuuid")),
            "size_bytes": _int_or_none(p2.get("size_bytes")),
            "expected_prefix_bytes": int(expected_fit_bytes),
            "expected_prefix_sha256": str(expected_fit_sha256 or "").lower(),
            "observed_prefix_bytes_at_collection": _int_or_none(hashes.get("p2_prefix_bytes")),
            "observed_prefix_sha256_at_collection": str(hashes.get("p2_prefix_sha256") or "").lower(),
            "observed_full_sha256_at_collection": str(hashes.get("p2_full_sha256") or "").lower(),
        },
        "gpt_first_34_sectors_sha256": str(hashes.get("gpt_first_34_sectors_sha256") or "").lower(),
        "raw_evidence_sha256": str(raw_evidence_sha256 or "").lower(),
        "raw_evidence_bytes": int(raw_evidence_bytes or 0),
    }


def bind_boot_chain_policy_to_fit(
    policy: dict[str, Any],
    *,
    expected_fit_sha256: str,
    expected_fit_bytes: int,
) -> dict[str, Any]:
    bound = copy.deepcopy(policy)
    p2 = dict(bound.get("p2_fit") or {})
    p2["expected_prefix_sha256"] = str(expected_fit_sha256 or "").lower()
    p2["expected_prefix_bytes"] = int(expected_fit_bytes)
    bound["p2_fit"] = p2
    return bound


def validate_boot_chain_policy(
    policy: dict[str, Any] | None,
    *,
    actual_fit_sha256: str,
    actual_fit_bytes: int,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy, dict) or not policy:
        return ["boot_chain_policy_missing"]
    if int(policy.get("schema_version") or 0) != 1:
        errors.append("boot_chain_policy_schema")
    if policy.get("policy_kind") != BOOT_CHAIN_POLICY_KIND:
        errors.append("boot_chain_policy_kind")
    card = dict(policy.get("card") or {})
    for key in ("cid", "csd", "name", "manfid", "oemid", "serial"):
        if not str(card.get(key) or ""):
            errors.append(f"boot_chain_card_{key}_missing")
    disk = dict(policy.get("disk") or {})
    if disk.get("device") != BOOT_CHAIN_DEVICE:
        errors.append("boot_chain_disk_device")
    if not _norm_guid(disk.get("ptuuid")):
        errors.append("boot_chain_disk_ptuuid_missing")
    p1 = dict(policy.get("p1_spl") or {})
    p2 = dict(policy.get("p2_fit") or {})
    if p1.get("device") != BOOT_CHAIN_P1_DEVICE:
        errors.append("boot_chain_p1_device")
    if _norm_guid(p1.get("type_guid")) != BOOT_CHAIN_P1_TYPE_GUID:
        errors.append("boot_chain_p1_type_guid")
    if not _norm_guid(p1.get("partuuid")):
        errors.append("boot_chain_p1_partuuid_missing")
    if _int_or_none(p1.get("size_bytes")) != BOOT_CHAIN_P1_SIZE_BYTES:
        errors.append("boot_chain_p1_size")
    if not _hex64(p1.get("sha256")):
        errors.append("boot_chain_p1_sha256")
    image_sha = str(p1.get("image_sha256") or "")
    image_bytes = _int_or_none(p1.get("image_bytes")) or 0
    if image_sha or image_bytes:
        if image_sha != str(p1.get("sha256") or ""):
            errors.append("boot_chain_p1_image_sha256_mismatch")
        if image_bytes != BOOT_CHAIN_P1_SIZE_BYTES:
            errors.append("boot_chain_p1_image_size")
    if p2.get("device") != BOOT_CHAIN_P2_DEVICE:
        errors.append("boot_chain_p2_device")
    if _norm_guid(p2.get("type_guid")) != BOOT_CHAIN_P2_TYPE_GUID:
        errors.append("boot_chain_p2_type_guid")
    if not _norm_guid(p2.get("partuuid")):
        errors.append("boot_chain_p2_partuuid_missing")
    if _int_or_none(p2.get("size_bytes")) != BOOT_CHAIN_P2_SIZE_BYTES:
        errors.append("boot_chain_p2_size")
    if _int_or_none(p2.get("expected_prefix_bytes")) != int(actual_fit_bytes):
        errors.append("boot_chain_expected_fit_bytes_mismatch")
    if str(p2.get("expected_prefix_sha256") or "") != str(actual_fit_sha256 or "").lower():
        errors.append("boot_chain_expected_fit_sha256_mismatch")
    if not _hex64(policy.get("gpt_first_34_sectors_sha256")):
        errors.append("boot_chain_gpt_first_34_sectors_sha256")
    return errors


def validate_runtime_boot_chain_evidence(
    policy: dict[str, Any],
    evidence: dict[str, Any],
) -> list[str]:
    errors = validate_boot_chain_policy(
        policy,
        actual_fit_sha256=str((policy.get("p2_fit") or {}).get("expected_prefix_sha256") or ""),
        actual_fit_bytes=int((policy.get("p2_fit") or {}).get("expected_prefix_bytes") or -1),
    )
    if errors:
        return errors
    expected_card = dict(policy.get("card") or {})
    actual_card = dict(evidence.get("card") or {})
    for key in ("cid", "csd", "name", "manfid", "oemid", "serial"):
        if str(actual_card.get(key) or "") != str(expected_card.get(key) or ""):
            errors.append(f"boot_chain_card_{key}_mismatch")
    expected_disk = dict(policy.get("disk") or {})
    actual_disk = dict(evidence.get("disk") or {})
    if _norm_guid(actual_disk.get("ptuuid")) != _norm_guid(expected_disk.get("ptuuid")):
        errors.append("boot_chain_disk_ptuuid_mismatch")
    actual_parts = dict(evidence.get("partitions") or {})
    actual_p1 = dict(actual_parts.get("p1") or {})
    actual_p2 = dict(actual_parts.get("p2") or {})
    policy_p1 = dict(policy.get("p1_spl") or {})
    policy_p2 = dict(policy.get("p2_fit") or {})
    if _norm_guid(actual_p1.get("type_guid")) != _norm_guid(policy_p1.get("type_guid")):
        errors.append("boot_chain_p1_type_guid_mismatch")
    if _norm_guid(actual_p1.get("partuuid")) != _norm_guid(policy_p1.get("partuuid")):
        errors.append("boot_chain_p1_partuuid_mismatch")
    if _int_or_none(actual_p1.get("size_bytes")) != _int_or_none(policy_p1.get("size_bytes")):
        errors.append("boot_chain_p1_size_mismatch")
    if _norm_guid(actual_p2.get("type_guid")) != _norm_guid(policy_p2.get("type_guid")):
        errors.append("boot_chain_p2_type_guid_mismatch")
    if _norm_guid(actual_p2.get("partuuid")) != _norm_guid(policy_p2.get("partuuid")):
        errors.append("boot_chain_p2_partuuid_mismatch")
    if _int_or_none(actual_p2.get("size_bytes")) != _int_or_none(policy_p2.get("size_bytes")):
        errors.append("boot_chain_p2_size_mismatch")
    hashes = dict(evidence.get("hashes") or {})
    if str(hashes.get("p1_full_sha256") or "") != str(policy_p1.get("sha256") or ""):
        errors.append("boot_chain_p1_sha256_mismatch")
    if _int_or_none(hashes.get("p2_prefix_bytes")) != _int_or_none(policy_p2.get("expected_prefix_bytes")):
        errors.append("boot_chain_p2_prefix_bytes_mismatch")
    if str(hashes.get("p2_prefix_sha256") or "") != str(policy_p2.get("expected_prefix_sha256") or ""):
        errors.append("boot_chain_p2_prefix_sha256_mismatch")
    if str(hashes.get("gpt_first_34_sectors_sha256") or "") != str(policy.get("gpt_first_34_sectors_sha256") or ""):
        errors.append("boot_chain_gpt_first_34_sectors_sha256_mismatch")
    return errors
