from __future__ import annotations

import re
from typing import Any

from .coverage_universe import make_coverage_universe


HPM_SCHEMA_VERSION = 1
HPM_GENERATION_RULE_VERSION = "hpm-coverage-universe-v1"
HPM_COUNTER_WIDTH = 40
HPM_RATE_BUCKETS: tuple[tuple[float, str], ...] = (
    (0.0, "0"),
    (0.1, "0-0.1"),
    (1.0, "0.1-1"),
    (10.0, "1-10"),
    (100.0, "10-100"),
)
HPM_RATE_BUCKET_LABELS = ["0", "0-0.1", "0.1-1", "1-10", "10-100", "gt100"]
_HPM_LINE_RE = re.compile(r"PMFUZZ_HPM\b\s+(.*)")
_KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)")


def _event_selector(event_set: int, event_index: int) -> int:
    return (1 << (8 + int(event_index))) | int(event_set)


ROCKET_CLEAN_HPM_MANIFEST: dict[str, Any] = {
    "schema_version": HPM_SCHEMA_VERSION,
    "dut": "rocket-clean",
    "counter_width": HPM_COUNTER_WIDTH,
    "events": [
        {
            "name": "exception",
            "counter": "c3",
            "event_selector": _event_selector(0, 0),
            "counter_width": HPM_COUNTER_WIDTH,
            "kind": "rate",
            "description": "Rocket core exception retire event",
        },
        {
            "name": "itlb_miss",
            "counter": "c4",
            "event_selector": _event_selector(2, 3),
            "counter_width": HPM_COUNTER_WIDTH,
            "kind": "rate",
            "description": "Rocket ITLB miss event",
        },
        {
            "name": "dtlb_miss",
            "counter": "c5",
            "event_selector": _event_selector(2, 4),
            "counter_width": HPM_COUNTER_WIDTH,
            "kind": "rate",
            "description": "Rocket DTLB miss event",
        },
        {
            "name": "l2_tlb_miss",
            "counter": "c6",
            "event_selector": _event_selector(2, 5),
            "counter_width": HPM_COUNTER_WIDTH,
            "kind": "rate",
            "description": "Rocket L2 TLB miss event",
        },
    ],
    "rate_buckets": list(HPM_RATE_BUCKET_LABELS),
    "pair_bins": [],
}


def manifest_for_dut(dut: str) -> dict[str, Any]:
    normalized = str(dut or "").strip().lower()
    if normalized != "rocket-clean":
        raise ValueError(f"unsupported HPM manifest DUT: {dut}")
    return {
        "schema_version": ROCKET_CLEAN_HPM_MANIFEST["schema_version"],
        "dut": ROCKET_CLEAN_HPM_MANIFEST["dut"],
        "counter_width": ROCKET_CLEAN_HPM_MANIFEST["counter_width"],
        "events": [dict(event) for event in ROCKET_CLEAN_HPM_MANIFEST["events"]],
        "rate_buckets": list(ROCKET_CLEAN_HPM_MANIFEST["rate_buckets"]),
        "pair_bins": list(ROCKET_CLEAN_HPM_MANIFEST["pair_bins"]),
    }


def build_hpm_coverage_universe(
    *,
    dut: str,
    generator_seed: int,
    manifest_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = _validate_manifest(manifest_override or manifest_for_dut(dut))
    bin_ids: list[str] = []
    for event in manifest["events"]:
        kind = str(event.get("kind") or "")
        name = str(event.get("name") or "")
        if kind == "rate":
            for label in HPM_RATE_BUCKET_LABELS:
                bin_ids.append(f"event={name}|bucket={label}")
        else:
            raise ValueError(f"unsupported HPM event kind for {name}: {kind}")
    capability_fingerprint = f"hpm:{manifest['dut']}:counter-width={manifest['counter_width']}"
    return make_coverage_universe(
        coverage_mode="hpm",
        bin_ids=bin_ids,
        capability_fingerprint=capability_fingerprint,
        target="pmp-relevant-hpm",
        include_experimental=False,
        generator_seed=generator_seed,
        generation_rule_version=HPM_GENERATION_RULE_VERSION,
        extra_fields={
            "dut": manifest["dut"],
            "events": [dict(event) for event in manifest["events"]],
            "rate_buckets": list(manifest["rate_buckets"]),
            "pair_bins": list(manifest["pair_bins"]),
        },
    )


def counter_delta(before: int, after: int, *, width: int) -> int:
    width = int(width)
    if width <= 0:
        raise ValueError(f"counter width must be positive, got {width}")
    modulo = 1 << width
    return (int(after) - int(before)) % modulo


def rate_bucket_label(rate_per_kilo_instruction: float) -> str:
    rate = float(rate_per_kilo_instruction)
    if rate < 0.0:
        raise ValueError(f"rate must be non-negative, got {rate}")
    if rate == 0.0:
        return "0"
    for upper, label in HPM_RATE_BUCKETS[1:]:
        if rate <= upper:
            return label
    return "gt100"


def parse_hpm_uart_snapshots(text: str) -> dict[str, Any]:
    snapshots: dict[str, Any] = {
        "before": None,
        "after": None,
        "counter_width": None,
    }
    for line in str(text or "").splitlines():
        match = _HPM_LINE_RE.search(line)
        if not match:
            continue
        fields = dict(_KV_RE.findall(match.group(1)))
        phase = str(fields.get("phase") or "")
        if phase not in {"before", "after"}:
            continue
        parsed: dict[str, int] = {}
        for key, value in fields.items():
            if key == "phase":
                continue
            if key == "width":
                snapshots["counter_width"] = int(value, 0)
                continue
            parsed[key] = int(value, 0)
        snapshots[phase] = parsed
    return snapshots


def summarize_hpm_coverage(
    *,
    manifest: dict[str, Any],
    before: dict[str, int] | None,
    after: dict[str, int] | None,
) -> dict[str, Any]:
    normalized_manifest = _validate_manifest(manifest)
    if before is None or after is None:
        return {
            "eligible": False,
            "qualification_reason": "missing-hpm-snapshot",
            "event_metrics": {},
            "observed_bins": [],
            "counter_width": normalized_manifest["counter_width"],
        }
    if "minstret" not in before or "minstret" not in after:
        return {
            "eligible": False,
            "qualification_reason": "missing-minstret",
            "event_metrics": {},
            "observed_bins": [],
            "counter_width": normalized_manifest["counter_width"],
        }
    if "mcycle" not in before or "mcycle" not in after:
        return {
            "eligible": False,
            "qualification_reason": "missing-mcycle",
            "event_metrics": {},
            "observed_bins": [],
            "counter_width": normalized_manifest["counter_width"],
        }

    event_metrics: dict[str, dict[str, Any]] = {}
    observed_bins: list[str] = []
    width = int(normalized_manifest["counter_width"])
    delta_minstret = counter_delta(before["minstret"], after["minstret"], width=width)
    delta_mcycle = counter_delta(before["mcycle"], after["mcycle"], width=width)

    for event in normalized_manifest["events"]:
        name = str(event["name"])
        counter_name = str(event["counter"])
        if counter_name not in before or counter_name not in after:
            raise ValueError(f"HPM event {name} requires counter {counter_name}")
        kind = str(event["kind"])
        if kind != "rate":
            raise ValueError(f"unsupported HPM event kind for {name}: {kind}")
        delta = counter_delta(before[counter_name], after[counter_name], width=int(event["counter_width"]))
        rate = (float(delta) * 1000.0) / max(1, delta_minstret)
        bucket = rate_bucket_label(rate)
        observed_bin = f"event={name}|bucket={bucket}"
        observed_bins.append(observed_bin)
        event_metrics[name] = {
            "counter": counter_name,
            "before": int(before[counter_name]),
            "after": int(after[counter_name]),
            "delta": delta,
            "rate_per_kilo_instruction": rate,
            "bucket": bucket,
        }

    return {
        "eligible": True,
        "qualification_reason": "eligible",
        "counter_width": width,
        "before": dict(before),
        "after": dict(after),
        "delta_minstret": delta_minstret,
        "delta_mcycle": delta_mcycle,
        "event_metrics": event_metrics,
        "observed_bins": sorted(set(observed_bins)),
    }


def _validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise TypeError(f"HPM manifest must be a dict, got {type(manifest).__name__}")
    if int(manifest.get("schema_version") or 0) != HPM_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported HPM manifest schema_version {manifest.get('schema_version')!r}; "
            f"expected {HPM_SCHEMA_VERSION}"
        )
    dut = str(manifest.get("dut") or "")
    if not dut:
        raise ValueError("HPM manifest requires dut")
    counter_width = int(manifest.get("counter_width") or 0)
    if counter_width <= 0:
        raise ValueError("HPM manifest requires positive counter_width")
    events = manifest.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("HPM manifest requires non-empty events")
    normalized_events: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_counters: set[str] = set()
    allowed_counters = {"c3", "c4", "c5", "c6"}
    for raw_event in events:
        if not isinstance(raw_event, dict):
            raise ValueError("HPM manifest events must be objects")
        name = str(raw_event.get("name") or "")
        counter = str(raw_event.get("counter") or "")
        kind = str(raw_event.get("kind") or "")
        if not name:
            raise ValueError("HPM event missing name")
        if not counter:
            raise ValueError(f"HPM event {name} missing counter")
        if counter not in allowed_counters:
            raise ValueError(f"HPM event {name} uses unsupported counter {counter}")
        if kind != "rate":
            raise ValueError(f"HPM event {name} uses unsupported kind {kind}")
        if name in seen_names:
            raise ValueError(f"duplicate HPM event name {name}")
        if counter in seen_counters:
            raise ValueError(f"duplicate HPM counter assignment {counter}")
        seen_names.add(name)
        seen_counters.add(counter)
        normalized_events.append(
            {
                "name": name,
                "counter": counter,
                "event_selector": int(raw_event.get("event_selector") or 0),
                "counter_width": int(raw_event.get("counter_width") or counter_width),
                "kind": kind,
                "description": str(raw_event.get("description") or ""),
            }
        )
    return {
        "schema_version": HPM_SCHEMA_VERSION,
        "dut": dut,
        "counter_width": counter_width,
        "events": normalized_events,
        "rate_buckets": list(manifest.get("rate_buckets") or HPM_RATE_BUCKET_LABELS),
        "pair_bins": list(manifest.get("pair_bins") or []),
    }
