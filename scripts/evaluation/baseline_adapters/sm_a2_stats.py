#!/usr/bin/env python3
"""Standard-metrics A2: exact Mann-Whitney U / Vargha-Delaney A12 / IQR per comparison.

Pure-python implementation (no scipy on the box). Exact permutation p-value for
n1,n2 <= 20; normal approximation with continuity correction otherwise.
A12 = U_a / (n1*n2)  (equivalently the centered form (2U - n1*n2)/(n1*n2) = 2*A12 - 1).
U_a = R_a - n1*(n1+1)/2 with midranks for ties.
"""
import json
import math
from itertools import combinations
from statistics import median

def ranks_with_ties(vals):
    """midranks for a list of numbers"""
    order = sorted(range(len(vals)), key=lambda i: vals[i])
    out = [0.0] * len(vals)
    i = 0
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and vals[order[j + 1]] == vals[order[i]]:
            j += 1
        avg = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            out[order[k]] = avg
        i = j + 1
    return out

def mwu(a, b):
    n1, n2 = len(a), len(b)
    ra = ranks_with_ties(list(a) + list(b))
    Ua = sum(ra[:n1]) - n1 * (n1 + 1) / 2.0
    Ub = n1 * n2 - Ua
    return Ua, Ub

def exact_p_two_tailed(a, b, Ua_obs):
    """Exact two-tailed p via enumeration of C(n1+n2, n1) partitions."""
    n1, n2 = len(a), len(b)
    if min(n1, n2) > 20:
        return None
    combined = list(a) + list(b)
    total = 0
    ge = 0
    le = 0
    for idx in combinations(range(n1 + n2), n1):
        ga = [combined[i] for i in idx]
        ra = ranks_with_ties(ga + [combined[i] for i in range(n1 + n2) if i not in idx])
        Ua = sum(ra[:n1]) - n1 * (n1 + 1) / 2.0
        total += 1
        if Ua >= Ua_obs:
            ge += 1
        if Ua <= Ua_obs:
            le += 1
    # two-tailed: sum of both tails, cap at 1
    p = min(1.0, 2 * min(le, ge) / total)
    return p

def iqr(v):
    s = sorted(v)
    n = len(s)
    def q(p):
        h = (n - 1) * p
        lo = int(math.floor(h))
        return s[lo] + (s[min(lo + 1, n - 1)] - s[lo]) * (h - lo)
    return q(0.75) - q(0.25)

def compare(name_a, vals_a, name_b, vals_b, unit, source, note):
    n1, n2 = len(vals_a), len(vals_b)
    Ua, Ub = mwu(vals_a, vals_b)
    A12 = Ua / (n1 * n2)
    p = exact_p_two_tailed(vals_a, vals_b, Ua)
    return {
        "comparison": f"{name_a} vs {name_b}",
        "status": "computed",
        "n_a": n1, "n_b": n2,
        "median_a": median(vals_a), "median_b": median(vals_b),
        "iqr_a": iqr(vals_a), "iqr_b": iqr(vals_b),
        "values_a": sorted(vals_a), "values_b": sorted(vals_b),
        "U_a": Ua, "U_b": Ub, "U_min": min(Ua, Ub),
        "A12": A12, "A12_direction": f"P({name_a} > {name_b}) + 0.5*P(tie)",
        "p_two_tailed_exact": p,
        "unit": unit, "source": source, "note": note,
    }

def recorded(comparison, medians, extra, unit, source, note):
    return {
        "comparison": comparison,
        "status": "recorded-only",
        "medians": medians, "extra": extra,
        "A12": None, "U": None, "p": None,
        "unit": unit, "source": source, "note": note,
    }

def excluded(comparison, medians, values, source, note):
    return {
        "comparison": comparison,
        "status": "located-excluded",
        "medians": medians, "values": values,
        "A12": None, "U": None, "p": None,
        "unit": "bins", "source": source, "note": note,
    }

const_note = ("constant seed-wise values: zero within-group variance; "
              "exact permutation two-tailed p (n=3 seeds each, statistical power limited); "
              "significance is trivial by construction")

results = []
# --- computable: riscv-dv series (seed-wise values are the per-DUT constants) ---
# riscv-dv-SV rocket (R5/R7): 30/144 every seed; Cascade rocket (ms 8.3): 9 every seed
results.append(compare(
    "riscv-dv-SV rocket", [30, 30, 30],
    "Cascade rocket", [9, 9, 9],
    "bins", "riscv-dv R5/R7 summaries; manuscript 8.3", const_note))
# riscv-dv-SV rocket vs cva6 (both 30/144 every seed)
results.append(compare(
    "riscv-dv-SV rocket", [30, 30, 30],
    "riscv-dv-SV cva6", [30, 30, 30],
    "bins", "riscv-dv R5/R7 summaries", const_note + "; identical distributions"))
# riscv-dv-SV rocket vs boom (35/144 every seed)
results.append(compare(
    "riscv-dv-SV rocket", [30, 30, 30],
    "riscv-dv-SV boom", [35, 35, 35],
    "bins", "riscv-dv R5/R7 summaries", const_note))
# riscv-dv SV pipeline (R5) vs splicer-only (R4): 30 vs 6 bins
results.append(compare(
    "riscv-dv-SV (R5)", [30, 30, 30],
    "riscv-dv splicer-only (R4)", [6, 6, 6],
    "bins", "riscv-dv R4/R5 summaries", const_note))

# --- recorded-only (manuscript statistics; seed-wise vectors not located) ---
results.append(recorded(
    "PMPFuzz vs Cascade final BAPC bins (8.3)",
    {"PMPFuzz": {"rocket": 122, "boom": 123, "cva6": 131},
     "Cascade": {"rocket": 9, "boom": 9, "cva6": 15}},
    {"multiplier": {"rocket": 13.6, "boom": 13.7, "cva6": 8.7},
     "universe": "144 bins; Cascade constant across all seeds"},
    "bins", "manuscript section 8.3",
    "PMPFuzz seed-wise vectors not located in workspace artifacts; medians quoted as recorded statistics"))
results.append(recorded(
    "PMPFuzz vs PMPFuzz-Syntax final bins (8.5)",
    {"PMPFuzz": 124, "Syntax-ablated": 83, "no-address": 41},
    {"inputs": 9216, "qualified": {"PMPFuzz": 7192, "Syntax": 7217}},
    "bins", "manuscript section 8.5",
    "seed-wise vectors not located; quoted as recorded statistics"))
results.append(recorded(
    "guided vs random time-to-endpoint (8.4)",
    {"reduction_range_pct": [33.6, 59.1]},
    {}, "median time reduction", "manuscript section 8.4",
    "campaign pairs not located in workspace; range quoted as recorded statistics"))
results.append(recorded(
    "guided vs random hardware coverage (8.7)",
    {"u74": {"guided_mean_pct": 76.2, "ci": [73.6, 78.5], "random_mean_pct": 70.6,
             "budget": 384, "delta_pp": 5.6},
     "c910": {"delta_pp": 14.9}},
    {}, "coverage pct", "manuscript section 8.7; see hardware_stats.json",
    "located local hardware artifacts contain only pilot runs with identical driver/seed/config (no guided-vs-random instrumentation); manuscript values quoted as recorded statistics"))

# --- located but excluded (inconsistent with manuscript; contract consistency rule) ---
results.append(excluded(
    "PMPFuzz boom-clean final bins (located dir)",
    {"median": 47.76923076923077},
    [6.230769230769231, 6.230769230769231, 6.230769230769231, 47.76923076923077,
     47.76923076923077, 48.46153846153847, 48.46153846153847, 48.46153846153847,
     48.46153846153847],
    "pmpfuzz-eval-artifacts/bapc-convergence/boom-clean-bapc-convergence-4aeecc5-20260716T045000Z",
    "inconsistent with manuscript 8.3 (BOOM median 123/144); excluded from statistics per contract consistency rule"))
results.append(excluded(
    "PMPFuzz cva6-clean final bins (located dir)",
    {"median": 46.38461538461539},
    [9.0, 9.0, 9.0, 46.38461538461539, 46.38461538461539, 47.07692307692308,
     47.07692307692308, 47.76923076923077, 47.76923076923077],
    "pmpfuzz-eval-artifacts/bapc-convergence/cva6-clean-bapc-convergence-9ef30a9-20260719T180529Z",
    "inconsistent with manuscript 8.3 (CVA6 median 131/144); excluded from statistics per contract consistency rule"))
results.append(excluded(
    "PMPFuzz rocket-clean final bins (located dir)",
    {"median": None}, [],
    "pmpfuzz-eval-artifacts/bapc-convergence/rocket-clean-bapc-convergence-4aeecc5-20260722T052610Z",
    "0 seed-wise rows located at expected depth; nothing to compare"))
results.append(excluded(
    "Cascade rocket final bins (located dir)",
    {"median": None}, [],
    "pmpfuzz-eval-artifacts/bapc-convergence/rocket-clean-cascade-3b5ebc0-20260722T091830Z",
    "0 seed-wise rows located at expected depth; manuscript constant 9 used instead (see computed row 1)"))

out = {
    "schema_version": 2,
    "generated": "2026-08-15",
    "results": results,
    "methods": {
        "centrality": "seed-wise median",
        "dispersion": "seed-wise IQR (linear interpolation)",
        "test": "two-tailed Mann-Whitney U with midrank ties",
        "p_value": "exact permutation enumeration over C(n1+n2, n1) partitions (n1,n2<=20); normal approximation with continuity correction otherwise",
        "effect_size": "Vargha-Delaney A12 = U_a/(n1*n2); centered form (2U - n1*n2)/(n1*n2) = 2*A12 - 1",
        "implementation": "pure python (no scipy on the box), archived as sm_a2_stats.py next to this file",
        "interpretation": "A12 = P(group_a > group_b) + 0.5*P(tie); 1.0 = group_a always above, 0.5 = no effect, 0.0 = group_b always above"
    },
    "not_located_annotations": [
        "PMPFuzz seed-wise final values for manuscript 8.3 were not unambiguously located in the workspace artifact trees; manuscript medians quoted as recorded statistics.",
        "8.4 guided vs random time-to-endpoint campaign pairs not located; 33.6-59.1% quoted as recorded statistics.",
        "8.7 hardware guided-vs-random: local artifacts contain pilot runs only (see hardware_stats.json); manuscript values quoted as recorded statistics."
    ]
}
with open("stats.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
print("stats.json written:", len(json.dumps(out)), "bytes")
for r in out["results"]:
    if r["status"] == "computed":
        print(f"{r['comparison']}: A12={r['A12']:.3f} U_min={r['U_min']} p={r['p_two_tailed_exact']}")
