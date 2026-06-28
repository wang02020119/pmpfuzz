# PMP Fuzz

Research-grade RISC-V PMP fuzzing tool for PMP, privilege switching, Sv39
translation, and page-table-walk PMP checks.

Current scope:

- PMP/Smepmp-aware scenario model.
- Sv39 page-table walk and final-physical PMP oracle.
- Smepmp/MMU profile generator with harness-safe M/S/U regions.
- Independent PMP oracle.
- Assembly testcase emitter for Spike and clean Chipyard Rocket/BOOM.
- Engineering CLI with generation, run, repro, triage, and report commands.
- Coverage matrix and security verdict reporting for differential DUT evidence.
- No AFL, libFuzzer, Cascade, GenHuzz, or other external fuzzers in this stage.

Run tests:

```sh
python3 -m unittest discover -s tests
```

Check the experiment environment:

```sh
python3 -m pmpfuzz env-check
```

Generate cases without running a DUT:

```sh
python3 -m pmpfuzz gen \
  --profile legacy-data \
  --count 16 \
  --no-smepmp \
  --out runs/generated_legacy_data
```

Generate multiple coverage profiles in one run directory:

```sh
python3 -m pmpfuzz gen \
  --profiles pmp-boundary,sv39-perm-matrix,sv39-ptw-pmp-matrix \
  --count 8 \
  --no-smepmp \
  --out runs/generated_coverage_matrix
```

Run a campaign:

```sh
python3 -m pmpfuzz run \
  --dut rocket-clean \
  --profile sv39-final-pmp \
  --count 30 \
  --seed 20260628 \
  --no-smepmp \
  --per-case-timeout 60 \
  --out runs/rocket_sv39_final
```

Reproduce a single generated case across Spike/Rocket/BOOM:

```sh
python3 -m pmpfuzz repro \
  --case runs/rocket_sv39_final/cases/scenario_0000 \
  --dut spike,rocket-clean,boom-clean \
  --no-smepmp \
  --out runs/repro_scenario_0000
```

Classify failures and write a report:

```sh
python3 -m pmpfuzz triage --run-dir runs/rocket_sv39_final
python3 -m pmpfuzz coverage --run-dir runs/rocket_sv39_final
python3 -m pmpfuzz report --run-dir runs/rocket_sv39_final
```

The report includes a `Security Verdict` section. A BOOM PTW/PMP hang with
Spike/Rocket pass evidence is reported as `confirmed_new_failure_mode`.

Useful coverage-oriented profiles:

- `pmp-boundary`: TOR/NA4/NAPOT boundary and first-match PMP behavior.
- `sv39-perm-matrix`: S/U, SUM, MXR, and final PTE permission matrix.
- `sv39-ptw-pmp-matrix`: PTW PMP deny coverage across walk levels and preload modes.
- `boom-ptw-pmp-regression`: fixed BOOM PTW/PMP regression and controls.

Stateful permission profiles close the stale-permission and memory-side-effect
part of the PMP security chain:

- `pmp-side-effect`: denied store must trap without changing the sentinel word;
  allowed store controls must update it.
- `tlb-stale-pte`: warm translation, mutate leaf PTE to deny, then probe again.
- `tlb-stale-pmp`: warm translation, mutate final-target PMP to deny, then probe again.
- `ptw-stale-pmp`: warm PTW path, mutate PTE-page PMP to deny, then probe again.

Run the chain-closure smoke suite on the server:

```sh
sh scripts/run_chain_closure_smoke.sh
```

Run the engineering smoke suite on the server:

```sh
sh scripts/run_engineering_smoke.sh
```

Campaign output uses this structure:

- `cases/<case>/case.json` and `<case>.S`
- `results/<case>/result.json` and simulator log
- `failures/` copied artifacts for non-pass cases
- `aggregate.json`, `triage/triage.json`, `reports/report.md`

The legacy `python3 -m pmpfuzz.runner` entry point is kept for compatibility.
