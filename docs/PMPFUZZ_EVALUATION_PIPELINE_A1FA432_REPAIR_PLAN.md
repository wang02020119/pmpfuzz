# PMPFuzz evaluation pipeline contract

This document records the reusable engineering contract for PMPFuzz
evaluation. Machine-specific paths, run logs, temporary workarounds, and
experiment results do not belong here.

## Scope

The evaluation pipeline consists of:

1. deterministic candidate generation;
2. execution through a declared DUT or baseline adapter;
3. execution-qualified coverage collection;
4. append-only timeline and result recording;
5. aggregation against a versioned coverage universe;
6. validation of provenance, counts, hashes, and completion state.

The implementation is organized under `scripts/evaluation/`:

- `campaigns/` owns orchestration;
- `baseline_adapters/` owns external-generator integration;
- `analysis/` owns aggregation and summaries;
- `validation/` owns artifact and timeline checks;
- `hardware/` owns board-specific flows;
- `off_state/` owns PMP OFF-state characterization;
- `oracle_validation/` owns reference-model validation.

## Required invariants

- A scheduled case has one stable case identifier.
- Every executed case has one terminal result record.
- Coverage changes only when an observation is execution-qualified.
- Timeline ordering uses recorded completion time, not directory order.
- Campaign metadata identifies the source revision, DUT, configuration,
  coverage universe, budget, seed, and stop reason.
- Aggregation fails closed when required inputs are absent or inconsistent.
- Generated artifacts are stored outside the source repository.

## External configuration

DUT binaries, compiler toolchains, baseline checkouts, board transports, and
artifact roots are supplied by command-line options or environment variables.
Repository code must not depend on a developer username, workstation path, or
server login alias.

## Release boundary

The Git repository contains source, configuration, documentation, and tests.
It excludes raw experiment data, simulator logs, generated binaries, plots,
paper sources, authorization packages, and temporary transfer bundles.
