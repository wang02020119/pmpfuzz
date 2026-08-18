# PMPFuzz

PMPFuzz is a RISC-V PMP/Smepmp fuzzing and evaluation toolkit. This branch
consolidates the newest project code found on GitHub, the experiment server,
and the local U74/C910 development trees.

## Release scope

The repository intentionally contains only reusable project material:

- `pmpfuzz/`: generators, models, emitters, DUT adapters, coverage logic, and
  campaign runtimes;
- `scripts/evaluation/`: evaluation tools grouped into analysis, campaigns,
  baselines, validation, OFF-state, Oracle, and hardware-specific modules;
- `configs/evaluation/`: versioned experiment contracts;
- `tests/`: unit, integration, data-contract, and regression tests;
- `defect/`: standalone project regression material;
- `docs/`: the design and engineering contracts required by `AGENTS.md`.

Raw experiment data, generated artifacts, paper sources, plotting scripts,
temporary Git bundles, and run logs are deliberately excluded. Data must be
stored and released separately from the tool repository.

## Consolidation provenance

The 2026-08-18 consolidation uses these inputs:

- private GitHub baseline: `c45de85d0d3c7ea0dc0067611c6d2b0c2b00cd24`;
- latest server branch: `8be1d6c02569ee28ff422b71af5d9dbf4b379f48`;
- local U74 baseline: `6d297d064fd48d008ae5908f5c27aebaa0337095`;
- later local C910, Oracle-validation, U74 campaign, and serial transport files
  that had not yet been published.

The release-layout regression test prevents the repository from losing the
new server/local components or reintroducing paper, plotting, and raw-data
material.

## Quick start

Run the portable test suite:

```sh
python -m pytest -q
```

Check the local experiment environment:

```sh
python -m pmpfuzz env-check
```

Generate cases without running a DUT:

```sh
python -m pmpfuzz gen \
  --profiles pmp-boundary,sv39-perm-matrix,sv39-ptw-pmp-matrix \
  --count 8 \
  --no-smepmp \
  --out runs/generated
```

Hardware, simulator, compiler, Docker, and external-generator checks may need
their explicitly configured dependencies. The U74 and C910 drivers require
the corresponding board or serial environment; Cascade and RISCV-DV adapters
require their external toolchains.

See [`docs/PMPFUZZ_DESIGN.md`](docs/PMPFUZZ_DESIGN.md) for the architecture.
See [`scripts/README.md`](scripts/README.md) for the complete script layout.
See [`scripts/evaluation/README.md`](scripts/evaluation/README.md) for the
evaluation-tool directory map and module entry points.
