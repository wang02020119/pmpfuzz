# PMPFuzz DUT readiness contract

This document defines the reusable readiness criteria for PMPFuzz DUT
adapters. It intentionally contains no machine-specific build paths or
historical experiment status.

## DUT matrix

The supported evaluation matrix is:

- Rocket
- BOOM
- XiangShan
- CVA6

Each adapter declares its simulator or board command, ISA configuration,
timeout policy, result parser, provenance fields, and supported coverage mode.

## Readiness stages

1. **Environment**: required binaries and external repositories are present.
2. **Build**: the DUT build is reproducible from a recorded source revision.
3. **Control execution**: a known control payload reaches a terminal state.
4. **Artifact contract**: logs, results, timelines, and hashes are complete.
5. **Coverage qualification**: only valid completed observations affect
   coverage.
6. **Campaign smoke**: a short predeclared campaign completes within budget.

Infrastructure failure, timeout, missing output, and ordinary non-pass results
remain distinct engineering states. Readiness checks validate transport and
artifact integrity; they do not reinterpret result contents.

## Configuration boundary

All installation roots and DUT-specific locations are external configuration.
Recommended variables include:

- `PMPFUZZ_WORKSPACE`
- `PMPFUZZ_ARTIFACT_ROOT`
- `RISCV`
- `RISCV_DV_ROOT`
- `CHIPYARD_DIR`
- `XIANGSHAN_DIR`

Board-specific flows additionally require explicit serial or remote-build
configuration. Credentials are provided at runtime and must never be committed.

## Repository boundary

Readiness reports and generated artifacts are not source files. Keep them in
an ignored artifact root and publish them separately when needed. The tool
repository retains only adapters, orchestration, validation logic, versioned
configuration, and regression tests.
