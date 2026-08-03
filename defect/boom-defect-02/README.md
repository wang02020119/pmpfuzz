# boom-defect-02

## Scope

- Target: `BOOM SmallBoomV3Config`
- Public tracking: `riscv-boom/riscv-boom` issue `#786`
- Defect class: over-restrictive execute-permission check

## Summary

BOOM frontend asks the TLB/PMP path to authorize an entire fetch packet instead of the actual target instruction bytes. On `SmallBoomV3Config`, that execute check is `8` bytes wide. A narrow `PMP NA4` entry can therefore poison a legal fetch that sits next to the denied region inside the same widened frontend check.

This is not a permission bypass. It is a false instruction-access fault on an otherwise legal target instruction.

## Trigger Shape

- translation mode: bare
- privilege: `M`
- denied PMP entry: `NA4`
- representative deny window: `[0x80008000, 0x80008004)`
- representative legal target PC: `0x80008004`

Architecturally, that target fetch should pass. BOOM instead faults because the execute-permission question is widened to the whole fetch packet.

## Root Cause Notes

The defect is specifically in frontend query granularity:

1. BOOM frontend sets the request size to the fetch-packet width;
2. `rocket TLB` forwards that widened size into `PMPChecker`;
3. `PMPChecker` selects a matching entry by overlap but grants permission only on full containment;
4. a `4B` `NA4` entry cannot fully authorize an `8B` BOOM fetch check.

Rocket's default frontend uses a smaller check width, which is why the same shape does not fail there.

## Evidence Status

- Source audit confirms the root cause.
- The issue is already publicly tracked upstream.
- The project treats this as a BOOM-specific false-fault defect rather than a bypass.

## Project Mapping

- Stable project name: `boom-defect-02`
- Paper role: BOOM execute-permission granularity defect
- Current seed status: research and source-level trigger shape are fixed; the bug is retained as a study target even though its strongest evidence is source-audit-based
