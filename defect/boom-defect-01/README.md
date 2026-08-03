# boom-defect-01

## Scope

- Target: `BOOM SmallBoomV3Config`
- Public tracking: `riscv-boom/riscv-boom` issue `#785`
- Defect class: PTW/PMP exception propagation failure

## Summary

When a low-privilege memory access triggers an `Sv39` page-table walk and the implicit PTE read is denied by `PMP`, BOOM does not reliably return the architecturally required access-fault trap. Two bad outcomes were observed:

1. the implementation compresses the fault into a page-fault-class exception, or
2. the fault is never delivered as a precise trap and the core eventually reaches `Pipeline has hung`.

The second outcome is the stronger defect because software never regains control through the trap handler.

## Trigger Shape

- `MXR=1`
- cold page-table / refill-sensitive state
- a page walk that touches a `PMP`-denied PTE page
- representative denied walk page: `0x80013000`

Observed controls show that the hang disappears when:

- `MXR=0`, or
- the relevant PTEs are pre-warmed before the critical access.

## Root Cause Notes

The study converged on two related but distinct BOOM-side problems:

1. frontend instruction-fetch PTW exceptions can be lost between `rocket TLB` refill and BOOM frontend exception enqueue, leaving the machine spinning without a trap;
2. BOOM v3 `NBDTLB` folds `ae_ptw` and `ae_final` too aggressively, which explains the wrong-exception-code behavior on load/store-side paths.

The hang path is not well explained by the `NBDTLB` folding bug alone. The strongest evidence points to a frontend `miss`/exception-delivery mismatch.

## Evidence Status

- Direct BOOM simulator replay still reproduces the hang.
- Return code from the direct replay path was `255`.
- Control variants with `MXR=0` or pre-warmed PTEs complete normally.

## Project Mapping

- Stable project name: `boom-defect-01`
- Paper role: BOOM PTW/PMP fault-delivery defect
- Current seed status: reproducible on the BOOM RTL path through the existing simulator flow
