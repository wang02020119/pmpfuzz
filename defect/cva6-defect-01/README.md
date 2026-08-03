# cva6-defect-01

## Scope

- Target: shared-TLB-enabled `CVA6`
- Disclosure status: private coordinated report
- Defect class: cross-access-type page-permission bypass

## Summary

The shared-TLB path in CVA6 can reuse translation state established by one access type for a later access of a different type without re-validating the relevant page-permission semantics for the current access.

The minimal project-facing instance is:

1. warm an `X-only` page through instruction fetch;
2. perform a data load from the same virtual page;
3. observe a successful load where a `LOAD_PAGE_FAULT` should have occurred.

## Trigger Shape

- build requirement: shared TLB enabled
- representative target page permissions: `V=1, R=0, W=0, X=1, A=1`
- phase 0: fetch warms the translation
- phase 1: load reuses it as data

On a correct implementation, phase 1 should trap. On the affected shared-TLB build, the load reads back the instruction word from the target page.

## Root Cause Notes

The defect chain is:

1. PTW performs miss-time permission screening for the triggering access type only;
2. shared TLB caches the raw leaf translation without an access-type dimension in the hit key;
3. ITLB/DTLB hit paths do not fully re-check the relevant `X/R/A/MXR` semantics for the current access;
4. final `PMP` checks operate on the physical address side and cannot restore a page-permission check that was skipped earlier.

## Evidence Status

- Dynamic reproduction succeeded on the shared-TLB-enabled `Variane_testharness`.
- The validated project path is the standalone PoC `cva6-defect-01.S` through `python3 -m pmpfuzz repro`.
- The default non-shared CVA6 build does not expose this path because the shared TLB is compiled out there.

## Project Mapping

- Stable project name: `cva6-defect-01`
- Paper role: CVA6 shared-TLB permission-reuse defect
- Current seed status: reproducible through the PMPFuzz repro flow when the standalone `.S` input is used with the shared-TLB CVA6 harness
