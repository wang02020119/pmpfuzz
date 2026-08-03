# c910-defect-01

## Scope

- Target: `T-HEAD C910`
- Validation platform: `LicheePi 4A / TH1520`
- Defect class: supervisor instruction-fetch permission bypass

## Summary

When `sstatus.SUM=1`, the tested C910 platform allows `S-mode` to fetch and execute from a `PTE.U=1` user page. Under RISC-V privilege semantics, `SUM` should relax supervisor access to user data pages only. It must not allow supervisor instruction fetch from user pages.

This breaks the expected supervisor/user execute boundary.

## Trigger Shape

- build a user executable page with `U=1, R=1, X=1, A=1, D=1`
- place a payload that writes a supervisor-only marker and then executes `ecall`
- run three controls:
  - `S-mode, SUM=0`
  - `S-mode, SUM=1`
  - `U-mode` control

## Key Observation

- `S-mode, SUM=0`: fetch page fault, marker unchanged
- `S-mode, SUM=1`: payload reaches `supervisor_ecall`, marker updated
- `U-mode control`: payload reaches `user_ecall`

The marker write is critical because it shows the code did not merely get speculatively touched; it executed with supervisor privilege.

## Root Cause Notes

The instruction-side permission check appears to incorporate `SUM` into the supervisor fetch allow path for user pages. That is the wrong policy boundary:

- `SUM` may affect supervisor load/store to user pages;
- `SUM` must not permit supervisor execute-from-user-page.

## Evidence Status

- Reproduced on real hardware through the OpenSBI probing layer.
- This defect is not currently tied to a public upstream issue in the project notes.

## Project Mapping

- Stable project name: `c910-defect-01`
- Paper role: C910 supervisor/user execute-isolation break
- Current seed status: this is maintained as a hardware validation study rather than an RTL simulator seed inside PMPFuzz
