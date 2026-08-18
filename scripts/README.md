# Project scripts

Scripts are grouped by operational responsibility:

- `build/`: DUT builds, environment setup, compilation, and Verilator wrappers;
- `evaluation/`: campaign, baseline, hardware, analysis, and validation tools;
- `smoke/`: short project smoke and targeted campaign entry points;
- `transport/`: serial-console execution and upload utilities.

Run scripts from the repository root unless their help text says otherwise.
Machine paths, board addresses, credentials, ports, and private keys are
runtime configuration and must be supplied through arguments or environment
variables.
