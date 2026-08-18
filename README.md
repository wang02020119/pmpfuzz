# PMPFuzz

PMPFuzz generates and runs RISC-V PMP and Smepmp test cases.

Run commands from the repository root with Python 3:

```sh
python -m pmpfuzz --help
python -m pmpfuzz env-check
```

Generate test cases:

```sh
python -m pmpfuzz gen \
  --profiles pmp-boundary,sv39-perm-matrix,sv39-ptw-pmp-matrix \
  --count 8 \
  --no-smepmp \
  --out runs/generated
```

Run a campaign:

```sh
python -m pmpfuzz run \
  --dut spike \
  --profile pmp-boundary \
  --count 8 \
  --out runs/spike
```

Use `python -m pmpfuzz <command> --help` to view command options. Pass tool
paths and DUT paths through command-line arguments or environment variables.
