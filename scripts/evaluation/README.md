# Evaluation tooling

Evaluation entry points are grouped by responsibility. Run modules from the
repository root with `python -m` so imports and provenance paths remain stable.

| Directory | Responsibility |
| --- | --- |
| `analysis/` | Aggregation, summaries, re-analysis, and efficiency metrics |
| `baseline_adapters/` | Cascade and RISCV-DV generation/execution adapters |
| `campaigns/` | Closed-loop and formal-matrix orchestration |
| `hardware/c910/` | C910 corpus preparation, scheduling, and board campaigns |
| `hardware/u74/` | U74 corpus preparation, scheduling, and board campaigns |
| `off_state/` | PMP OFF-state characterization and execution |
| `oracle_validation/` | Reference-model and semantic-mutant validation |
| `validation/` | Timeline, coverage-universe, and runtime-attribution checks |

Examples:

```sh
python -m scripts.evaluation.campaigns.run_closed_loop_campaign --help
python -m scripts.evaluation.analysis.aggregate_results --help
python -m scripts.evaluation.hardware.u74.run_u74_board_round --help
python -m scripts.evaluation.validation.validate_timeline --help
```

Generated data and plots do not belong in this directory or in Git. Keep them
under an ignored artifact root outside the source tree.
