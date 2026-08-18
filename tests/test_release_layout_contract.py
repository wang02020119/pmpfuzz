from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_LATEST_COMPONENTS = (
    "pmpfuzz/cascade_runtime.py",
    "pmpfuzz/c910_m2_scheduling.py",
    "scripts/evaluation/baseline_adapters/riscv_dv.py",
    "scripts/evaluation/campaigns/run_closed_loop_campaign.py",
    "scripts/evaluation/analysis/aggregate_results.py",
    "scripts/evaluation/hardware/c910/c910_cl56_common.py",
    "scripts/evaluation/hardware/u74/u74_cl144_common.py",
    "scripts/evaluation/validation/validate_timeline.py",
)

FORBIDDEN_TOP_LEVEL = ("analysis", "artifacts", "paper", "papers")
FORBIDDEN_FILES = ("RUNLOG.md", "scripts/evaluation/plot_coverage_time.py")


def test_release_contains_latest_local_and_server_components() -> None:
    missing = [
        relative
        for relative in REQUIRED_LATEST_COMPONENTS
        if not (REPOSITORY_ROOT / relative).is_file()
    ]

    assert not missing, f"release is missing latest PMPFuzz components: {missing}"


def test_release_excludes_paper_plotting_and_raw_artifact_material() -> None:
    forbidden = [
        relative
        for relative in FORBIDDEN_TOP_LEVEL + FORBIDDEN_FILES
        if (REPOSITORY_ROOT / relative).exists()
    ]
    plotting_scripts = sorted(
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in REPOSITORY_ROOT.rglob("plot_*.py")
        if ".git" not in path.parts and "__pycache__" not in path.parts
    )
    bundles = sorted(
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in REPOSITORY_ROOT.rglob("*.bundle")
        if ".git" not in path.parts
    )

    assert not forbidden, f"release contains non-project paths: {forbidden}"
    assert not plotting_scripts, f"release contains plotting scripts: {plotting_scripts}"
    assert not bundles, f"release contains temporary git bundles: {bundles}"


def test_evaluation_scripts_are_grouped_by_responsibility() -> None:
    evaluation_root = REPOSITORY_ROOT / "scripts" / "evaluation"
    required_groups = {
        "analysis",
        "baseline_adapters",
        "campaigns",
        "hardware",
        "off_state",
        "oracle_validation",
        "validation",
    }
    actual_groups = {path.name for path in evaluation_root.iterdir() if path.is_dir()}
    flat_scripts = sorted(path.name for path in evaluation_root.glob("*.py"))

    assert required_groups <= actual_groups
    assert not flat_scripts, f"evaluation scripts must not be flat: {flat_scripts}"


def test_repository_scripts_are_grouped_by_responsibility() -> None:
    scripts_root = REPOSITORY_ROOT / "scripts"
    required_groups = {"build", "evaluation", "smoke", "transport"}
    actual_groups = {path.name for path in scripts_root.iterdir() if path.is_dir()}
    flat_scripts = sorted(
        path.name
        for path in scripts_root.iterdir()
        if path.is_file() and path.suffix in {".py", ".sh"}
    )

    assert required_groups <= actual_groups
    assert not flat_scripts, f"repository scripts must not be flat: {flat_scripts}"


def test_release_docs_do_not_expose_internal_execution_context() -> None:
    forbidden_markers = (
        "D:\\c_s",
        "/home/dubhe/wjs",
        "ssh dubhe",
        "DeepSeek",
        "Claude Code",
    )
    exposed = []
    for path in (REPOSITORY_ROOT / "docs").rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        for marker in forbidden_markers:
            if marker in text:
                exposed.append(f"{path.relative_to(REPOSITORY_ROOT).as_posix()}: {marker}")

    assert not exposed, f"release docs expose internal execution context: {exposed}"
