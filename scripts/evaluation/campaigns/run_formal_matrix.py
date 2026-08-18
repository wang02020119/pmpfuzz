#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.evaluation.baseline_adapters.cascade import (
    CASCADE_COPYBACK_TIMEOUT_SECONDS,
    CASCADE_GENERATOR_TIMEOUT_SECONDS,
    CASCADE_RETRYABLE_SPIKE_TIMEOUT_RETRIES,
    CASCADE_STAGE_TIMEOUT_SECONDS,
)

CHIPYARD_DIR = Path(
    os.environ.get("CHIPYARD_DIR", str(Path.home() / "pmpfuzz-workspace" / "chipyard"))
).expanduser()
BAPC_CORE_VERSION = 'v4'
BAPC_TARGET = 144
BAPC_BIN_SET_SHA256 = '7e142506fe8566ac33198039caaf2c0da98473feadd826becc8dff785bb5df07'
EXPERIMENT_834 = 'section-8.3-8.4-formal-v4'
EXPERIMENT_85 = 'section-8.5-formal-v4'
FROZEN_DUT_HASHES = {
    'rocket-clean': '368ad4754798e45f8fa2809ce8e97741fb66bbc0e5445c8c1218115aeab20893',
    'boom-clean': '55c4247240ba79749e0897f2a0b939ef9d4810da092ad793891a1aed58e3c570',
    'cva6-clean': 'a81caf31b48eddee6ce29c16879f365cad03c68367e6f07961c9c02fc8692796',
}
DUT_SLOTS_BY_SEED = {
    4: {'rocket-clean': '0-7', 'boom-clean': '8-15', 'cva6-clean': '16-23'},
    5: {'boom-clean': '0-7', 'cva6-clean': '8-15', 'rocket-clean': '16-23'},
    6: {'cva6-clean': '0-7', 'rocket-clean': '8-15', 'boom-clean': '16-23'},
}
WAVES_834 = [
    {'wave': '8.3-8.4-wave01', 'seed': 4, 'kind': 'pmpfuzz', 'variant': 'random-mutation'},
    {'wave': '8.3-8.4-wave02', 'seed': 5, 'kind': 'pmpfuzz', 'variant': 'bb-guided'},
    {'wave': '8.3-8.4-wave03', 'seed': 6, 'kind': 'cascade', 'variant': 'cascade'},
    {'wave': '8.3-8.4-wave04', 'seed': 4, 'kind': 'pmpfuzz', 'variant': 'bb-guided'},
    {'wave': '8.3-8.4-wave05', 'seed': 5, 'kind': 'cascade', 'variant': 'cascade'},
    {'wave': '8.3-8.4-wave06', 'seed': 6, 'kind': 'pmpfuzz', 'variant': 'random-mutation'},
    {'wave': '8.3-8.4-wave07', 'seed': 4, 'kind': 'cascade', 'variant': 'cascade'},
    {'wave': '8.3-8.4-wave08', 'seed': 5, 'kind': 'pmpfuzz', 'variant': 'random-mutation'},
    {'wave': '8.3-8.4-wave09', 'seed': 6, 'kind': 'pmpfuzz', 'variant': 'bb-guided'},
]
WAVES_85 = [
    {'wave': '8.5-wave01', 'seed': 4, 'generator_variant': 'full'},
    {'wave': '8.5-wave02', 'seed': 5, 'generator_variant': 'syntax'},
    {'wave': '8.5-wave03', 'seed': 6, 'generator_variant': 'full'},
    {'wave': '8.5-wave04', 'seed': 4, 'generator_variant': 'syntax'},
    {'wave': '8.5-wave05', 'seed': 5, 'generator_variant': 'full'},
    {'wave': '8.5-wave06', 'seed': 6, 'generator_variant': 'syntax'},
]

REPO_ROOT = Path(__file__).resolve().parents[3]
ARTIFACT_ROOT = Path('/tmp/unconfigured-formal-artifact-root')
WORKTREE = REPO_ROOT
SOURCE_SHA = ''
SOURCE_BRANCH = ''
LOG_PATH = Path('/tmp/unconfigured-formal.log')
STATUS_PATH = Path('/tmp/unconfigured-matrix-status.json')
SELF_CHECK_PATH = Path('/tmp/unconfigured-selfcheck.json')
FROZEN_DUTS: dict[str, dict[str, Any]] = {}
CASCADE_STALE_LIMIT_SECONDS = (
    CASCADE_STAGE_TIMEOUT_SECONDS * 2
    + CASCADE_GENERATOR_TIMEOUT_SECONDS * (CASCADE_RETRYABLE_SPIKE_TIMEOUT_RETRIES + 1)
    + CASCADE_COPYBACK_TIMEOUT_SECONDS
    + 2 * 60
    + 120
)


def stale_limit_seconds(spec: dict[str, Any]) -> int:
    if spec.get('kind') == 'cascade':
        return CASCADE_STALE_LIMIT_SECONDS
    return 600


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run the frozen BAPC v4 formal matrix for Sections 8.3/8.4/8.5.')
    parser.add_argument('--artifact-root', required=True)
    parser.add_argument('--chipyard-dir', default=str(CHIPYARD_DIR))
    parser.add_argument('--bapc-core-version', default=BAPC_CORE_VERSION)
    parser.add_argument('--bapc-target', type=int, default=BAPC_TARGET)
    parser.add_argument('--bin-set-sha256', default=BAPC_BIN_SET_SHA256)
    parser.add_argument('--rocket-bin')
    parser.add_argument('--boom-bin')
    parser.add_argument('--cva6-bin')
    return parser.parse_args()


def configure(args: argparse.Namespace) -> None:
    global ARTIFACT_ROOT, WORKTREE, SOURCE_SHA, SOURCE_BRANCH, LOG_PATH, STATUS_PATH, SELF_CHECK_PATH, CHIPYARD_DIR, BAPC_CORE_VERSION, BAPC_TARGET, BAPC_BIN_SET_SHA256, FROZEN_DUTS
    ARTIFACT_ROOT = Path(args.artifact_root).resolve()
    WORKTREE = REPO_ROOT
    CHIPYARD_DIR = Path(args.chipyard_dir).resolve()
    BAPC_CORE_VERSION = args.bapc_core_version
    BAPC_TARGET = int(args.bapc_target)
    BAPC_BIN_SET_SHA256 = args.bin_set_sha256
    SOURCE_SHA = run_text(['git', 'rev-parse', 'HEAD'])
    SOURCE_BRANCH = run_text(['git', 'branch', '--show-current'])
    LOG_PATH = ARTIFACT_ROOT / 'logs' / 'matrix-supervisor.log'
    STATUS_PATH = ARTIFACT_ROOT / 'ops' / 'matrix-status.json'
    SELF_CHECK_PATH = ARTIFACT_ROOT / 'validation' / 'bapc-v4-selfcheck.json'
    FROZEN_DUTS = {
        'rocket-clean': {
            'path': Path(args.rocket_bin).resolve() if args.rocket_bin else (ARTIFACT_ROOT / 'frozen-duts' / 'rocket.bin'),
            'sha256': FROZEN_DUT_HASHES['rocket-clean'],
        },
        'boom-clean': {
            'path': Path(args.boom_bin).resolve() if args.boom_bin else (ARTIFACT_ROOT / 'frozen-duts' / 'boom.bin'),
            'sha256': FROZEN_DUT_HASHES['boom-clean'],
        },
        'cva6-clean': {
            'path': Path(args.cva6_bin).resolve() if args.cva6_bin else (ARTIFACT_ROOT / 'frozen-duts' / 'cva6.bin'),
            'sha256': FROZEN_DUT_HASHES['cva6-clean'],
        },
    }


def dut_root(dut: str) -> Path:
    return ARTIFACT_ROOT / 'dut-roots' / dut


def log(message: str) -> None:
    line = f'[{utcnow()}] {message}'
    print(line, flush=True)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(line + '\n')


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.tmp')
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + '\n', encoding='ascii')
    os.replace(tmp, path)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_text(cmd: list[str], *, cwd: Path | None = None) -> str:
    proc = subprocess.run(cmd, cwd=cwd or WORKTREE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    return proc.stdout.strip()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def capture_environment() -> dict[str, Any]:
    return {
        'artifact_root': str(ARTIFACT_ROOT),
        'worktree': str(WORKTREE),
        'hostname': platform.node(),
        'platform': platform.platform(),
        'python_executable': sys.executable,
        'python_version': platform.python_version(),
        'worktree_branch': SOURCE_BRANCH,
        'worktree_sha': SOURCE_SHA,
        'worktree_status_short': run_text(['git', 'status', '--short']),
        'cpu': run_text(['lscpu']),
        'memory': run_text(['free', '-h']),
        'disk': run_text(['df', '-h', '/', '/tmp']),
        'chipyard_sha': run_text(['git', '-C', str(CHIPYARD_DIR), 'rev-parse', 'HEAD']),
        'chipyard_status_short': run_text(['git', '-C', str(CHIPYARD_DIR), 'status', '--short']),
        'chipyard_status': run_text(['git', '-C', str(CHIPYARD_DIR), 'status']),
        'chipyard_submodule_status': run_text(['git', '-C', str(CHIPYARD_DIR), 'submodule', 'status']),
    }


def write_dut_root_manifests(dut: str, env: dict[str, Any]) -> None:
    root = dut_root(dut)
    (root / 'manifests').mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        root / 'manifests' / 'environment.json',
        {
            'artifact_root': str(root),
            'dut': dut,
            'worktree': str(WORKTREE),
            'source_sha': SOURCE_SHA,
            'chipyard_sha': env['chipyard_sha'],
            'hostname': env['hostname'],
            'python_executable': env['python_executable'],
            'python_version': env['python_version'],
        },
    )
    (root / 'manifests' / 'git-shas.txt').write_text(
        f"{SOURCE_SHA}  pmpfuzz\n{env['chipyard_sha']}  chipyard\n",
        encoding='ascii',
    )
    atomic_write_json(
        root / 'manifests' / 'formal-freeze.json',
        {
            'schema_version': '1.0',
            'created_utc': utcnow(),
            'artifact_root': str(root),
            'dut': dut,
            'source_sha': SOURCE_SHA,
            'source_branch': SOURCE_BRANCH,
            'chipyard_dir': str(CHIPYARD_DIR),
            'chipyard_sha': env['chipyard_sha'],
            'bapc_core_version': BAPC_CORE_VERSION,
            'bapc_target': BAPC_TARGET,
            'bin_set_sha256': BAPC_BIN_SET_SHA256,
            'frozen_dut': {
                'path': str(FROZEN_DUTS[dut]['path']),
                'sha256': FROZEN_DUTS[dut]['sha256'],
            },
        },
    )


def write_initial_manifests() -> None:
    env = capture_environment()
    atomic_write_json(ARTIFACT_ROOT / 'manifests' / 'environment.json', env)
    (ARTIFACT_ROOT / 'manifests' / 'git-shas.txt').write_text(
        f"{SOURCE_SHA}  pmpfuzz\n{env['chipyard_sha']}  chipyard\n",
        encoding='ascii',
    )
    atomic_write_json(
        ARTIFACT_ROOT / 'manifests' / 'formal-freeze.json',
        {
            'schema_version': '1.0',
            'created_utc': utcnow(),
            'artifact_root': str(ARTIFACT_ROOT),
            'worktree': str(WORKTREE),
            'source_sha': SOURCE_SHA,
            'source_branch': SOURCE_BRANCH,
            'chipyard_dir': str(CHIPYARD_DIR),
            'chipyard_sha': env['chipyard_sha'],
            'bapc_core_version': BAPC_CORE_VERSION,
            'bapc_target': BAPC_TARGET,
            'bin_set_sha256': BAPC_BIN_SET_SHA256,
            'dut_roots': {dut: str(dut_root(dut)) for dut in FROZEN_DUTS},
            'frozen_duts': {
                dut: {'path': str(info['path']), 'sha256': info['sha256']}
                for dut, info in FROZEN_DUTS.items()
            },
            'wave_plan': {
                'section_8_3_8_4': WAVES_834,
                'section_8_5': WAVES_85,
            },
        },
    )
    atomic_write_json(
        ARTIFACT_ROOT / 'manifests' / 'matrix-plan.json',
        {
            'schema_version': '1.0',
            'created_utc': utcnow(),
            'waves_8_3_8_4': WAVES_834,
            'waves_8_5': WAVES_85,
            'slot_map_by_seed': DUT_SLOTS_BY_SEED,
        },
    )
    for dut in FROZEN_DUTS:
        write_dut_root_manifests(dut, env)


def assert_frozen_inputs() -> None:
    head = run_text(['git', 'rev-parse', 'HEAD'])
    if head != SOURCE_SHA:
        raise RuntimeError(f'source sha drifted: expected {SOURCE_SHA}, got {head}')
    status = run_text(['git', 'status', '--short'])
    if status:
        raise RuntimeError(f'source worktree is dirty:\n{status}')
    for dut, info in FROZEN_DUTS.items():
        actual = sha256_file(info['path'])
        if actual != info['sha256']:
            raise RuntimeError(f"frozen dut hash drift for {dut}: expected {info['sha256']}, got {actual}")


def run_selfcheck() -> None:
    log('running v4 selfcheck')
    out_log = ARTIFACT_ROOT / 'logs' / 'bapc-v4-selfcheck.log'
    with out_log.open('w', encoding='utf-8') as handle:
        proc = subprocess.run(
            [
                sys.executable,
                'scripts/evaluation/validation/validate_bapc_universe.py',
                '--dut',
                'cva6-clean',
                '--bapc-core-version',
                BAPC_CORE_VERSION,
                '--output',
                str(SELF_CHECK_PATH),
            ],
            cwd=WORKTREE,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(f'selfcheck failed with exit code {proc.returncode}')
    report = read_json(SELF_CHECK_PATH)
    if str(report.get('bapc_core_version')) != BAPC_CORE_VERSION:
        raise RuntimeError('selfcheck core version mismatch')
    if int(report.get('universe_bin_count') or 0) != BAPC_TARGET:
        raise RuntimeError('selfcheck bin count mismatch')
    if str(report.get('bin_set_sha256') or '') != BAPC_BIN_SET_SHA256:
        raise RuntimeError('selfcheck bin_set_sha256 mismatch')
    if int(report.get('witnessed_bin_count') or 0) != BAPC_TARGET:
        raise RuntimeError('selfcheck witnessed bin count mismatch')
    if int(report.get('unwitnessed_bin_count') or 0) != 0:
        raise RuntimeError('selfcheck has unwitnessed bins')
    if int(report.get('unexpected_mapper_bin_count') or 0) != 0:
        raise RuntimeError('selfcheck has unexpected mapper bins')
    log('v4 selfcheck passed')


def campaign_dir_for(dut: str, experiment_id: str, variant_segment: str, seed: int) -> Path:
    return dut_root(dut) / 'campaigns' / experiment_id / dut / variant_segment / 'bapc' / f'seed-{seed:04d}'


def build_pmpfuzz_cmd(*, experiment_id: str, dut: str, seed: int, variant: str, generator_variant: str) -> tuple[list[str], Path]:
    variant_segment = variant if generator_variant == 'full' else f'{variant}__{generator_variant}'
    campaign_dir = campaign_dir_for(dut, experiment_id, variant_segment, seed)
    dut_sha = run_text(['git', '-C', str(CHIPYARD_DIR), 'rev-parse', 'HEAD'])
    cmd = [
        'taskset', '-c', DUT_SLOTS_BY_SEED[seed][dut],
        sys.executable,
        'scripts/evaluation/campaigns/run_closed_loop_campaign.py',
        '--experiment-id', experiment_id,
        '--variant', variant,
        '--generator-variant', generator_variant,
        '--coverage-mode', 'bapc',
        '--bapc-core-version', BAPC_CORE_VERSION,
        '--dut', dut,
        '--profile', 'core-stateful',
        '--seed', str(seed),
        '--round-size', '8',
        '--bootstrap-size', '32',
        '--per-case-timeout', '10',
        '--jobs', '8',
        '--artifact-root', str(dut_root(dut)),
        '--dut-bin', str(FROZEN_DUTS[dut]['path']),
        '--chipyard-dir', str(CHIPYARD_DIR),
        '--source-sha', SOURCE_SHA,
        '--dut-sha', dut_sha,
        '--dut-binary-sha256', FROZEN_DUTS[dut]['sha256'],
        '--skip-artifact-root-prep',
        '--skip-artifact-root-finalize',
    ]
    if experiment_id == EXPERIMENT_834:
        cmd.extend([
            '--run-class', 'formal',
            '--budget-class', 'primary-wall-clock',
            '--time-budget', '7200',
            '--experiment-protocol-id', 'bapc-convergence-v1',
            '--convergence-stop',
            '--convergence-min-runtime-seconds', '0',
            '--convergence-confirmation-seconds', '600',
            '--convergence-confirmation-eligible-cases', '300',
            '--max-wall-time-seconds', '7200',
        ])
    else:
        cmd.extend([
            '--run-class', 'formal',
            '--budget-class', 'fixed-completed-inputs',
            '--time-budget', '3600',
            '--max-wall-time-seconds', '3600',
            '--max-completed-cases', '1024',
        ])
    return cmd, campaign_dir


def build_cascade_cmd(*, dut: str, seed: int) -> tuple[list[str], Path]:
    campaign_dir = campaign_dir_for(dut, EXPERIMENT_834, 'cascade', seed)
    cmd = [
        'taskset', '-c', DUT_SLOTS_BY_SEED[seed][dut],
        sys.executable,
        'scripts/evaluation/baseline_adapters/cascade.py',
        '--experiment-id', EXPERIMENT_834,
        '--experiment-protocol-id', 'bapc-convergence-v1',
        '--dut', dut,
        '--num-elfs', '8',
        '--batch-size', '8',
        '--simlen', '50000',
        '--timeout', '60',
        '--out', str(campaign_dir),
        '--seed', str(seed),
        '--coverage-mode', 'bapc',
        '--bapc-core-version', BAPC_CORE_VERSION,
        '--dut-bin', str(FROZEN_DUTS[dut]['path']),
        '--dut-source-dir', str(CHIPYARD_DIR),
        '--run-class', 'baseline-formal',
        '--budget-class', 'primary-wall-clock',
        '--convergence-min-runtime-seconds', '0',
        '--convergence-confirmation-seconds', '600',
        '--convergence-confirmation-eligible-cases', '300',
        '--max-wall-time-seconds', '7200',
    ]
    return cmd, campaign_dir


def launch_campaign(spec: dict[str, Any], wave_name: str) -> dict[str, Any]:
    dut = spec['dut']
    if spec['kind'] == 'cascade':
        cmd, campaign_dir = build_cascade_cmd(dut=dut, seed=spec['seed'])
        variant_segment = 'cascade'
    else:
        cmd, campaign_dir = build_pmpfuzz_cmd(
            experiment_id=spec['experiment_id'],
            dut=dut,
            seed=spec['seed'],
            variant=spec['variant'],
            generator_variant=spec.get('generator_variant', 'full'),
        )
        variant_segment = spec['variant'] if spec.get('generator_variant', 'full') == 'full' else f"{spec['variant']}__{spec['generator_variant']}"
    log_path = ARTIFACT_ROOT / 'logs' / wave_name / f'{dut}__{variant_segment}.log'
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open('w', encoding='utf-8')
    proc = subprocess.Popen(
        cmd,
        cwd=WORKTREE,
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    return {
        'spec': spec,
        'campaign_dir': campaign_dir,
        'log_path': log_path,
        'handle': handle,
        'proc': proc,
        'last_completed': 0,
        'last_progress_marker': None,
        'last_progress_time': time.monotonic(),
    }


def load_metadata(campaign_dir: Path) -> dict[str, Any] | None:
    path = campaign_dir / 'metrics' / 'campaign_metadata.json'
    if not path.is_file():
        return None
    try:
        return read_json(path)
    except Exception:
        return None


def load_bapc_universe(campaign_dir: Path, metadata: dict[str, Any]) -> dict[str, Any] | None:
    rel = ((metadata.get('coverage_universe_files') or {}).get('bapc') or '')
    if not rel:
        return None
    path = campaign_dir / rel
    if not path.is_file():
        return None
    try:
        return read_json(path)
    except Exception:
        return None


def validate_live_contract(entry: dict[str, Any], metadata: dict[str, Any]) -> None:
    if str(metadata.get('bapc_core_version') or '') != BAPC_CORE_VERSION:
        raise RuntimeError(f"{entry['spec']['dut']} core version mismatch")
    if int(metadata.get('bapc_target') or 0) != BAPC_TARGET:
        raise RuntimeError(f"{entry['spec']['dut']} bapc target mismatch")
    universe = load_bapc_universe(entry['campaign_dir'], metadata)
    if not isinstance(universe, dict):
        raise RuntimeError(f"{entry['spec']['dut']} missing bapc universe manifest")
    if int(universe.get('bin_count') or 0) != BAPC_TARGET:
        raise RuntimeError(f"{entry['spec']['dut']} universe bin count mismatch")
    if str(universe.get('bin_set_sha256') or '') != BAPC_BIN_SET_SHA256:
        raise RuntimeError(f"{entry['spec']['dut']} bin_set_sha256 mismatch")


def _count_files(path: Path, pattern: str) -> int:
    if not path.is_dir():
        return 0
    return sum(1 for _ in path.glob(pattern))


def cascade_progress_marker(campaign_dir: Path) -> dict[str, int]:
    return {
        'elf_count': _count_files(campaign_dir / 'elfs', '*.elf'),
        'sidecar_count': _count_files(campaign_dir / 'elfs', '*.json'),
        'stdout_log_count': _count_files(campaign_dir / 'logs', '*.stdout.log'),
        'stderr_log_count': _count_files(campaign_dir / 'logs', '*.stderr.log'),
    }


def _marker_tuple(marker: dict[str, int] | None) -> tuple[int, int, int, int] | None:
    if marker is None:
        return None
    return (
        int(marker.get('elf_count') or 0),
        int(marker.get('sidecar_count') or 0),
        int(marker.get('stdout_log_count') or 0),
        int(marker.get('stderr_log_count') or 0),
    )


def refresh_entry_progress(entry: dict[str, Any], now: float) -> tuple[bool, dict[str, Any]]:
    spec = entry['spec']
    campaign_dir = entry['campaign_dir']
    metadata = load_metadata(campaign_dir)
    snapshot: dict[str, Any] = {
        'dut': spec['dut'],
        'artifact_root': str(dut_root(spec['dut'])),
        'variant': spec.get('variant', spec.get('generator_variant', 'cascade')),
        'campaign_dir': str(campaign_dir),
        'metadata_present': metadata is not None,
        'completed_cases': None,
        'eligible_cases': None,
        'eligible_bapc_cases': None,
    }
    progressed = False
    if metadata is not None:
        validate_live_contract(entry, metadata)
        completed = int(metadata.get('completed_cases') or 0)
        eligible = int(metadata.get('eligible_cases') or 0)
        eligible_bapc = int(metadata.get('eligible_bapc_cases') or 0)
        snapshot.update(
            {
                'completed_cases': completed,
                'eligible_cases': eligible,
                'eligible_bapc_cases': eligible_bapc,
            }
        )
        if completed > entry['last_completed']:
            entry['last_completed'] = completed
            progressed = True
        if bool(metadata.get('any_round_failed')):
            raise RuntimeError(f"{spec['wave_name']} {spec['dut']} reports any_round_failed=true")
    if spec['kind'] == 'cascade':
        marker = cascade_progress_marker(campaign_dir)
        snapshot['artifact_progress'] = marker
        marker_tuple = _marker_tuple(marker)
        if marker_tuple != entry.get('last_progress_marker'):
            entry['last_progress_marker'] = marker_tuple
            if sum(marker_tuple or (0, 0, 0, 0)) > 0:
                progressed = True
    if progressed:
        entry['last_progress_time'] = now
    return progressed, snapshot


def kill_entry(entry: dict[str, Any]) -> None:
    proc = entry['proc']
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        time.sleep(3)
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def monitor_wave(wave_name: str, entries: list[dict[str, Any]]) -> None:
    last_heartbeat = 0.0
    while True:
        assert_frozen_inputs()
        all_done = True
        snapshots: list[dict[str, Any]] = []
        now = time.monotonic()
        for entry in entries:
            _, snapshot = refresh_entry_progress(entry, now)
            if snapshot.get('metadata_present') or entry['spec']['kind'] == 'cascade':
                snapshots.append(snapshot)
            if entry['proc'].poll() is None:
                all_done = False
                stale_limit = stale_limit_seconds(entry['spec'])
                if now - entry['last_progress_time'] > stale_limit:
                    raise RuntimeError(f"{wave_name} {entry['spec']['dut']} stalled for {int(now - entry['last_progress_time'])} seconds")
        if now - last_heartbeat >= 300:
            atomic_write_json(
                STATUS_PATH,
                {
                    'schema_version': '1.0',
                    'updated_utc': utcnow(),
                    'artifact_root': str(ARTIFACT_ROOT),
                    'source_sha': SOURCE_SHA,
                    'active_wave': wave_name,
                    'snapshots': snapshots,
                },
            )
            log(f'heartbeat {wave_name}: {json.dumps(snapshots, ensure_ascii=True)}')
            last_heartbeat = now
        if all_done:
            break
        time.sleep(30)


def validate_campaign(campaign_dir: Path) -> None:
    cmd = [sys.executable, 'scripts/evaluation/validation/validate_timeline.py', '--campaign', str(campaign_dir), '--defer-cross-campaign-artifact-manifest']
    proc = subprocess.run(cmd, cwd=WORKTREE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    out_path = campaign_dir / 'validation.stdout.log'
    out_path.write_text(proc.stdout, encoding='utf-8')
    if proc.returncode != 0:
        raise RuntimeError(f'timeline validation failed for {campaign_dir}: see {out_path}')


def aggregate_security_events_mode(wave: dict[str, Any], *, section: str) -> str:
    if section == '8.3-8.4' and str(wave.get('kind') or '') == 'cascade':
        return 'skip'
    return 'full'


def aggregate_experiment(dut: str, experiment_id: str, *, security_events_mode: str = 'full') -> None:
    cmd = [
        sys.executable,
        'scripts/evaluation/analysis/aggregate_results.py',
        '--artifact-root',
        str(dut_root(dut)),
        '--experiment-id',
        experiment_id,
    ]
    if security_events_mode != 'full':
        cmd.extend(['--security-events-mode', security_events_mode])
    proc = subprocess.run(cmd, cwd=WORKTREE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    out_path = ARTIFACT_ROOT / 'logs' / f'aggregate-{dut}-{experiment_id}.log'
    out_path.write_text(proc.stdout, encoding='utf-8')
    if proc.returncode != 0:
        raise RuntimeError(f'aggregate failed for {dut} {experiment_id}: see {out_path}')


def recompute_artifact_sha_manifest(root: Path) -> None:
    manifest_path = root / 'manifests' / 'artifact-sha256.txt'
    lines: list[str] = []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path == manifest_path:
            continue
        rel = path.relative_to(root).as_posix()
        lines.append(f'{sha256_file(path)}  {rel}')
    manifest_path.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='ascii')


def run_wave(wave: dict[str, Any], *, section: str) -> None:
    wave_name = wave['wave']
    seed = int(wave['seed'])
    entries: list[dict[str, Any]] = []
    for dut in ('rocket-clean', 'boom-clean', 'cva6-clean'):
        spec = {
            'dut': dut,
            'seed': seed,
            'kind': wave.get('kind', 'pmpfuzz'),
            'variant': wave.get('variant', 'bb-guided'),
            'generator_variant': wave.get('generator_variant', 'full'),
            'experiment_id': EXPERIMENT_834 if section == '8.3-8.4' else EXPERIMENT_85,
            'wave_name': wave_name,
        }
        entries.append(launch_campaign(spec, wave_name))
    log(f'started {wave_name} with {len(entries)} campaigns')
    try:
        monitor_wave(wave_name, entries)
    except Exception:
        for entry in entries:
            kill_entry(entry)
        raise
    finally:
        for entry in entries:
            entry['handle'].close()
    for entry in entries:
        rc = entry['proc'].wait()
        if rc != 0:
            raise RuntimeError(f"{wave_name} {entry['spec']['dut']} exited with {rc}")
        validate_campaign(entry['campaign_dir'])
    experiment_id = EXPERIMENT_834 if section == '8.3-8.4' else EXPERIMENT_85
    security_events_mode = aggregate_security_events_mode(wave, section=section)
    for dut in ('rocket-clean', 'boom-clean', 'cva6-clean'):
        aggregate_experiment(dut, experiment_id, security_events_mode=security_events_mode)
    log(f'completed {wave_name}')


def run_all_waves() -> None:
    for wave in WAVES_834:
        run_wave(wave, section='8.3-8.4')
    for wave in WAVES_85:
        run_wave(wave, section='8.5')


def main() -> int:
    args = parse_args()
    configure(args)
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        STATUS_PATH,
        {
            'schema_version': '1.0',
            'updated_utc': utcnow(),
            'artifact_root': str(ARTIFACT_ROOT),
            'source_sha': SOURCE_SHA,
            'state': 'starting',
        },
    )
    write_initial_manifests()
    run_selfcheck()
    run_all_waves()
    recompute_artifact_sha_manifest(ARTIFACT_ROOT)
    atomic_write_json(
        STATUS_PATH,
        {
            'schema_version': '1.0',
            'updated_utc': utcnow(),
            'artifact_root': str(ARTIFACT_ROOT),
            'source_sha': SOURCE_SHA,
            'state': 'complete',
        },
    )
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        log(f'FATAL: {exc}')
        atomic_write_json(
            STATUS_PATH,
            {
                'schema_version': '1.0',
                'updated_utc': utcnow(),
                'artifact_root': str(ARTIFACT_ROOT),
                'source_sha': SOURCE_SHA,
                'state': 'failed',
                'error': str(exc),
            },
        )
        raise
