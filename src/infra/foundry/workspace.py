"""Helpers for preparing isolated Foundry workspaces used during evaluation."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterable

from infra.chain.metadata import resolve_rpc_url
from project_layout import (
    DEFIHACKLABS_DIR,
    EXPLOIT_WORKSPACE_DIR,
    PATCH_WORKSPACE_DIR,
    resolve_repo_path,
)

_WORKSPACE_PROFILE = """[profile.default]
src = 'src'
test = 'src'
libs = ['lib']
solc = '0.8.20'
auto_detect_solc = true
evm_version = 'shanghai'

# Keep CI noise down.
verbosity = 2
"""

_RPC_ALIAS_TO_CHAIN = {
    "ethereum": "ethereum",
    "mainnet": "ethereum",
    "eth": "ethereum",
    "bsc": "bsc",
    "bnb": "bsc",
    "base": "base",
    "fantom": "fantom",
    "ftm": "fantom",
}

_DEFAULT_PUBLIC_RPC_ENDPOINTS = {
    "ethereum": "https://ethereum.publicnode.com",
    "mainnet": "https://ethereum.publicnode.com",
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc.publicnode.com",
    "bnb": "https://bsc.publicnode.com",
    "base": "https://base.publicnode.com",
    "fantom": "https://rpcapi.fantom.network",
    "ftm": "https://rpcapi.fantom.network",
}

_TRANSIENT_SRC_DIRS = ("_benchmark_eval",)
WORKSPACE_OWNER_FILE = ".owner_pid"


def _reset_workspace_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _foundry_task_root(task: str) -> Path:
    task_name = str(task or "").strip().lower()
    if task_name.startswith("patch") or task_name.startswith("fix"):
        return PATCH_WORKSPACE_DIR
    return EXPLOIT_WORKSPACE_DIR


def _shared_foundry_workspace_dir(task: str) -> Path:
    return _foundry_task_root(task) / "_foundry_shared"


def _isolated_foundry_workspace_dir(task: str, case_id: str) -> Path:
    return _foundry_task_root(task) / _workspace_slug(case_id) / "foundry"


def _workspace_rpc_endpoint(alias: str) -> str:
    chain = _RPC_ALIAS_TO_CHAIN.get(alias, alias)
    return resolve_rpc_url(chain) or _DEFAULT_PUBLIC_RPC_ENDPOINTS.get(alias, "")


def _render_workspace_foundry_toml() -> str:
    lines = [_WORKSPACE_PROFILE.rstrip(), "", "[rpc_endpoints]"]
    for alias in ("ethereum", "mainnet", "eth", "bsc", "bnb", "base", "fantom", "ftm"):
        endpoint = _workspace_rpc_endpoint(alias)
        if not endpoint:
            continue
        lines.append(f'{alias} = "{endpoint}"')
    return "\n".join(lines).rstrip() + "\n"


def _ensure_workspace_foundry_config(workspace: Path) -> None:
    foundry_toml = workspace / "foundry.toml"
    desired = _render_workspace_foundry_toml()
    if foundry_toml.exists() and foundry_toml.read_text() == desired:
        return
    foundry_toml.write_text(desired)


def write_structured_source_remappings(
    workspace: Path,
    test_dir_rel: str,
    scoped_prefixes: set[str],
) -> None:
    """Append import remappings pointing into the structured source tree."""
    if not scoped_prefixes:
        return
    lines: list[str] = []
    for prefix in sorted(scoped_prefixes):
        if prefix.startswith("/") and prefix.endswith(".sol"):
            source_name = prefix
            lines.append(f"{source_name}=src/{test_dir_rel}/{source_name.lstrip('/')}")
        else:
            staged_prefix = prefix.lstrip("/")
            lines.append(f"{prefix}/=src/{test_dir_rel}/{staged_prefix}/")
    remappings_path = workspace / "remappings.txt"
    existing = remappings_path.read_text().rstrip("\n") if remappings_path.exists() else ""
    new_block = "\n".join(lines)
    combined = f"{existing}\n{new_block}\n" if existing else f"{new_block}\n"
    remappings_path.write_text(combined)


def _ensure_workspace_src_root(workspace: Path) -> None:
    src_dir = workspace / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    for transient in _TRANSIENT_SRC_DIRS:
        shutil.rmtree(src_dir / transient, ignore_errors=True)


def _ensure_workspace_dfhl_test_tree(base_dir: Path, workspace: Path) -> None:
    target_root = workspace / "src" / "test"
    target_root.mkdir(parents=True, exist_ok=True)


def _ensure_workspace_forge_std_dependency(base_dir: Path, workspace: Path) -> None:
    lib_dir = workspace / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    source = resolve_repo_path(base_dir, DEFIHACKLABS_DIR) / "lib" / "forge-std"
    target = lib_dir / "forge-std"
    if not source.exists():
        return

    desired_rel = os.path.relpath(source, start=lib_dir)

    if target.is_symlink():
        current = os.readlink(target)
        if current != desired_rel and target.exists():
            target.unlink()
        elif current == desired_rel:
            return
        else:
            target.unlink()

    if target.exists():
        return

    try:
        target.symlink_to(desired_rel, target_is_directory=True)
    except OSError:
        shutil.copytree(source, target, dirs_exist_ok=True)


def _workspace_slug(value: str) -> str:
    text = "".join(ch if ch.isalnum() else "_" for ch in str(value or "").strip())
    return text.strip("_") or "case"


def _read_workspace_owner_pid(workspace_dir: Path) -> int | None:
    marker = workspace_dir / WORKSPACE_OWNER_FILE
    if not marker.exists():
        return None
    try:
        return int(marker.read_text().strip())
    except (OSError, ValueError):
        return None


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def ensure_eval_workspace(base_dir: Path, *, task: str = "exploit") -> Path | None:
    """Ensure eval_workspace exists and its forge-std dependency resolves.

    The local workspace historically used an absolute symlink:
    `tmp/exploit/_foundry_shared/lib/forge-std -> /abs/path/.../data/sources/DeFiHackLabs/lib/forge-std`
    which breaks after rsyncing to a remote host. Normalize that dependency into a
    relative symlink (or a copied directory as fallback) before exploit/fix runs.
    """
    workspace = base_dir / _shared_foundry_workspace_dir(task)
    workspace.mkdir(parents=True, exist_ok=True)

    _ensure_workspace_foundry_config(workspace)
    _ensure_workspace_src_root(workspace)
    _ensure_workspace_dfhl_test_tree(base_dir, workspace)
    _ensure_workspace_forge_std_dependency(base_dir, workspace)

    return workspace


def create_isolated_eval_workspace(base_dir: Path, *, task: str, case_id: str) -> Path | None:
    template = ensure_eval_workspace(base_dir, task=task)
    if template is None:
        return None

    workspace = base_dir / _isolated_foundry_workspace_dir(task, case_id)
    _reset_workspace_dir(workspace)
    _ensure_workspace_foundry_config(workspace)
    _ensure_workspace_src_root(workspace)
    _ensure_workspace_dfhl_test_tree(base_dir, workspace)
    _ensure_workspace_forge_std_dependency(base_dir, workspace)
    (workspace / WORKSPACE_OWNER_FILE).write_text(f"{os.getpid()}\n")
    return workspace


def cleanup_isolated_eval_workspace(workspace: Path | None) -> None:
    if workspace is None:
        return
    shutil.rmtree(workspace, ignore_errors=True)


def cleanup_isolated_eval_workspaces(
    base_dir: Path,
    *,
    include_owner_pids: Iterable[int] | None = None,
) -> int:
    forced_owner_pids = {int(pid) for pid in (include_owner_pids or []) if int(pid) > 0}
    removed = 0

    for task_root in (
        (base_dir / EXPLOIT_WORKSPACE_DIR).resolve(),
        (base_dir / PATCH_WORKSPACE_DIR).resolve(),
    ):
        if not task_root.exists():
            continue
        for case_dir in list(task_root.iterdir()):
            if not case_dir.is_dir() or case_dir.name.startswith("_foundry_"):
                continue
            child = case_dir / "foundry"
            if not child.exists():
                continue
            owner_pid = _read_workspace_owner_pid(child)
            if owner_pid is not None and owner_pid in forced_owner_pids:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
                continue
            if owner_pid is not None and _pid_is_running(owner_pid):
                continue
            shutil.rmtree(child, ignore_errors=True)
            removed += 1

    return removed


def cleanup_eval_workspace_runtime_artifacts(base_dir: Path) -> int:
    removed = 0
    for workspace in (
        (base_dir / _shared_foundry_workspace_dir("exploit")).resolve(),
        (base_dir / _shared_foundry_workspace_dir("patch")).resolve(),
    ):
        if not workspace.exists():
            continue
        for target in (
            workspace / "cache",
            workspace / "out",
            workspace / "src" / "_benchmark_eval",
        ):
            if not target.exists():
                continue
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            else:
                target.unlink(missing_ok=True)
            removed += 1

        _ensure_workspace_src_root(workspace)
    return removed


def cleanup_foundry_eval_tmp(
    base_dir: Path,
    *,
    include_owner_pids: Iterable[int] | None = None,
) -> int:
    removed = cleanup_isolated_eval_workspaces(
        base_dir,
        include_owner_pids=include_owner_pids,
    )
    removed += cleanup_eval_workspace_runtime_artifacts(base_dir)
    return removed
