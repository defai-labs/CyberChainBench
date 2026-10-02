"""Helpers for compiling legacy Solidity contracts outside the Foundry workspace."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from infra.chain.metadata import resolve_case_source_metadata
from infra.foundry.exploit_runner import _build_foundry_env, _resolve_forge_bin
from infra.solidity.fixed_sources import (
    normalize_staged_source_path,
    resolve_staged_source_path,
    rewrite_imports_to_local_flat_files,
)
from infra.solidity.solc_resolver import (
    extract_solc_version,
    get_or_install_solc,
    infer_solc_version_from_source_text,
    normalize_supported_solc_version,
)
from project_layout import resolve_repo_path


def normalize_solc_version(version_text: str) -> str:
    return extract_solc_version(version_text)


def is_legacy_solidity(version_text: str) -> bool:
    normalized = normalize_solc_version(version_text)
    if not normalized:
        return False
    major, minor, _patch = (int(part) for part in normalized.split("."))
    return (major, minor) < (0, 8)


def normalize_supported_legacy_version(version_text: str) -> str:
    return normalize_supported_solc_version(version_text)


def infer_solc_version_from_source(source_text: str) -> str:
    return infer_solc_version_from_source_text(source_text)


def compile_fixed_bytecode_from_source(
    *,
    fixed_code: str,
    contract_name_hint: str,
    compiler_version: str,
    optimization_used: bool = True,
    optimization_runs: int = 200,
    evm_version: str = "",
    reference_sources: dict[str, str] | None = None,
    source_remappings: list[str] | None = None,
) -> tuple[str, str]:
    """Compile a standalone fixed contract and return (runtime_bytecode, contract_name)."""
    try:
        import solcx
    except ImportError as exc:  # pragma: no cover - env dependent
        raise RuntimeError("py-solc-x is not installed") from exc

    normalized_version = normalize_supported_legacy_version(compiler_version)
    if not normalized_version:
        raise RuntimeError("missing compiler version")

    solc_binary = get_or_install_solc(normalized_version)
    if not solc_binary:
        raise RuntimeError(f"failed to resolve solc {normalized_version}")

    settings: dict = {
        "optimizer": {"enabled": optimization_used, "runs": optimization_runs},
        "outputSelection": {"*": {"*": ["evm.deployedBytecode.object"]}},
    }
    if evm_version and evm_version.lower() not in ("", "default"):
        settings["evmVersion"] = evm_version

    solcx_error: RuntimeError | None = None
    try:
        compiled = solcx.compile_standard(
            {
                "language": "Solidity",
                "sources": {"fix.sol": {"content": fixed_code}},
                "settings": settings,
            },
            solc_binary=solc_binary,
        )

        errors = compiled.get("errors", []) if isinstance(compiled, dict) else []
        fatal_errors = [
            error.get("formattedMessage", error.get("message", ""))
            for error in errors
            if isinstance(error, dict) and error.get("severity") == "error"
        ]
        if fatal_errors:
            solcx_error = RuntimeError("\n".join(fatal_errors))
        else:
            file_contracts = (compiled.get("contracts", {}) or {}).get("fix.sol", {})
            if not isinstance(file_contracts, dict) or not file_contracts:
                solcx_error = RuntimeError("no contracts compiled from fixed source")
            else:
                if contract_name_hint and contract_name_hint in file_contracts:
                    artifact = file_contracts[contract_name_hint]
                    bytecode = artifact.get("evm", {}).get("deployedBytecode", {}).get("object", "")
                    if bytecode:
                        return bytecode, contract_name_hint

                # Prefer actual contracts over libraries (by bytecode size as proxy)
                candidates = []
                for name, artifact in file_contracts.items():
                    if not isinstance(artifact, dict):
                        continue
                    bytecode = artifact.get("evm", {}).get("deployedBytecode", {}).get("object", "")
                    if bytecode:
                        candidates.append((len(bytecode), name, bytecode))
                if candidates:
                    candidates.sort(reverse=True)
                    return candidates[0][2], candidates[0][1]

                solcx_error = RuntimeError("no deployed bytecode produced from fixed source")
    except solcx.exceptions.SolcError as exc:
        solcx_error = RuntimeError(str(exc))

    # Forge fallback — include reference sources so imports can resolve
    forge_sources = {"fix.sol": fixed_code}
    if reference_sources:
        for name, content in reference_sources.items():
            if name not in forge_sources:
                forge_sources[name] = content
    try:
        bc, cn = _forge_compile_fallback(
            forge_sources,
            compiler_version=normalized_version,
            contract_name_hint=contract_name_hint,
            target_file="fix.sol",
            source_remappings=source_remappings,
        )
        return bc, cn
    except RuntimeError:
        pass

    raise solcx_error


def _pick_target_file(source_dir: Path, metadata: dict, contract_name_hint: str) -> str:
    files = [
        str(item).strip()
        for item in metadata.get("files", [])
        if str(item).strip().endswith(".sol")
    ]
    if not files:
        files = [path.name for path in sorted(source_dir.glob("*.sol"))]

    if len(files) == 1:
        return files[0]

    target_names = [contract_name_hint, str(metadata.get("contract_name", "")).strip()]
    for target_name in target_names:
        if not target_name:
            continue
        for file_name in files:
            stem = Path(file_name).stem
            if stem == target_name or target_name.lower() in stem.lower():
                return file_name

    return files[0] if files else ""


def compile_dfhl_fixed_bytecode(
    *,
    base_dir: Path,
    case_id: str,
    fixed_code: str,
    contract_name_hint: str,
    source_metadata: dict | None = None,
) -> tuple[str, str, str]:
    """Compile a legacy fixed contract and return (runtime_bytecode, compiler_version, contract_name)."""
    try:
        import solcx
    except ImportError as exc:  # pragma: no cover - env dependent
        raise RuntimeError("py-solc-x is not installed") from exc

    metadata = resolve_case_source_metadata(case_id, base_dir, contract_name_hint=contract_name_hint, explicit_metadata=source_metadata or {})
    source_dir_text = str(metadata.get("source_dir", "")).strip()
    compiler_version = normalize_supported_legacy_version(str(metadata.get("compiler_version", "")))
    if not source_dir_text or not compiler_version:
        raise RuntimeError(f"missing source metadata for {case_id}")

    source_dir = resolve_repo_path(base_dir, source_dir_text)
    if not source_dir.exists():
        raise RuntimeError(f"missing source directory for {case_id}: {source_dir}")

    target_file = _pick_target_file(source_dir, metadata, contract_name_hint)
    if not target_file:
        raise RuntimeError(f"could not infer target file for {case_id}")

    available_files = [
        str(item).strip()
        for item in metadata.get("files", [])
        if str(item).strip().endswith(".sol")
    ]
    if not available_files:
        available_files = [path.name for path in sorted(source_dir.glob("*.sol"))]

    sources: dict[str, dict[str, str]] = {}
    for file_name in available_files:
        path = source_dir / file_name
        if not path.exists():
            continue
        content = fixed_code if path.name == target_file else path.read_text(errors="replace")
        content = rewrite_imports_to_local_flat_files(
            content,
            available_files=available_files,
        )
        sources[path.name] = {"content": content}

    solc_binary = get_or_install_solc(compiler_version)
    if not solc_binary:
        raise RuntimeError(f"failed to resolve solc {compiler_version}")

    solcx_error: RuntimeError | None = None
    try:
        compiled = solcx.compile_standard(
            {
                "language": "Solidity",
                "sources": sources,
                "settings": {
                    "optimizer": {"enabled": True, "runs": 200},
                    "outputSelection": {"*": {"*": ["evm.deployedBytecode.object"]}},
                },
            },
            solc_binary=solc_binary,
        )

        errors = compiled.get("errors", []) if isinstance(compiled, dict) else []
        fatal_errors = [
            error.get("formattedMessage", error.get("message", ""))
            for error in errors
            if isinstance(error, dict) and error.get("severity") == "error"
        ]
        if fatal_errors:
            solcx_error = RuntimeError("\n".join(fatal_errors))
        else:
            contract_name = contract_name_hint or str(metadata.get("contract_name", "")).strip()
            contracts = compiled.get("contracts", {}) if isinstance(compiled, dict) else {}
            preferred_files = [target_file] + [name for name in contracts.keys() if name != target_file]
            for file_name in preferred_files:
                file_contracts = contracts.get(file_name, {})
                if not isinstance(file_contracts, dict):
                    continue
                if contract_name and contract_name in file_contracts:
                    bytecode = (
                        file_contracts[contract_name]
                        .get("evm", {})
                        .get("deployedBytecode", {})
                        .get("object", "")
                    )
                    if bytecode:
                        return bytecode, compiler_version, contract_name
                for name, artifact in file_contracts.items():
                    if not isinstance(artifact, dict):
                        continue
                    bytecode = artifact.get("evm", {}).get("deployedBytecode", {}).get("object", "")
                    if bytecode:
                        return bytecode, compiler_version, name
            solcx_error = RuntimeError(f"no deployed bytecode produced for {case_id}")
    except solcx.exceptions.SolcError as exc:
        solcx_error = RuntimeError(str(exc))

    # Forge fallback: when solcx fails, try forge build which handles
    # import remappings and type resolution better
    try:
        flat_sources = {name: info["content"] for name, info in sources.items()}
        bc, cn = _forge_compile_fallback(
            flat_sources,
            compiler_version=compiler_version,
            contract_name_hint=contract_name_hint or str(metadata.get("contract_name", "")).strip(),
            target_file=target_file,
            source_dir=source_dir,
        )
        return bc, compiler_version, cn
    except RuntimeError:
        pass

    raise solcx_error


_LOCAL_IMPORT_RE = re.compile(r'import\s+(?:[^"\']+\s+from\s+)?["\']\.\/([^"\']+)["\']')


def _discover_transitive_imports(
    seed_files: dict[str, str],
    source_dir: Path | None,
) -> dict[str, str]:
    """Expand *seed_files* with any transitively imported local files from *source_dir*."""
    if source_dir is None or not source_dir.exists():
        return seed_files

    all_available = sorted([f.name for f in source_dir.glob("*.sol")])
    result = dict(seed_files)
    pending = set(seed_files.keys())
    processed: set[str] = set()

    while pending - processed:
        current = (pending - processed).pop()
        processed.add(current)
        content = result.get(current, "")
        rewritten = rewrite_imports_to_local_flat_files(content, available_files=all_available)
        result[current] = rewritten
        for m in _LOCAL_IMPORT_RE.finditer(rewritten):
            dep = m.group(1)
            if dep not in result:
                dep_path = source_dir / dep
                if dep_path.exists():
                    result[dep] = dep_path.read_text(errors="replace")
                    pending.add(dep)
    return result


_AT_IMPORT_RE = re.compile(r'"(@[^/]+/[^/"]+)')


def _extract_npm_packages(error_text: str) -> list[str]:
    """Extract @scope/package names from forge/solc 'not found' errors."""
    packages: list[str] = []
    seen: set[str] = set()
    for m in _AT_IMPORT_RE.finditer(error_text):
        pkg = m.group(1)
        if pkg not in seen:
            seen.add(pkg)
            packages.append(pkg)
    return packages


_OZ_VERSION_BY_SOLC = {
    (0, 5): "@openzeppelin/contracts@2.5.1",
    (0, 6): "@openzeppelin/contracts@3.4.2",
    (0, 7): "@openzeppelin/contracts@4.9.6",
    (0, 8): "@openzeppelin/contracts@4.9.6",
}
_OZ_UPGRADEABLE_VERSION_BY_SOLC = {
    (0, 6): "@openzeppelin/contracts-upgradeable@3.4.2",
    (0, 7): "@openzeppelin/contracts-upgradeable@4.9.5",
    (0, 8): "@openzeppelin/contracts-upgradeable@4.9.5",
}


def _pin_oz_version(packages: list[str], compiler_version: str) -> list[str]:
    """Pin @openzeppelin packages to a version compatible with the target solc."""
    normalized = extract_solc_version(compiler_version)
    if not normalized:
        return packages
    parts = normalized.split(".")
    key = (int(parts[0]), int(parts[1]))

    result = []
    for pkg in packages:
        if pkg == "@openzeppelin/contracts":
            pinned = _OZ_VERSION_BY_SOLC.get(key, pkg)
            result.append(pinned)
        elif pkg == "@openzeppelin/contracts-upgradeable":
            pinned = _OZ_UPGRADEABLE_VERSION_BY_SOLC.get(key, pkg)
            result.append(pinned)
        else:
            result.append(pkg)
    return result


def _npm_install(tmp_dir: Path, packages: list[str], compiler_version: str = "") -> None:
    """Install npm packages into node_modules/ (forge resolves via libs config)."""
    if not packages:
        return
    packages = _pin_oz_version(packages, compiler_version)
    subprocess.run(
        ["npm", "init", "-y"],
        cwd=tmp_dir, capture_output=True, timeout=15,
    )
    result = subprocess.run(
        ["npm", "install", "--save", *packages],
        cwd=tmp_dir, capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"npm install failed: {(result.stderr or result.stdout)[-300:]}")


def _extract_bytecode_from_forge_out(
    out_dir: Path,
    contract_name_hint: str,
    target_file: str,
) -> tuple[str, str]:
    """Search forge build artifacts for deployed bytecode. Returns (hex_bytecode, contract_name)."""
    search_order = []
    if contract_name_hint:
        search_order.append(contract_name_hint)
    if target_file:
        stem = Path(target_file).stem
        if stem != contract_name_hint:
            search_order.append(stem)

    # First pass: look for preferred contract names
    for artifact_dir in sorted(out_dir.iterdir()):
        if not artifact_dir.is_dir():
            continue
        for artifact_file in sorted(artifact_dir.glob("*.json")):
            art_name = artifact_file.stem
            try:
                artifact = json.loads(artifact_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            bytecode = (
                artifact.get("deployedBytecode", {}).get("object", "")
                or artifact.get("bytecode", {}).get("object", "")
            )
            if not bytecode or bytecode == "0x" or len(bytecode) < 10:
                continue
            bc = bytecode[2:] if bytecode.startswith("0x") else bytecode
            if art_name in search_order:
                return bc, art_name

    # Second pass: take any contract with bytecode
    for artifact_dir in sorted(out_dir.iterdir()):
        if not artifact_dir.is_dir():
            continue
        for artifact_file in sorted(artifact_dir.glob("*.json")):
            art_name = artifact_file.stem
            try:
                artifact = json.loads(artifact_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            bytecode = (
                artifact.get("deployedBytecode", {}).get("object", "")
                or artifact.get("bytecode", {}).get("object", "")
            )
            if not bytecode or bytecode == "0x" or len(bytecode) < 10:
                continue
            bc = bytecode[2:] if bytecode.startswith("0x") else bytecode
            return bc, art_name

    raise RuntimeError("forge build succeeded but no deployed bytecode found in artifacts")


def _forge_compile_fallback(
    sources: dict[str, str],
    *,
    compiler_version: str,
    contract_name_hint: str,
    target_file: str = "",
    source_dir: Path | None = None,
    source_remappings: list[str] | None = None,
) -> tuple[str, str]:
    """Forge-based compilation fallback when solcx fails.

    Creates a temporary forge project, stages all source files, runs ``forge build``,
    and extracts the deployed bytecode. If the first build fails due to missing
    @-scoped imports, auto-installs them via npm and retries.

    Returns (runtime_bytecode_hex, contract_name).
    """
    sources = _discover_transitive_imports(sources, source_dir)

    tmp_dir = Path(tempfile.mkdtemp(prefix="forge_legacy_"))
    try:
        src_dir = tmp_dir / "src"
        src_dir.mkdir()
        destinations: set[Path] = set()
        for name, content in sources.items():
            dest = resolve_staged_source_path(src_dir, name)
            if dest in destinations:
                raise RuntimeError(f"duplicate staged Solidity source path: {name}")
            destinations.add(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)

        solc_ver = normalize_supported_solc_version(compiler_version) or "0.6.12"
        foundry_toml = tmp_dir / "foundry.toml"
        foundry_toml.write_text(
            f'[profile.default]\nsrc = "src"\nout = "out"\nsolc = "{solc_ver}"\n'
            f'auto_detect_solc = false\nlibs = ["node_modules"]\n'
        )

        # Build remappings: start with original verified-source remappings,
        # then auto-generate from source paths for any missing prefixes.
        remappings: list[str] = []
        covered_prefixes: set[str] = set()
        if source_remappings:
            for r in source_remappings:
                if "=" not in r:
                    continue
                lhs, rhs = r.split("=", 1)
                if not rhs.startswith("src/"):
                    rhs = "src/" + rhs.lstrip("/")
                remappings.append(f"{lhs}={rhs}")
                covered_prefixes.add(lhs.rstrip("/"))
        for name in sources:
            parts = normalize_staged_source_path(name).parts
            if parts[0].startswith("@"):
                scope = parts[0]
                if scope not in covered_prefixes:
                    covered_prefixes.add(scope)
                    remappings.append(f"{scope}/=src/{scope}/")
                rooted_scope = f"/{scope}"
                if str(name).startswith("/") and rooted_scope not in covered_prefixes:
                    covered_prefixes.add(rooted_scope)
                    remappings.append(f"{rooted_scope}/=src/{scope}/")
            elif str(name).startswith("/"):
                root_prefix = f"/{parts[0]}"
                if root_prefix not in covered_prefixes:
                    covered_prefixes.add(root_prefix)
                    if len(parts) == 1:
                        remappings.append(f"{root_prefix}=src/{parts[0]}")
                    else:
                        remappings.append(f"{root_prefix}/=src/{parts[0]}/")
            elif parts[0] == "node_modules" and len(parts) > 1:
                scope = parts[1] if parts[1].startswith("@") else None
                if scope and scope not in covered_prefixes:
                    covered_prefixes.add(scope)
                    remappings.append(f"{scope}/=src/node_modules/{scope}/")
            elif parts[0] not in ("fix.sol", "") and "/" in name and parts[0] not in covered_prefixes:
                covered_prefixes.add(parts[0])
                remappings.append(f"{parts[0]}/=src/{parts[0]}/")
        if remappings:
            (tmp_dir / "remappings.txt").write_text("\n".join(remappings) + "\n")

        # Pre-scan all source files for @-scoped imports and install them upfront
        all_source_text = "\n".join(sources.values())
        pre_packages = _extract_npm_packages(all_source_text)
        if pre_packages:
            _npm_install(tmp_dir, pre_packages, compiler_version)

        foundry_env = _build_foundry_env()
        forge_bin = _resolve_forge_bin(foundry_env)

        result = subprocess.run(
            [forge_bin, "build"],
            cwd=tmp_dir,
            capture_output=True,
            text=True,
            timeout=120,
            env=foundry_env,
        )

        # If build still fails due to missing @-scoped imports, try extracting from error
        if result.returncode != 0:
            error_text = result.stderr or result.stdout
            extra_packages = [p for p in _extract_npm_packages(error_text) if p not in (pre_packages or [])]
            if extra_packages:
                _npm_install(tmp_dir, (pre_packages or []) + extra_packages, compiler_version)
                result = subprocess.run(
                    [forge_bin, "build"],
                    cwd=tmp_dir,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    env=foundry_env,
                )

        if result.returncode != 0:
            raise RuntimeError(f"forge build failed: {(result.stderr or result.stdout)[-500:]}")

        out_dir = tmp_dir / "out"
        if not out_dir.exists():
            raise RuntimeError("forge build produced no output directory")

        return _extract_bytecode_from_forge_out(out_dir, contract_name_hint, target_file)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
