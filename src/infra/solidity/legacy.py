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
    resolve_reference_contract_source_unit,
    resolve_reference_source_unit,
    resolve_staged_source_path,
    rewrite_imports_to_local_flat_files,
    unflatten_source_filename,
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
    target_source_unit: str = "",
    artifact_source_unit: str = "",
) -> tuple[str, str]:
    """Compile fixed source and return its exact target runtime artifact."""
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

    if reference_sources:
        target_unit = resolve_reference_source_unit(
            reference_sources=reference_sources,
            source_unit_hints=[target_source_unit],
            contract_name_hint=contract_name_hint,
        )
        resolved_artifact_unit = resolve_reference_contract_source_unit(
            reference_sources=reference_sources,
            contract_name=contract_name_hint,
        )
        if artifact_source_unit and artifact_source_unit != resolved_artifact_unit:
            raise RuntimeError(
                "trusted artifact source unit differs from the original verified bundle"
            )
        artifact_unit = resolved_artifact_unit
        compiler_sources = {
            name: {"content": fixed_code if name == target_unit else content}
            for name, content in reference_sources.items()
        }
        allow_unique_source_unit_fallback = target_unit == artifact_unit
    else:
        target_unit = "fix.sol"
        artifact_unit = target_unit
        compiler_sources = {target_unit: {"content": fixed_code}}
        allow_unique_source_unit_fallback = False

    solcx_error: RuntimeError | None = None
    try:
        compiled = solcx.compile_standard(
            {
                "language": "Solidity",
                "sources": compiler_sources,
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
            try:
                bytecode, contract_name = _extract_solc_runtime_artifact(
                    compiled,
                    target_source_unit=artifact_unit,
                    contract_name=contract_name_hint,
                    allow_unique_source_unit_fallback=allow_unique_source_unit_fallback,
                )
                return bytecode, contract_name
            except RuntimeError as exc:
                solcx_error = exc
    except solcx.exceptions.SolcError as exc:
        solcx_error = RuntimeError(str(exc))

    # Forge fallback includes reference sources so imports can resolve.
    forge_sources = {
        name: str(info.get("content", ""))
        for name, info in compiler_sources.items()
    }
    try:
        bc, cn = _forge_compile_fallback(
            forge_sources,
            compiler_version=normalized_version,
            contract_name_hint=contract_name_hint,
            target_file=artifact_unit,
            source_remappings=source_remappings,
            allow_unique_source_unit_fallback=allow_unique_source_unit_fallback,
        )
        return bc, cn
    except RuntimeError:
        pass

    raise solcx_error


def _runtime_bytecode_from_solc_artifact(artifact: object) -> str:
    if not isinstance(artifact, dict):
        return ""
    bytecode = artifact.get("evm", {}).get("deployedBytecode", {}).get("object", "")
    return str(bytecode) if bytecode else ""


def _extract_solc_runtime_artifact(
    compiled: dict,
    *,
    target_source_unit: str,
    contract_name: str,
    allow_unique_source_unit_fallback: bool = False,
) -> tuple[str, str]:
    if not contract_name:
        raise RuntimeError("missing target contract name")
    contracts = compiled.get("contracts", {}) if isinstance(compiled, dict) else {}
    file_contracts = contracts.get(target_source_unit, {}) if isinstance(contracts, dict) else {}
    artifact = file_contracts.get(contract_name, {}) if isinstance(file_contracts, dict) else {}
    bytecode = _runtime_bytecode_from_solc_artifact(artifact)
    if bytecode:
        return bytecode, contract_name

    if not allow_unique_source_unit_fallback:
        raise RuntimeError(
            f"no deployed bytecode produced for {target_source_unit}:{contract_name}"
        )

    fallback_artifacts = [
        (name, candidate_bytecode)
        for name, candidate_artifact in sorted(file_contracts.items())
        if (candidate_bytecode := _runtime_bytecode_from_solc_artifact(candidate_artifact))
    ] if isinstance(file_contracts, dict) else []
    if len(fallback_artifacts) != 1:
        raise RuntimeError(
            f"expected one deployed runtime artifact from {target_source_unit} "
            f"after {contract_name} was absent, found {len(fallback_artifacts)}"
        )
    fallback_name, fallback_bytecode = fallback_artifacts[0]
    return fallback_bytecode, fallback_name


def _pick_target_file(
    source_dir: Path,
    metadata: dict,
    contract_name_hint: str,
    target_source_unit: str = "",
) -> str:
    files = [
        str(item).strip()
        for item in metadata.get("files", [])
        if str(item).strip().endswith(".sol")
    ]
    if not files:
        files = [path.name for path in sorted(source_dir.glob("*.sol"))]

    explicit_target = str(target_source_unit or "").strip()
    if explicit_target:
        if explicit_target in files:
            return explicit_target
        explicit_name = normalize_staged_source_path(explicit_target).name
        basename_matches = []
        for file_name in files:
            direct_name = normalize_staged_source_path(file_name).name
            recovered_name = Path(unflatten_source_filename(Path(file_name).name)).name
            if explicit_name in {direct_name, recovered_name}:
                basename_matches.append(file_name)
        if len(basename_matches) == 1:
            return basename_matches[0]
        if len(basename_matches) > 1:
            raise RuntimeError(f"ambiguous target source unit: {explicit_target}")
        raise RuntimeError(f"target source unit not found: {explicit_target}")

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
    target_source_unit: str = "",
    artifact_source_unit: str = "",
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
    if not target_source_unit:
        raise RuntimeError("missing trusted patch source unit")
    if not artifact_source_unit:
        raise RuntimeError("missing trusted artifact source unit")

    target_file = _pick_target_file(
        source_dir,
        metadata,
        contract_name_hint,
        target_source_unit,
    )
    if not target_file:
        raise RuntimeError(f"could not infer target file for {case_id}")
    artifact_file = _pick_target_file(
        source_dir,
        metadata,
        contract_name_hint,
        artifact_source_unit,
    )
    if not artifact_file:
        raise RuntimeError(f"could not infer artifact source unit for {case_id}")
    same_logical_source_unit = target_source_unit == artifact_source_unit
    if not same_logical_source_unit and target_file == artifact_file:
        raise RuntimeError(
            "distinct trusted source units collapse to one cached Solidity source file"
        )
    allow_unique_source_unit_fallback = (
        same_logical_source_unit and target_file == artifact_file
    )

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
        content = fixed_code if file_name == target_file else path.read_text(errors="replace")
        content = rewrite_imports_to_local_flat_files(
            content,
            available_files=available_files,
        )
        if file_name in sources:
            raise RuntimeError(f"duplicate Solidity source unit: {file_name}")
        sources[file_name] = {"content": content}

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
            try:
                bytecode, compiled_contract_name = _extract_solc_runtime_artifact(
                    compiled,
                    target_source_unit=artifact_file,
                    contract_name=contract_name,
                    allow_unique_source_unit_fallback=allow_unique_source_unit_fallback,
                )
                return bytecode, compiler_version, compiled_contract_name
            except RuntimeError as exc:
                solcx_error = exc
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
            target_file=artifact_file,
            source_dir=source_dir,
            allow_unique_source_unit_fallback=allow_unique_source_unit_fallback,
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
    *,
    allow_unique_source_unit_fallback: bool = False,
) -> tuple[str, str]:
    """Return the exact source-unit and contract artifact from Forge output."""
    if not target_file or not contract_name_hint:
        raise RuntimeError("missing exact Forge artifact identity")
    expected_source = f"src/{normalize_staged_source_path(target_file).as_posix()}"
    exact_matches: list[tuple[str, str]] = []
    source_unit_matches: list[tuple[str, str]] = []

    for artifact_file in sorted(out_dir.glob("*/*.json")):
        try:
            artifact = json.loads(artifact_file.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        metadata = artifact.get("metadata", {}) if isinstance(artifact, dict) else {}
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {}
        if not isinstance(metadata, dict):
            continue
        settings = metadata.get("settings", {})
        compilation_target = (
            settings.get("compilationTarget", {}) if isinstance(settings, dict) else {}
        )
        if not isinstance(compilation_target, dict) or len(compilation_target) != 1:
            continue
        artifact_source, artifact_contract = next(iter(compilation_target.items()))
        if artifact_source != expected_source or not isinstance(artifact_contract, str):
            continue
        bytecode = artifact.get("deployedBytecode", {}).get("object", "")
        if not isinstance(bytecode, str) or not bytecode or bytecode == "0x":
            continue
        normalized_bytecode = bytecode[2:] if bytecode.startswith("0x") else bytecode
        match = (normalized_bytecode, artifact_contract)
        source_unit_matches.append(match)
        if artifact_contract == contract_name_hint:
            exact_matches.append(match)

    if len(exact_matches) == 1:
        return exact_matches[0]
    if len(exact_matches) > 1:
        raise RuntimeError(
            f"expected one Forge artifact for {target_file}:{contract_name_hint}, "
            f"found {len(exact_matches)}"
        )
    if not allow_unique_source_unit_fallback:
        raise RuntimeError(
            f"no deployed bytecode produced for {target_file}:{contract_name_hint}"
        )
    if len(source_unit_matches) != 1:
        raise RuntimeError(
            f"expected one deployed Forge runtime artifact from {target_file} "
            f"after {contract_name_hint} was absent, found {len(source_unit_matches)}"
        )
    return source_unit_matches[0]


def _forge_compile_fallback(
    sources: dict[str, str],
    *,
    compiler_version: str,
    contract_name_hint: str,
    target_file: str = "",
    source_dir: Path | None = None,
    source_remappings: list[str] | None = None,
    allow_unique_source_unit_fallback: bool = False,
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
        solc_binary = get_or_install_solc(solc_ver)
        if not solc_binary:
            raise RuntimeError(f"failed to resolve solc {solc_ver}")
        foundry_toml = tmp_dir / "foundry.toml"
        foundry_toml.write_text(
            f'[profile.default]\nsrc = "src"\nout = "out"\nsolc = "{solc_binary}"\n'
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

        return _extract_bytecode_from_forge_out(
            out_dir,
            contract_name_hint,
            target_file,
            allow_unique_source_unit_fallback=allow_unique_source_unit_fallback,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
