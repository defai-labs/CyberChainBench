"""Helpers for staging patched Solidity sources for Forge compilation."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

_IMPORT_RE = re.compile(r'(import\s+(?:[^"\']+\s+from\s+)?["\'])([^"\']+)(["\'])')
_CONTRACT_DECLARATION_RE = re.compile(
    r"(?<![A-Za-z0-9_$])"
    r"(?:abstract\s+)?(?:contract|library|interface)\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)(?![A-Za-z0-9_$])",
)
_SOLIDITY_COMMENT_OR_STRING_RE = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)


def _declared_contract_names(source: str) -> set[str]:
    def _erase(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    stripped = _SOLIDITY_COMMENT_OR_STRING_RE.sub(_erase, str(source or ""))
    return {
        match.group("name")
        for match in _CONTRACT_DECLARATION_RE.finditer(stripped)
    }


def normalize_staged_source_path(source_path: str) -> PurePosixPath:
    """Normalize one explorer source name to a confined relative path."""
    text = str(source_path)
    if not text or "\x00" in text:
        raise RuntimeError("invalid empty Solidity source path")
    if text.startswith("//") or "\\" in text or re.match(r"^/*[A-Za-z]:", text):
        raise RuntimeError(f"unsupported Solidity source path: {text}")

    relative = PurePosixPath(text.lstrip("/"))
    if not relative.parts or any(part == ".." for part in relative.parts):
        raise RuntimeError(f"unsafe Solidity source path: {text}")
    return relative


def resolve_staged_source_path(target_dir: Path, source_path: str) -> Path:
    """Resolve an explorer source name beneath *target_dir*.

    Solidity standard-json inputs may use root-relative logical names such as
    ``/contracts/Token.sol``.  Those names are not host filesystem paths.  Drop
    their leading slash while rejecting traversal and path collisions outside
    the staging root.
    """
    relative = normalize_staged_source_path(source_path)

    root = target_dir.resolve()
    destination = target_dir.joinpath(*relative.parts)
    try:
        destination.resolve().relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"unsafe Solidity source path: {source_path}") from exc
    return destination


def resolve_reference_source_unit(
    *,
    reference_sources: dict[str, str],
    source_unit_hints: list[str] | None = None,
    contract_name_hint: str = "",
) -> str:
    """Resolve one exact source-unit key without relying on mapping order.

    Explorer standard-json keys are compiler identities, not host paths.  A
    public case file hint may name either the complete unit or its basename.
    When no file hint identifies a unique unit, the explorer contract name may
    identify the one unit that declares it.  Ambiguity is an error because
    replacing or selecting a different source unit changes the graded program.
    """
    if not reference_sources:
        raise RuntimeError("verified source bundle is empty")

    keys = list(reference_sources)

    resolved_hints: list[str] = []
    supplied_hints = [str(item or "").strip() for item in (source_unit_hints or [])]
    supplied_hints = [item for item in supplied_hints if item]
    for hint in supplied_hints:
        try:
            normalized_hint = normalize_staged_source_path(hint)
        except RuntimeError as exc:
            raise RuntimeError(f"invalid verified source-unit hint: {hint}") from exc
        if hint in reference_sources:
            resolved_hints.append(hint)
            continue
        normalized_matches = [
            key
            for key in keys
            if normalize_staged_source_path(key) == normalized_hint
        ]
        if len(normalized_matches) == 1:
            resolved_hints.append(normalized_matches[0])
            continue
        if len(normalized_matches) > 1:
            raise RuntimeError(f"ambiguous verified source-unit hint: {hint}")

        basename = normalized_hint.name
        basename_matches = [
            key
            for key in keys
            if normalize_staged_source_path(key).name == basename
        ]
        if len(basename_matches) == 1:
            resolved_hints.append(basename_matches[0])
            continue
        if len(basename_matches) > 1:
            raise RuntimeError(f"ambiguous verified source-unit basename: {hint}")
        raise RuntimeError(f"verified source-unit hint not found: {hint}")

    if resolved_hints:
        unique_resolutions = list(dict.fromkeys(resolved_hints))
        if len(unique_resolutions) != 1:
            raise RuntimeError("conflicting verified source-unit hints")
        return unique_resolutions[0]

    contract_name = str(contract_name_hint or "").strip()
    if contract_name:
        declaration_matches = []
        for key, source in reference_sources.items():
            declared = _declared_contract_names(source)
            if contract_name in declared:
                declaration_matches.append(key)
        if len(declaration_matches) == 1:
            return declaration_matches[0]
        if len(declaration_matches) > 1:
            raise RuntimeError(
                f"contract {contract_name} is declared in multiple verified source units"
            )

    if len(keys) == 1:
        return keys[0]
    raise RuntimeError("could not identify the target verified source unit")


def resolve_reference_contract_source_unit(
    *,
    reference_sources: dict[str, str],
    contract_name: str,
) -> str:
    """Resolve the unique original source unit declaring a trusted contract."""
    trusted_name = str(contract_name or "").strip()
    if not trusted_name:
        raise RuntimeError("missing trusted artifact contract name")
    matches = [
        key
        for key, source in reference_sources.items()
        if trusted_name in _declared_contract_names(source)
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise RuntimeError(
            f"contract {trusted_name} is declared in multiple verified source units"
        )
    raise RuntimeError(
        f"contract {trusted_name} is not declared in the verified source bundle"
    )


def public_source_unit_hints(
    raw_case: dict | None,
    contracts: dict | None,
) -> list[str]:
    """Collect source-unit hints that are part of the public Patch input."""
    hints: list[str] = []

    def _append(value: object) -> None:
        text = str(value or "").strip()
        if text and text not in hints:
            hints.append(text)

    raw = raw_case if isinstance(raw_case, dict) else {}
    for key in ("file", "vulnerable_contract_file", "source_file"):
        _append(raw.get(key))
    if hints:
        return hints
    public_contracts = contracts if isinstance(contracts, dict) else {}
    for value in public_contracts.get("vulnerable", []) or []:
        _append(value)
    return hints


def unflatten_source_filename(flat_name: str) -> str:
    """Reverse the `/ → _` convention used when saving verified sources to disk.

    Example: ``@openzeppelin_contracts_token_ERC20_ERC20.sol``
           → ``@openzeppelin/contracts/token/ERC20/ERC20.sol``
    """
    stem, dot_ext = (flat_name.rsplit(".", 1) if "." in flat_name else (flat_name, ""))
    unflat = stem.replace("_", "/")
    return f"{unflat}.{dot_ext}" if dot_ext else unflat


def pick_reference_source_filename(
    *,
    reference_sources: dict[str, str],
    target_hints: list[str] | None = None,
) -> str | None:
    if not reference_sources:
        return None

    available = {Path(name).name.lower(): Path(name).name for name in reference_sources}
    for hint in target_hints or []:
        text = str(hint or "").strip()
        if not text:
            continue
        basename = Path(text).name
        _stem = basename[:-4] if basename.endswith(".sol") else basename
        candidates = {
            basename,
            _stem,
            f"{_stem}.sol",
        }
        for candidate in candidates:
            resolved = available.get(candidate.lower())
            if resolved:
                return resolved
        stem = _stem.lower()
        for source_name in reference_sources:
            if Path(source_name).stem.lower() == stem:
                return Path(source_name).name
    return next(iter(reference_sources))


def rewrite_imports_to_local_flat_files(
    solidity_code: str,
    *,
    available_files: list[str],
) -> str:
    available = [Path(item).name for item in available_files]
    file_names = {name.lower(): name for name in available}

    def _resolve_local_name(file_name: str) -> str | None:
        resolved = file_names.get(file_name.lower())
        if resolved:
            return resolved
        suffix_matches = [name for name in available if name.lower().endswith(f"_{file_name.lower()}")]
        if suffix_matches:
            return sorted(suffix_matches, key=len)[0]
        stem = Path(file_name).stem.lower()
        stem_matches = [
            name for name in available
            if Path(name).stem.lower() == stem or Path(name).stem.lower().endswith(f"_{stem}")
        ]
        if stem_matches:
            return sorted(stem_matches, key=len)[0]
        return None

    def repl(match: re.Match[str]) -> str:
        file_name = Path(match.group(2)).name
        resolved = _resolve_local_name(file_name)
        if not resolved:
            return match.group(0)
        return f"{match.group(1)}./{resolved}{match.group(3)}"

    return _IMPORT_RE.sub(repl, solidity_code)


def stage_flattened_reference_sources(
    *,
    target_dir: Path,
    reference_sources: dict[str, str],
    fixed_code: str,
    fixed_file_name: str,
    target_hints: list[str] | None = None,
) -> list[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)

    fixed_local_name = Path(fixed_file_name).name
    target_source_name = pick_reference_source_filename(
        reference_sources=reference_sources,
        target_hints=target_hints,
    )
    available_files = sorted(
        {Path(name).name for name in reference_sources}
        | {fixed_local_name}
        | ({target_source_name} if target_source_name else set())
    )

    staged_paths: list[Path] = []
    for source_name, source_code in reference_sources.items():
        local_name = Path(source_name).name
        content = (
            fixed_code if target_source_name and local_name == target_source_name else source_code
        )
        rewritten = rewrite_imports_to_local_flat_files(
            content,
            available_files=available_files,
        )
        output_path = target_dir / local_name
        output_path.write_text(rewritten)
        staged_paths.append(output_path)

    fixed_output = target_dir / fixed_local_name
    rewritten_fixed = rewrite_imports_to_local_flat_files(
        fixed_code,
        available_files=available_files,
    )
    if not fixed_output.exists() or fixed_output.read_text(errors="replace") != rewritten_fixed:
        fixed_output.write_text(rewritten_fixed)
    if fixed_output not in staged_paths:
        staged_paths.append(fixed_output)
    return staged_paths


# ---------------------------------------------------------------------------
# Structured (non-flattened) staging
# ---------------------------------------------------------------------------


def pick_reference_source_key(
    *,
    reference_sources: dict[str, str],
    target_hints: list[str] | None = None,
) -> str | None:
    """Match a target hint against full-path keys, returning the matched key."""
    if not reference_sources:
        return None

    basename_to_key: dict[str, str] = {}
    for key in reference_sources:
        bn = Path(key).name.lower()
        basename_to_key.setdefault(bn, key)

    for hint in target_hints or []:
        text = str(hint or "").strip()
        if not text:
            continue
        basename = Path(text).name
        stem = basename[:-4] if basename.endswith(".sol") else basename
        candidates = [basename, stem, f"{stem}.sol"]
        for c in candidates:
            matched = basename_to_key.get(c.lower())
            if matched:
                return matched
        stem_lower = stem.lower()
        for key in reference_sources:
            if Path(key).stem.lower() == stem_lower:
                return key

    return next(iter(reference_sources))


def stage_reference_sources_structured(
    *,
    target_dir: Path,
    reference_sources: dict[str, str],
    fixed_code: str,
    fixed_file_name: str,
    target_hints: list[str] | None = None,
) -> tuple[list[Path], set[str]]:
    """Write reference sources preserving directory structure under *target_dir*.

    Returns ``(staged_paths, scoped_prefixes)`` where *scoped_prefixes* contains
    import prefixes that need remapping into the structured source tree.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    target_key = pick_reference_source_key(
        reference_sources=reference_sources,
        target_hints=target_hints,
    )

    scoped_prefixes: set[str] = set()
    staged_paths: list[Path] = []

    destinations: set[Path] = set()
    for source_path, source_code in reference_sources.items():
        content = fixed_code if source_path == target_key else source_code
        output_path = resolve_staged_source_path(target_dir, source_path)
        if output_path in destinations:
            raise RuntimeError(f"duplicate staged Solidity source path: {source_path}")
        destinations.add(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
        staged_paths.append(output_path)

        logical_path = normalize_staged_source_path(source_path)
        first_part = logical_path.parts[0]
        if first_part.startswith("@"):
            scoped_prefixes.add(first_part)
            if str(source_path).startswith("/"):
                scoped_prefixes.add(f"/{first_part}")
        elif str(source_path).startswith("/"):
            scoped_prefixes.add(f"/{first_part}")

    fixed_output = target_dir / fixed_file_name
    if not fixed_output.exists() or fixed_output.read_text(errors="replace") != fixed_code:
        fixed_output.write_text(fixed_code)
    if fixed_output not in staged_paths:
        staged_paths.append(fixed_output)

    return staged_paths, scoped_prefixes
