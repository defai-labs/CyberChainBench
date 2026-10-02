"""
Patch evaluator — verifies that the agent's patch blocks the exploit
AND that normal operations are preserved.

Two verification axes (mirroring SWE-bench):
  - fail-to-pass: the exploit must FAIL after applying the patch.
  - pass-to-pass: normal views and benign token-like transactions must
    still behave the same after applying the patch (regression test).

DeFiHackLabs (fork-based) strategy:
  1. Write the agent's patched contract to a temp file in the Foundry project.
  2. Copy the original exploit, inject ``vm.etch(vulnAddr, patchedBytecode)``
     into setUp() so the forked on-chain contract code is swapped.
  3. ``forge build`` → compilation check.
  4. ``forge test`` on the modified exploit → FAIL means the patch works.
  5. Prefer replaying historical benign transactions against the patched
     contract; if none are available, fall back to a lightweight generated
     view regression test.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from agents.task_agent.base import AgentResponse
from benchmark.tasks.patch.case import PatchCase
from eval.artifacts import copy_session_log_to_artifact, write_raw_response_artifact
from eval.tasks.patch.attack_replay import validate_patch_attack_transactions
from eval.tasks.patch.score import PatchScore

# Backwards-compatible aliases
FixCase = PatchCase
from infra.chain.metadata import lookup_runtime_code, lookup_verified_source, resolve_case_source_metadata
from infra.foundry.exploit_runner import _run_forge as _foundry_run_forge
from infra.foundry.bootstrap import inject_state_bootstrap, normalize_create_select_fork
from infra.foundry.workspace import (
    cleanup_isolated_eval_workspace,
    create_isolated_eval_workspace,
)
from infra.solidity.fixed_contract_name import select_fixed_contract_name
from infra.solidity.legacy import (
    compile_dfhl_fixed_bytecode,
    compile_fixed_bytecode_from_source,
    infer_solc_version_from_source,
)
from infra.solidity.fixed_sources import (
    public_source_unit_hints,
    resolve_reference_contract_source_unit,
    resolve_reference_source_unit,
)
from project_layout import resolve_repo_path

TEMP_DIR_NAME = "_benchmark_eval"


def _looks_like_valid_solidity(code: str) -> bool:
    """Quick heuristic: does the text look like compilable Solidity source?"""
    if not code or not code.strip():
        return False
    text = code.strip()
    has_pragma = bool(re.search(r"pragma\s+solidity", text))
    has_contract = bool(re.search(r"\b(?:contract|library|interface)\s+\w+", text))
    return has_pragma or has_contract


def _run_forge(cmd: list[str], cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess:
    return _foundry_run_forge(cmd, cwd=cwd, timeout=timeout)


def _write_json_payload(path: Path, payload: dict[str, object]) -> str:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return str(path)


def _apply_patch_plan(score: PatchScore, response: AgentResponse) -> None:
    score.patch_possible = response.fix_possible
    if score.patch_possible is None and response.fixed_code:
        score.patch_possible = True
    score.required_authority = str(response.required_authority or "").strip()
    score.fix_confidence = str(response.fix_confidence or "").strip().lower()
    score.fix_rationale = str(response.fix_rationale or "").strip()
    score.target_contracts = [
        str(item).strip() for item in response.fix_target_contracts if str(item).strip()
    ]
    score.classification_present = any(
        [
            score.patch_possible is not None,
            bool(score.required_authority),
            bool(score.fix_rationale),
        ]
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_vulnerable_addresses(
    exploit_code: str,
    case: PatchCase,
) -> list[str]:
    """Extract vulnerable contract address(es) from exploit source.

    Tries (in order):
      0. Case JSON: ``contracts.vulnerable_address`` (pre-extracted by pipeline)
      1. Exploit comment: ``// Vuln Contract : https://...scan.../address/0x...``
      2. Case references: URLs containing ``/address/0x...``
      3. Inline interface cast: ``ISomeProtocol(0x...)`` or ``ISomeProtocol(payable(0x...))``
      4. Indirect address variable: ``address varName = 0x...``
    """
    addrs: list[str] = []

    # Strategy 0: pre-extracted vulnerable_address from case JSON
    vuln_addr = case.contracts.get("vulnerable_address", "")
    if vuln_addr and re.fullmatch(r"0x[0-9a-fA-F]{40}", vuln_addr):
        return [vuln_addr]

    # Strategy 1: "Vuln(erable) Contract" comment with embedded address
    for m in re.finditer(
        r"//.*?Vuln(?:erable)?\s+Contract.*?(0x[0-9a-fA-F]{40})",
        exploit_code,
        re.IGNORECASE,
    ):
        addrs.append(m.group(1))

    if addrs:
        return list(dict.fromkeys(addrs))

    # Strategy 2: etherscan-style /address/0x... URLs in case references
    refs = case.raw.get("vulnerability_detail", {}).get("references", [])
    for ref in refs:
        m = re.search(r"/address/(0x[0-9a-fA-F]{40})", ref)
        if m and m.group(1) not in addrs:
            addrs.append(m.group(1))

    if addrs:
        return list(dict.fromkeys(addrs))

    # Well-known infrastructure addresses and types to skip
    _INFRA_TYPES = {
        "CheatCodes",
        "Vm",
        "IERC20",
        "IUSDT",
        "IUSDC",
        "IDAI",
        "IWETH",
        "IWBNB",
        "USDT",
        "USDC",
        "IUniswapV2Router02",
        "IUniswapV2Router",
        "IUniswapV2Factory",
        "IPancakeRouter02",
        "IPancakeRouter",
        "IPancakeFactory",
        "IBeethovenVault",
        "IPancakePair",
        "IUniswapV2Pair",
    }
    _INFRA_ADDRS = {
        "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D".lower(),  # CheatCodes
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".lower(),  # WETH
        "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c".lower(),  # WBNB
        "0xdAC17F958D2ee523a2206206994597C13D831ec7".lower(),  # USDT
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".lower(),  # USDC
        "0x6B175474E89094C44Da98b954EedeAC495271d0F".lower(),  # DAI
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".lower(),  # UniV2 Router
        "0x10ED43C718714eb63d5aA57B78B54704E256024E".lower(),  # PCS Router
    }
    _INFRA_VAR_KEYWORDS = {
        "weth",
        "wbnb",
        "usdt",
        "usdc",
        "dai",
        "busd",
        "router",
        "factory",
        "pair",
        "cheats",
        "cheat",
        "btc",
        "wftm",
        "wmatic",
    }

    # Strategy 3: Inline interface cast — ISomeProtocol(payable(0x...))
    for m in re.finditer(
        r"(\w+)\s+\w+\s*=\s*\w+\((?:payable\()?(0x[0-9a-fA-F]{40})",
        exploit_code,
    ):
        type_name = m.group(1)
        addr = m.group(2)
        if type_name in _INFRA_TYPES:
            continue
        if addr.lower() in _INFRA_ADDRS:
            continue
        addrs.append(addr)

    if addrs:
        return list(dict.fromkeys(addrs))

    # Strategy 4: address varName = 0x...
    for m in re.finditer(
        r"address\s+(?:(?:private|public|internal|constant)\s+)*(\w+)\s*=\s*(0x[0-9a-fA-F]{40})",
        exploit_code,
    ):
        var_name = m.group(1).lower()
        addr = m.group(2)
        if addr.lower() in _INFRA_ADDRS:
            continue
        if any(kw in var_name for kw in _INFRA_VAR_KEYWORDS):
            continue
        addrs.append(addr)

    return list(dict.fromkeys(addrs))


def _parse_contract_name(solidity_code: str) -> str | None:
    """Extract the primary contract name from Solidity source.

    Skips interfaces (``IFoo``), test contracts (``FooTest``), and prefers
    concrete contracts over abstract helpers.
    """
    concrete = re.findall(r"^\s*(?:contract|library)\s+(\w+)\b", solidity_code, flags=re.MULTILINE)
    matches = concrete or re.findall(r"^\s*(?:abstract\s+)?(?:contract|library)\s+(\w+)\b", solidity_code, flags=re.MULTILINE)
    for name in matches:
        if not name.startswith("I") and not name.endswith("Test"):
            return name
    return matches[0] if matches else None


def _parse_contract_names(solidity_code: str) -> list[str]:
    concrete = re.findall(r"^\s*(?:contract|library)\s+(\w+)\b", solidity_code, flags=re.MULTILINE)
    return concrete or re.findall(r"^\s*(?:abstract\s+)?(?:contract|library)\s+(\w+)\b", solidity_code, flags=re.MULTILINE)


def _select_fixed_contract_name(
    solidity_code: str,
    *,
    target_hints: list[str] | None = None,
) -> str | None:
    matches = _parse_contract_names(solidity_code)
    if not matches:
        return None

    def _removesuffix(s: str, suffix: str) -> str:
        return s[:-len(suffix)] if suffix and s.endswith(suffix) else s
    normalized_hints = {
        _removesuffix(str(item).strip(), ".sol").lower()
        for item in (target_hints or [])
        if str(item).strip()
    }
    if normalized_hints:
        for name in matches:
            if name.lower() in normalized_hints:
                return name

    for name in matches:
        if not name.startswith("I") and not name.endswith("Test"):
            return name
    return matches[0]


def _canonical_source(text: str) -> str:
    lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _patch_source_metadata(case: PatchCase, base_dir: Path) -> dict:
    raw_metadata = case.raw if isinstance(case.raw, dict) else {}
    ground_truth = case.ground_truth if isinstance(getattr(case, "ground_truth", None), dict) else {}
    return resolve_case_source_metadata(
        case.id,
        base_dir,
        chain=str(getattr(case, "chain", "") or "").strip(),
        address=str(getattr(case, "contracts", {}).get("vulnerable_address", "") or "").strip(),
        file_hint=str(raw_metadata.get("file", "") or ground_truth.get("file", "")).strip(),
        contract_name_hint=str(raw_metadata.get("target_contract_name", "")).strip(),
        explicit_metadata=raw_metadata,
    )


def _target_token_variants(value: str) -> set[str]:
    text = str(value or "").strip()
    if not text:
        return set()
    lowered = text.lower()
    variants = {lowered}
    name = Path(text).name.lower()
    variants.add(name)
    if name.endswith(".sol"):
        variants.add(name[:-4])
    elif name:
        variants.add(f"{name}.sol")
    return {item for item in variants if item}


def _collect_expected_patch_targets(
    case: PatchCase,
    metadata: dict,
    proxy_info: dict[str, object] | None,
) -> list[str]:
    expected: list[str] = []

    def _push(value: str) -> None:
        text = str(value or "").strip()
        if text and text not in expected:
            expected.append(text)

    _push(str(metadata.get("target_contract_name", "")).strip())
    for path in case.contracts.get("vulnerable", []) or []:
        text = str(path).strip()
        if not text:
            continue
        name = Path(text).name
        _push(name)
        if name.endswith(".sol"):
            _push(name[:-4])
    if proxy_info:
        for key in ("implementation", "beacon_implementation", "minimal_proxy_target"):
            _push(str(proxy_info.get(key, "")).strip())
    return expected


def _match_patch_targets(reported: list[str], expected: list[str]) -> bool:
    reported_tokens: set[str] = set()
    for item in reported:
        reported_tokens.update(_target_token_variants(item))
    if not reported_tokens:
        return False
    if not expected:
        return True

    expected_tokens: set[str] = set()
    for item in expected:
        expected_tokens.update(_target_token_variants(item))
    return bool(reported_tokens & expected_tokens)


def _append_patch_note(score: PatchScore, note: str) -> None:
    text = str(note).strip()
    if text and text not in score.diagnostic_notes:
        score.diagnostic_notes.append(text)


def _apply_normal_tx_replay_result(
    score: PatchScore,
    normal_tx_replay: dict[str, object],
    *,
    artifact_dir: Path | None = None,
) -> bool:
    if artifact_dir is not None:
        replay_path = artifact_dir / "normal_tx_replay.json"
        score.normal_tx_replay_path = _write_json_payload(replay_path, normal_tx_replay)

    checked_count = int(normal_tx_replay.get("checked_count", 0) or 0)
    preserved_count = int(normal_tx_replay.get("preserved_count", 0) or 0)
    all_preserved = bool(normal_tx_replay.get("all_preserved", False))
    score.historical_normal_txs_checked = checked_count
    score.historical_normal_txs_preserved = preserved_count
    score.historical_normal_txs_all_preserved = all_preserved

    error = str(normal_tx_replay.get("error", "")).strip()
    if error:
        _append_patch_note(score, f"normal-tx replay validation error: {error}")

    if checked_count <= 0:
        if error == "no candidate historical normal transactions found":
            score.normal_ops_pass = True
            _append_patch_note(
                score,
                "no historical normal transactions were found in the pre-attack 100-block window; treating regression coverage as satisfied",
            )
            return True
        return False

    score.normal_ops_pass = all_preserved
    _append_patch_note(
        score,
        f"historical normal-tx replay checked {checked_count} transaction(s); {preserved_count} preserved",
    )
    return True


def _finalize_patch_summary(score: PatchScore) -> None:
    if score.skipped:
        score.summary = score.skip_reason or "patch evaluation was skipped"
        return
    if score.plan_only:
        if score.patch_possible is False:
            score.summary = "plan-only remediation classified as not fixable"
        elif score.patch_possible is True:
            score.summary = "plan-only remediation classified as fixable, but no executable patch was returned"
        else:
            score.summary = "plan-only remediation without executable patch"
        return
    if score.exploit_blocked and score.normal_ops_pass:
        score.summary = "patched code blocked the exploit and preserved normal operations"
        return
    if score.exploit_blocked and score.historical_normal_txs_checked <= 0:
        score.summary = "patched code blocked the exploit, but no historical normal-transaction replay was available"
        return
    if score.exploit_blocked:
        score.summary = "patched code blocked the exploit, but regression checks failed"
        return
    if score.compiles:
        score.summary = "patched code compiled, but the exploit still passed"
        return
    if score.patch_possible is True and not score.proxy_target_matched:
        score.summary = "fixable classification did not identify a matching target contract"
        return
    if score.classification_present:
        score.summary = "agent produced a remediation classification, but no verifiable patch"
        return
    if score.compile_error:
        score.summary = "patched code did not compile"
        return
    score.summary = "agent did not produce a usable fix classification or patch"


def _apply_patch_expectations(
    score: PatchScore,
    case: PatchCase,
    base_dir: Path,
    proxy_info: dict[str, object] | None,
) -> None:
    metadata = _patch_source_metadata(case, base_dir)
    info = proxy_info or {}

    score.proxy_detected = bool(info.get("proxy_detected", False))
    score.proxy_kind = str(info.get("proxy_kind", "")).strip()
    score.proxy_implementation = str(
        info.get("implementation")
        or info.get("beacon_implementation")
        or info.get("minimal_proxy_target")
        or ""
    ).strip()
    score.proxy_admin = str(info.get("admin", "")).strip()

    expected_targets = _collect_expected_patch_targets(case, metadata, info)
    score.expected_target_contracts = expected_targets

    if score.patch_possible is not True:
        return

    if not score.target_contracts:
        score.proxy_target_matched = True
        return

    score.proxy_target_matched = _match_patch_targets(score.target_contracts, expected_targets)
    if not score.proxy_target_matched:
        _append_patch_note(
            score,
            "fixable target mismatch: expected one of "
            + ", ".join(expected_targets or ["<any concrete target>"])
            + ", got "
            + ", ".join(score.target_contracts),
        )


def _load_reference_sources(
    case: PatchCase, base_dir: Path
) -> tuple[dict[str, str], list[str], dict[str, str]]:
    """Load reference Solidity sources for a fix case.

    Returns (sources, remappings, public metadata).  Keys are full logical paths
    (e.g. ``contracts/Monoswap.sol``).  Remappings come from the
    verified-source metadata when available.
    """
    from infra.solidity.fixed_sources import unflatten_source_filename

    verification = case.verification or {}
    metadata = _patch_source_metadata(case, base_dir)
    public_metadata = {
        "contract_name": str(metadata.get("target_contract_name", "")).strip(),
    }

    # --- Priority 1: on-disk source_dir (files are flattened, unflatten keys) ---
    source_dir_text = (
        str(verification.get("source_dir", "")).strip()
        or str(metadata.get("source_dir", "")).strip()
    )
    listed_files = (
        verification.get("files", []) if isinstance(verification.get("files"), list) else []
    )
    if not listed_files and isinstance(metadata.get("files"), list):
        listed_files = metadata.get("files", [])
    if source_dir_text:
        source_dir = resolve_repo_path(base_dir, source_dir_text)
        if source_dir.exists():
            sources: dict[str, str] = {}
            file_names = [
                str(item).strip() for item in listed_files if str(item).strip().endswith(".sol")
            ]
            if not file_names:
                file_names = [path.name for path in sorted(source_dir.glob("*.sol"))]
            for file_name in file_names:
                full_path = source_dir / file_name
                if full_path.exists():
                    logical_path = unflatten_source_filename(full_path.name)
                    sources[logical_path] = full_path.read_text(errors="replace")
            if sources:
                return sources, [], public_metadata

    # --- Priority 2: case-bundled vulnerable code ---
    local_sources = case.get_vulnerable_code(base_dir)
    if local_sources:
        return local_sources, [], public_metadata

    # --- Priority 3: fetch verified source via API (preserves full paths) ---
    candidate_addresses: list[str] = []
    vulnerable_address = str((case.contracts or {}).get("vulnerable_address", "")).strip()
    if vulnerable_address:
        candidate_addresses.append(vulnerable_address)
    proxy_address = str((case.remediation or {}).get("proxy_address", "")).strip()
    if proxy_address and proxy_address not in candidate_addresses:
        candidate_addresses.append(proxy_address)

    for address in candidate_addresses:
        verified = lookup_verified_source(case.chain or "", address)
        if not isinstance(verified, dict) or not verified.get("ok"):
            continue
        source_files = verified.get("source_files", {})
        if not isinstance(source_files, dict):
            continue
        sources: dict[str, str] = {}
        for file_path, content in source_files.items():
            file_key = str(file_path).strip()
            body = str(content or "")
            if file_key and body:
                sources[file_key] = body
        if sources:
            remappings = verified.get("remappings", [])
            if not isinstance(remappings, list):
                remappings = []
            return sources, remappings, {
                "contract_name": str(verified.get("contract_name", "")).strip(),
            }

    return {}, [], public_metadata


# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------


def evaluate_patch(
    case: PatchCase,
    response: AgentResponse,
    exploit_code: str | None,
    base_dir: Path,
    artifact_dir: Path | None = None,
    proxy_info: dict[str, object] | None = None,
    foundry_root: Path | None = None,
) -> PatchScore:
    """Evaluate agent's patch with two verification axes:

    1. **fail-to-pass** — the exploit must FAIL after the patch.
    2. **pass-to-pass** — historical benign transactions should replay
       successfully after the patch.

    Flow:
      1. Write the patched contract to a temp file.
      2. Generate exploit harness (vm.etch).
      3. ``forge build`` → compilation check.
      4. ``forge test`` on exploit harness → FAIL = exploit blocked.
      5. Run historical normal-tx replay when candidate benign transactions exist.
    """
    score = PatchScore()
    _apply_patch_plan(score, response)
    _apply_patch_expectations(score, case, base_dir, proxy_info)
    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        score.artifact_dir = str(artifact_dir)
        if response.raw_response:
            score.response_path = write_raw_response_artifact(artifact_dir, response.raw_response)
        score.session_log_path = copy_session_log_to_artifact(
            artifact_dir,
            response.session_log_path,
            str(response.session_log_text or ""),
        )
        score.agent_elapsed_seconds = response.agent_elapsed_seconds
        score.input_tokens_total = response.input_tokens_total
        score.output_tokens_total = response.output_tokens_total
        score.cache_read_input_tokens_total = response.cache_read_input_tokens_total
        score.cache_write_input_tokens_total = response.cache_write_input_tokens_total

    # Record ground-truth fixability from the benchmark case
    raw_fixable = case.raw.get("fixable") if isinstance(case.raw, dict) else None
    score.case_fixable = raw_fixable if isinstance(raw_fixable, bool) else None

    if score.patch_possible is False:
        score.summary = "agent classified the case as not fixable"
        _finalize_patch_summary(score)
        return score

    if not response.fixed_code:
        if (
            score.patch_possible is True
            and score.target_contracts
            and score.proxy_target_matched
        ):
            _append_patch_note(
                score,
                "fixable classification named a plausible target, but no patched code was returned",
            )
        _finalize_patch_summary(score)
        return score

    if not exploit_code:
        if not case.has_attack_replay_verification:
            score.compiles = _looks_like_valid_solidity(response.fixed_code)
            _append_patch_note(
                score,
                "verification exploit and historical attack transactions were unavailable during patch evaluation",
            )
            _finalize_patch_summary(score)
            return score

        if artifact_dir is not None:
            patched_code_path = artifact_dir / "patched_code.sol"
            patched_code_path.write_text(response.fixed_code)
            score.patched_code_path = str(patched_code_path)

        attack_artifact_dir = (
            artifact_dir / "attack_tx_replay" if artifact_dir is not None else None
        )
        attack_replay = validate_patch_attack_transactions(
            case=case,
            fixed_code=response.fixed_code,
            fixed_path=Path(score.patched_code_path) if score.patched_code_path else None,
            base_dir=base_dir,
            artifact_dir=attack_artifact_dir,
            foundry_root=foundry_root,
        )
        if artifact_dir is not None:
            _write_json_payload(artifact_dir / "attack_tx_replay.json", attack_replay)
        _append_patch_note(
            score,
            "used historical attack-tx replay lane because no verification exploit harness was available",
        )
        if attack_replay.get("error"):
            _append_patch_note(score, f"attack-tx replay validation error: {attack_replay['error']}")
        score.compiles = bool(attack_replay.get("compile_ok") or attack_replay.get("checked_count"))
        if not score.compiles and not attack_replay.get("results"):
            score.compiles = _looks_like_valid_solidity(response.fixed_code)
        score.exploit_blocked = bool(attack_replay.get("all_blocked", False))
        score.test_output = str(attack_replay.get("summary") or attack_replay.get("error") or "")

        if not score.exploit_blocked:
            _append_patch_note(score, "exploit still passes; skipping normal-tx replay")
        else:
            normal_artifact_dir = (
                artifact_dir / "normal_tx_replay" if artifact_dir is not None else None
            )
            from infra.cli.validate_patch import validate_patch_normal_transactions

            normal_tx_replay = validate_patch_normal_transactions(
                case=case,
                fixed_code=response.fixed_code,
                fixed_path=Path(score.patched_code_path) if score.patched_code_path else None,
                base_dir=base_dir,
                artifact_dir=normal_artifact_dir,
                foundry_root=foundry_root,
            )
            _apply_normal_tx_replay_result(score, normal_tx_replay, artifact_dir=artifact_dir)
        _finalize_patch_summary(score)
        return score

    isolated_workspace = create_isolated_eval_workspace(
        foundry_root or base_dir,
        task="patch",
        case_id=case.id,
    )
    project_root = isolated_workspace
    if project_root is None or not project_root.exists():
        _append_patch_note(score, "Foundry project root was not available for patch evaluation")
        _finalize_patch_summary(score)
        return score

    from infra.foundry.exploit_runner import _fix_address_checksums

    sanitized_patched_code = _fix_address_checksums(response.fixed_code)

    # --- Parse patched contract name ---
    verification = case.verification or {}
    metadata = _patch_source_metadata(case, base_dir)
    ground_truth = (
        case.ground_truth if isinstance(getattr(case, "ground_truth", None), dict) else {}
    )
    contract_name = select_fixed_contract_name(
        sanitized_patched_code,
        target_hints=[
            *response.fix_target_contracts,
            str(verification.get("target_contract_name", "")).strip(),
            str(metadata.get("target_contract_name", "")).strip(),
            str(ground_truth.get("contract", "")).strip(),
            str(ground_truth.get("file", "")).strip(),
        ],
    )

    # --- Set up temp files ---
    case_slug = case.id.replace("-", "_")
    test_dir = project_root / "src" / TEMP_DIR_NAME / case_slug
    test_dir.mkdir(parents=True, exist_ok=True)

    patch_file = test_dir / f"{case_slug}_patched.sol"
    harness_file = test_dir / f"{case_slug}_patch_test.sol"
    temp_files = [patch_file, harness_file]

    try:
        if artifact_dir is not None:
            patched_code_path = artifact_dir / "patched_code.sol"
            patched_code_path.write_text(sanitized_patched_code)
            score.patched_code_path = str(patched_code_path)

        compiler_version = (
            str(verification.get("compiler_version", "")).strip()
            or str(metadata.get("compiler_version", "")).strip()
        )
        source_origin = (
            str(verification.get("source_origin", "")).strip()
            or str(metadata.get("source_origin", "")).strip()
        )
        source_case_id = str(getattr(case, "raw", {}).get("source_case_id", "")).strip() or case.id
        if not source_origin and case.source == "DeFiHackLabs" and bool(getattr(case, "raw", {}).get("has_public_source", False)):
            source_origin = "verified"
        compile_note = ""
        effective_compiler_version = compiler_version or infer_solc_version_from_source(sanitized_patched_code)
        reference_sources, source_remappings, public_source_metadata = _load_reference_sources(
            case, base_dir
        )
        trusted_contract_name = (
            str(public_source_metadata.get("contract_name", "")).strip()
            or str(metadata.get("target_contract_name", "")).strip()
        )
        if trusted_contract_name:
            contract_name = trusted_contract_name
        target_source_unit = ""
        artifact_source_unit = ""
        if reference_sources:
            target_source_unit = resolve_reference_source_unit(
                reference_sources=reference_sources,
                source_unit_hints=public_source_unit_hints(
                    getattr(case, "raw", {}),
                    getattr(case, "contracts", {}),
                ),
                contract_name_hint=trusted_contract_name,
            )
            artifact_source_unit = resolve_reference_contract_source_unit(
                reference_sources=reference_sources,
                contract_name=trusted_contract_name,
            )
        elif not contract_name:
            score.test_output = "Could not parse contract name from patched code"
            score.compiles = _looks_like_valid_solidity(sanitized_patched_code)
            _append_patch_note(score, "failed to parse contract name from patched code")
            _finalize_patch_summary(score)
            return score
        try:
            if str(metadata.get("source_dir", "")).strip():
                bytecode, compiled_version, compiled_contract_name = compile_dfhl_fixed_bytecode(
                    base_dir=base_dir,
                    case_id=case.id,
                    source_metadata=metadata,
                    fixed_code=sanitized_patched_code,
                    contract_name_hint=contract_name
                    or str(verification.get("target_contract_name", "")).strip()
                    or str(metadata.get("target_contract_name", "")).strip(),
                    target_source_unit=target_source_unit,
                    artifact_source_unit=artifact_source_unit,
                )
            else:
                bytecode, compiled_contract_name = compile_fixed_bytecode_from_source(
                    fixed_code=sanitized_patched_code,
                    contract_name_hint=contract_name,
                    compiler_version=effective_compiler_version,
                    reference_sources=reference_sources,
                    source_remappings=source_remappings,
                    target_source_unit=target_source_unit,
                    artifact_source_unit=artifact_source_unit,
                )
                compiled_version = effective_compiler_version
            fixed_code_line = f'bytes memory _fixedCode = hex"{bytecode}";'
            contract_name = compiled_contract_name or contract_name
            compile_note = (
                f"bytecode compiled via solc {compiled_version} for {contract_name}"
            )
        except RuntimeError as exc:
            canonical_patched = _canonical_source(sanitized_patched_code)
            canonical_original = (
                _canonical_source(reference_sources[target_source_unit])
                if target_source_unit
                else ""
            )
            vulnerable_address = ""
            if case.chain_context:
                addresses = case.chain_context.get("vulnerable_addresses", []) or []
                if addresses:
                    vulnerable_address = str(addresses[0]).strip()
            if not vulnerable_address:
                vulnerable_address = str(case.contracts.get("vulnerable_address", "")).strip()
            fork_block = None
            if case.chain_context:
                raw_block = case.chain_context.get("fork_block")
                if isinstance(raw_block, int):
                    fork_block = raw_block

            if canonical_patched == canonical_original and canonical_original and vulnerable_address:
                runtime_code = lookup_runtime_code(
                    case.chain_context.get("fork_chain", "") or case.chain or "ethereum",
                    vulnerable_address,
                    fork_block,
                )
                if runtime_code:
                    fixed_code_line = f'bytes memory _fixedCode = hex"{runtime_code[2:]}";'
                    compile_note = (
                        "bytecode fallback used on-chain runtime bytecode "
                        f"because the patch is source-identical and solc compilation failed: {exc}"
                    )
                else:
                    raise
            else:
                raise

        prepared_exploit_code, _, _ = inject_state_bootstrap(
            exploit_code,
            state_context=case.state_context,
            chain_context=case.chain_context,
        )
        prepared_exploit_code, _, _ = normalize_create_select_fork(
            prepared_exploit_code,
            state_context=case.state_context,
            chain_context=case.chain_context,
        )
        prepared_exploit_code = _rewrite_eval_imports_for_isolated_workspace(prepared_exploit_code)
        _stage_required_test_helpers(
            base_dir=base_dir,
            project_root=project_root,
            exploit_code=prepared_exploit_code,
        )

        # --- Generate exploit harness based on exploit type ---
        vuln_addresses = _parse_vulnerable_addresses(prepared_exploit_code, case)

        fork_block = None
        if case.chain_context:
            raw_block = case.chain_context.get("fork_block")
            if isinstance(raw_block, int):
                fork_block = raw_block

        if vuln_addresses:
            # Fork-based (DeFiHackLabs): inject vm.etch into setUp
            harness_code = _generate_etch_harness(
                exploit_code=prepared_exploit_code,
                fixed_code_line=fixed_code_line,
                vuln_addresses=vuln_addresses,
            )
        else:
            # Local-import exploit or no address found: try import rewrite
            # This path needs the source file on disk for forge to compile
            patch_file.write_text(sanitized_patched_code)
            vuln_files = case.contracts.get("vulnerable", [])
            harness_code = _patch_exploit_imports(
                prepared_exploit_code,
                patch_file.name,
                vuln_files,
            )

        if not harness_code:
            score.test_output = (
                "Failed to generate patch harness — "
                "no setUp() found in exploit and no vulnerable address detected"
            )
            score.compiles = _looks_like_valid_solidity(response.fixed_code)
            _append_patch_note(
                score, "failed to generate a patch verification harness from the exploit"
            )
            _finalize_patch_summary(score)
            return score

        harness_file.write_text(harness_code)
        if artifact_dir is not None:
            harness_path = artifact_dir / "prepared_patch_harness.sol"
            harness_path.write_text(harness_code)
            score.harness_path = str(harness_path)

        # --- Step 0: Unpatched baseline (must reproduce the exploit) ---
        # Build the same harness against the ORIGINAL (unpatched) contract and
        # confirm the exploit PASSes. Without this, a compile/setup/RPC failure
        # in the patched run would be misread as "exploit blocked", awarding a
        # false positive. If the baseline does not reproduce, the case/harness is
        # inconclusive for this run and is not scored as blocked.
        if vuln_addresses:
            baseline_runtime = lookup_runtime_code(
                case.chain_context.get("fork_chain", "") or case.chain or "ethereum",
                vuln_addresses[0],
                fork_block,
            )
            if baseline_runtime:
                baseline_code = _generate_etch_harness(
                    exploit_code=prepared_exploit_code,
                    fixed_code_line=(
                        f'bytes memory _fixedCode = hex"{baseline_runtime[2:]}";'
                    ),
                    vuln_addresses=vuln_addresses,
                )
                if baseline_code:
                    score.baseline_checked = True
                    baseline_file = test_dir / f"{case_slug}_patch_baseline.sol"
                    temp_files.append(baseline_file)
                    baseline_file.write_text(baseline_code)
                    baseline_result = _run_forge(
                        [
                            "forge",
                            "test",
                            "--match-path",
                            str(baseline_file.relative_to(project_root)),
                            "-vv",
                        ],
                        cwd=project_root,
                        timeout=300,
                    )
                    score.baseline_passed = (
                        baseline_result.returncode == 0
                        and "PASS" in baseline_result.stdout
                    )
                    if artifact_dir is not None:
                        (artifact_dir / "baseline_output.txt").write_text(
                            (baseline_result.stdout + baseline_result.stderr)[-4000:]
                        )
                    if not score.baseline_passed:
                        _append_patch_note(
                            score,
                            "unpatched baseline exploit did not reproduce in this "
                            "harness/RPC context; patch result is inconclusive and "
                            "not scored as blocked",
                        )
                        _finalize_patch_summary(score)
                        return score

        # --- Step 1+2: Run exploit against patched code (fail-to-pass) ---
        # Use forge test --match-path directly (handles compilation of only
        # the needed files, avoiding unrelated compile errors)
        test_result = _run_forge(
            [
                "forge",
                "test",
                "--match-path",
                str(harness_file.relative_to(project_root)),
                "-vv",
            ],
            cwd=project_root,
            timeout=300,
        )

        output = test_result.stdout + test_result.stderr
        if compile_note:
            output = compile_note + "\n" + output
        score.test_output = output[-1000:] if output else ""
        if artifact_dir is not None and output:
            forge_output_path = artifact_dir / "forge_output.txt"
            forge_output_path.write_text(output)
            score.forge_output_path = str(forge_output_path)

        # Check if it was a compile error (no tests ran at all)
        if test_result.returncode != 0 and "FAIL" not in output and "PASS" not in output:
            score.compiles = False
            score.compile_error = output[-500:]
            _append_patch_note(
                score,
                "forge test failed before any PASS/FAIL oracle, indicating a compile or setup failure",
            )
            _finalize_patch_summary(score)
            return score

        score.compiles = True
        exploit_still_passes = test_result.returncode == 0 and "PASS" in test_result.stdout
        # Patch succeeds when the exploit NO LONGER passes
        score.exploit_blocked = not exploit_still_passes

        # --- Step 3: Prefer historical normal-tx replay for pass-to-pass ---
        if not score.exploit_blocked:
            _append_patch_note(score, "exploit still passes; skipping normal-tx replay")
        else:
            from infra.cli.validate_patch import validate_patch_normal_transactions

            normal_tx_replay = validate_patch_normal_transactions(
                case=case,
                fixed_code=response.fixed_code,
                fixed_path=Path(score.patched_code_path) if score.patched_code_path else None,
                base_dir=base_dir,
                artifact_dir=(artifact_dir / "normal_tx_replay") if artifact_dir is not None else None,
            )
            used_normal_tx_replay = _apply_normal_tx_replay_result(
                score,
                normal_tx_replay,
                artifact_dir=artifact_dir,
            )
            if not used_normal_tx_replay:
                _append_patch_note(
                    score,
                    "historical normal-transaction replay was unavailable; generated regression fallback is disabled",
                )

    except RuntimeError as exc:
        score.test_output = str(exc)
        score.compile_error = str(exc)[-500:]
        _append_patch_note(score, f"runtime error during patch evaluation: {exc}")
        if artifact_dir is not None:
            forge_output_path = artifact_dir / "forge_output.txt"
            forge_output_path.write_text(str(exc))
            score.forge_output_path = str(forge_output_path)
    except subprocess.TimeoutExpired:
        score.test_output = "TIMEOUT"
        _append_patch_note(score, "forge timed out during patch evaluation")
        if artifact_dir is not None:
            forge_output_path = artifact_dir / "forge_output.txt"
            forge_output_path.write_text("TIMEOUT")
            score.forge_output_path = str(forge_output_path)
    except FileNotFoundError:
        score.test_output = "forge not found"
        _append_patch_note(score, "forge executable was not found")
        if artifact_dir is not None:
            forge_output_path = artifact_dir / "forge_output.txt"
            forge_output_path.write_text("forge not found")
            score.forge_output_path = str(forge_output_path)
    finally:
        for f in temp_files:
            if f.exists():
                f.unlink()
        try:
            current = test_dir
            stop_at = project_root / "src"
            while current.exists() and current != stop_at and not any(current.iterdir()):
                current.rmdir()
                current = current.parent
        except OSError:
            pass
        cleanup_isolated_eval_workspace(isolated_workspace)

    _finalize_patch_summary(score)
    return score


# Backwards-compatible alias
evaluate_fix = evaluate_patch
