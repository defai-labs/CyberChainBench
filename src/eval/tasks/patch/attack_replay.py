"""Replay historical attack transactions against a patched patch case."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from infra.chain.metadata import lookup_transaction, resolve_rpc_url
from infra.cli.validate_patch_normal_txs import (
    _coerce_transaction_payload,
    _pick_case_chain,
    _pick_case_contract_address,
    _prepare_fixed_code_line,
    _resolve_case_creation_block,
    _solidity_address_expr,
    _solidity_hex_bytes,
)
from infra.foundry.exploit_runner import _run_forge as _foundry_run_forge
from infra.foundry.workspace import (
    cleanup_isolated_eval_workspace,
    create_isolated_eval_workspace,
)
from infra.solidity.fixed_sources import stage_reference_sources_structured


def _run_forge(
    cmd: list[str],
    cwd: Path,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    return _foundry_run_forge(cmd, cwd=cwd, timeout=timeout)


def _pick_case_attack_tx_list(case) -> list[str]:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    seen: set[str] = set()
    ordered: list[str] = []
    for item in chain_context.get("attack_txs", []) or []:
        tx_hash = str(item).strip()
        if not tx_hash:
            continue
        lowered = tx_hash.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(tx_hash)
    return ordered


def _select_attack_transactions(
    case,
    *,
    chain: str,
    tx_hashes: list[str],
    limit: int,
) -> tuple[list[dict[str, object]], str]:
    requested = [str(item).strip() for item in tx_hashes if str(item).strip()]
    if not requested:
        requested = _pick_case_attack_tx_list(case)
    selected: list[dict[str, object]] = []
    for tx_hash in requested:
        payload = lookup_transaction(chain, tx_hash)
        candidate = _coerce_transaction_payload(payload)
        if candidate is None:
            continue
        selected.append(candidate)
        if len(selected) >= max(int(limit), 1):
            break
    return selected, ("manual" if tx_hashes else "case_attack_txs")


_CHAIN_WNATIVE = {
    "ethereum": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "mainnet": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "bsc": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    "bnb": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    "polygon": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
    "arbitrum": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    "optimism": "0x4200000000000000000000000000000000000006",
    "avalanche": "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
    "fantom": "0x21be370D5312f44cB42ce377BC9b8a0cEF1A4C83",
    "base": "0x4200000000000000000000000000000000000006",
}


def _generate_attack_tx_replay_test(
    *,
    case_slug: str,
    patch_target: str,
    call_target: str,
    caller: str,
    replay_block: int,
    fork_chain: str,
    value_wei: int,
    calldata_hex: str,
    fixed_code_line: str,
    tx_hash: str,
    is_creation: bool = False,
) -> str:
    test_name = f"{case_slug}_AttackTxReplay_{tx_hash[2:10]}"
    calldata_literal = _solidity_hex_bytes(calldata_hex)
    patch_target_expr = _solidity_address_expr(patch_target)
    caller_expr = _solidity_address_expr(caller)

    if is_creation:
        # Contract creation attack: deploy initcode via CREATE, check if it reverts
        execute_snippet = (
            'bytes memory initcode = CALLDATA;\n'
            '        address deployed;\n'
            '        assembly {\n'
            '            deployed := create(CALL_VALUE, add(initcode, 0x20), mload(initcode))\n'
            '        }\n'
            '        bool ok = deployed != address(0);\n'
            '        bytes memory ret = abi.encode(deployed);'
        )
        constants_snippet = ""
    else:
        call_target_expr = _solidity_address_expr(call_target, payable=True)
        execute_snippet = (
            '(bool ok, bytes memory ret) = CALL_TARGET.call{value: CALL_VALUE}(CALLDATA);'
        )
        constants_snippet = f"address payable constant CALL_TARGET = {call_target_expr};"

    return f"""\
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract {test_name} is Test {{
    address constant PATCH_TARGET = {patch_target_expr};
    {constants_snippet}
    address constant CALLER = {caller_expr};
    uint256 constant CALL_VALUE = {value_wei};
    bytes constant CALLDATA = hex"{calldata_literal}";

    function _applyFix() internal {{
        {fixed_code_line}
        vm.etch(PATCH_TARGET, _fixedCode);
    }}

    function _ensureCallerBalance() internal {{
        if (CALLER.balance < CALL_VALUE) {{
            vm.deal(CALLER, CALL_VALUE);
        }}
    }}

    function _hashLogs(Vm.Log[] memory entries) internal pure returns (bytes32) {{
        bytes memory encoded;
        for (uint256 i = 0; i < entries.length; i++) {{
            encoded = abi.encodePacked(encoded, entries[i].emitter, entries[i].data);
            for (uint256 j = 0; j < entries[i].topics.length; j++) {{
                encoded = abi.encodePacked(encoded, entries[i].topics[j]);
            }}
        }}
        return keccak256(encoded);
    }}

    function _executeAttack() internal returns (bool, bytes memory) {{
        {execute_snippet}
        return (ok, ret);
    }}

    function _totalTransferVolume(Vm.Log[] memory entries) internal pure returns (uint256) {{
        // Sum ALL ERC20 Transfer event values (measures total token movement)
        bytes32 transferTopic = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;
        uint256 total = 0;
        for (uint256 i = 0; i < entries.length; i++) {{
            if (entries[i].topics.length >= 3 && entries[i].topics[0] == transferTopic) {{
                if (entries[i].data.length >= 32) {{
                    total += abi.decode(entries[i].data, (uint256));
                }}
            }}
        }}
        return total;
    }}

    function _runHistoricalCall() internal returns (bool, bytes32, bytes32, uint256) {{
        vm.createSelectFork("{fork_chain}", {replay_block});
        _ensureCallerBalance();
        uint256 nativeBefore = CALLER.balance;
        vm.recordLogs();
        vm.prank(CALLER, CALLER);
        (bool ok, bytes memory ret) = _executeAttack();
        Vm.Log[] memory entries = vm.getRecordedLogs();
        uint256 profit = _measureProfit(nativeBefore, entries);
        return (ok, keccak256(ret), _hashLogs(entries), profit);
    }}

    function _measureProfit(uint256 nativeBefore, Vm.Log[] memory entries) internal view returns (uint256) {{
        // Native gain to CALLER (covers direct BNB/ETH transfers)
        uint256 nativeGain = CALLER.balance > nativeBefore ? CALLER.balance - nativeBefore : 0;
        // Total ERC20 transfer volume (not just to CALLER — attacker may use any address)
        uint256 tokenVolume = _totalTransferVolume(entries);
        return nativeGain + tokenVolume;
    }}

    function _runPatchedCall() internal returns (bool, bytes32, bytes32, uint256) {{
        vm.createSelectFork("{fork_chain}", {replay_block});
        _applyFix();
        _ensureCallerBalance();
        uint256 nativeBefore = CALLER.balance;
        vm.recordLogs();
        vm.prank(CALLER, CALLER);
        (bool ok, bytes memory ret) = _executeAttack();
        Vm.Log[] memory entries = vm.getRecordedLogs();
        uint256 afterProfit = _measureProfit(nativeBefore, entries);
        emit log_named_uint("AFTER_PROFIT", afterProfit);
        return (ok, keccak256(ret), _hashLogs(entries), afterProfit);
    }}

    function testHistoricalAttackTxReplay() public {{
        (bool beforeOk, bytes32 beforeRet, bytes32 beforeLogs, uint256 beforeProfit) = _runHistoricalCall();
        if (beforeOk) {{
            emit log_string("ATTACK_TX_BEFORE_OK");
        }}
        assertTrue(beforeOk, "historical attack tx did not succeed before patch");
        emit log_named_uint("BEFORE_PROFIT", beforeProfit);

        (bool afterOk, bytes32 afterRet, bytes32 afterLogs, uint256 afterProfit) = _runPatchedCall();
        emit log_named_uint("AFTER_PROFIT", afterProfit);

        // Blocked if: reverts, behavior changes, OR profit drops to <1% of before
        bool blocked = (!afterOk) || afterRet != beforeRet || afterLogs != beforeLogs;
        if (!blocked && beforeProfit > 0) {{
            blocked = afterProfit * 100 < beforeProfit;
        }}
        if (blocked) {{
            emit log_string("ATTACK_TX_BLOCKED");
        }}
        assertTrue(blocked, "patched contract still reproduces the historical attack tx");
        emit log_string("ATTACK_TX_REPLAY_CHECKED");
    }}
}}
"""


def validate_patch_attack_transactions(
    *,
    case,
    fixed_code: str,
    fixed_path: Path | None,
    base_dir: Path,
    artifact_dir: Path | None = None,
    tx_hashes: list[str] | None = None,
    limit: int = 3,
    timeout: int = 300,
    _fixed_code_line_override: str = "",
    foundry_root: Path | None = None,
) -> dict[str, object]:
    chain = _pick_case_chain(case)
    contract_address = _pick_case_contract_address(case)
    # For proxy cases, etch the proxy address directly (vm.etch + delegatecall
    # has caching issues in forked mode — etch proxy to bypass delegatecall)
    raw = getattr(case, "raw", {}) or {}
    proxy_address = str(raw.get("proxy_address", "")).strip()
    etch_target = proxy_address if proxy_address else contract_address
    payload: dict[str, object] = {
        "ok": False,
        "case_id": case.id,
        "case_name": case.name,
        "chain": chain,
        "contract_address": contract_address,
        "fixed_path": str(fixed_path) if fixed_path is not None else "",
        "selection_mode": "manual" if tx_hashes else "case_attack_txs",
        "selected_transactions": [],
        "results": [],
    }
    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    if not contract_address:
        payload["error"] = "case does not define a vulnerable contract address"
        return _finalize_payload(payload, artifact_dir)

    selected, selection_mode = _select_attack_transactions(
        case,
        chain=chain,
        tx_hashes=[str(item).strip() for item in (tx_hashes or []) if str(item).strip()],
        limit=max(int(limit), 1),
    )
    payload["selection_mode"] = selection_mode
    payload["selected_transactions"] = selected
    if not selected:
        payload["error"] = "no historical attack transactions were available for replay"
        return _finalize_payload(payload, artifact_dir)

    if _fixed_code_line_override:
        fixed_code_line = _fixed_code_line_override
        sanitized_fixed_code = ""
        fixed_note = ""
    else:
        fixed_code_line, sanitized_fixed_code, fixed_note = _prepare_fixed_code_line(
            case, base_dir, fixed_code
        )
        if not fixed_code_line:
            payload["error"] = fixed_note or "failed to prepare patched bytecode"
            return _finalize_payload(payload, artifact_dir)
    if fixed_note:
        payload["fixed_code_note"] = fixed_note

    creation_block = _resolve_case_creation_block(case, chain=chain, address=contract_address)
    payload["creation_block"] = creation_block
    payload["patch_from_creation"] = creation_block is not None

    workspace = create_isolated_eval_workspace(foundry_root or base_dir, task="patch_attack_txs", case_id=case.id)
    if workspace is None or not workspace.exists():
        payload["error"] = "failed to create isolated evaluation workspace"
        return _finalize_payload(payload, artifact_dir)

    case_slug = case.id.replace("-", "_")
    test_dir = workspace / "src" / "_benchmark_eval" / case_slug
    test_dir.mkdir(parents=True, exist_ok=True)
    payload["workspace_dir"] = str(workspace)

    temp_files: list[Path] = []
    try:
        if sanitized_fixed_code:
            fix_file = test_dir / "patch.sol"
            from infra.cli.validate_patch import _patch_source_metadata as _fix_source_metadata, _load_reference_sources
            ground_truth = (
                case.ground_truth if isinstance(getattr(case, "ground_truth", None), dict) else {}
            )
            metadata = _fix_source_metadata(case, base_dir)
            verification = case.verification or {}
            reference_sources, _, _ = _load_reference_sources(case, base_dir)
            staged_paths, scoped_prefixes = stage_reference_sources_structured(
                target_dir=test_dir,
                reference_sources=reference_sources,
                fixed_code=sanitized_fixed_code,
                fixed_file_name=fix_file.name,
                target_hints=[
                    str(ground_truth.get("contract", "")).strip(),
                    str(verification.get("target_contract_name", "")).strip(),
                    str(metadata.get("target_contract_name", "")).strip(),
                    str(ground_truth.get("file", "")).strip(),
                ],
            )
            temp_files.extend(path for path in staged_paths if path not in temp_files)
            if scoped_prefixes:
                from infra.foundry.workspace import write_structured_source_remappings
                test_dir_rel = str(test_dir.relative_to(workspace / "src"))
                write_structured_source_remappings(workspace, test_dir_rel, scoped_prefixes)
        if artifact_dir is not None:
            artifact_fixed = artifact_dir / "fixed_code.sol"
            artifact_fixed.write_text(sanitized_fixed_code or fixed_code)
            payload["fixed_code_path"] = str(artifact_fixed)

        payload["rpc_configured"] = bool(resolve_rpc_url(chain))
        results: list[dict[str, object]] = []

        for index, tx in enumerate(selected, start=1):
            tx_hash = str(tx["tx_hash"])
            block_number = int(tx["block_number"])
            replay_block = max(block_number - 1, 1)
            test_code = _generate_attack_tx_replay_test(
                case_slug=case_slug,
                patch_target=etch_target,
                call_target=str(tx.get("to", "")),
                caller=str(tx["from"]),
                replay_block=replay_block,
                fork_chain=chain,
                value_wei=int(tx["value_wei"]),
                calldata_hex=str(tx["input"]),
                fixed_code_line=fixed_code_line,
                tx_hash=tx_hash,
                is_creation=bool(tx.get("is_creation", False)),
            )
            test_file = test_dir / f"{case_slug}_attack_tx_{index}.sol"
            test_file.write_text(test_code)
            temp_files.append(test_file)

            entry_artifact_dir = artifact_dir / tx_hash if artifact_dir is not None else None
            if entry_artifact_dir is not None:
                entry_artifact_dir.mkdir(parents=True, exist_ok=True)
                (entry_artifact_dir / "replay_test.sol").write_text(test_code)

            test_result = _run_forge(
                [
                    "forge",
                    "test",
                    "--match-path",
                    str(test_file.relative_to(workspace)),
                    "-vv",
                ],
                cwd=workspace,
                timeout=max(int(timeout), 1),
            )
            output = (test_result.stdout or "") + (test_result.stderr or "")
            compile_failed = bool(
                test_result.returncode != 0 and "FAIL" not in output and "PASS" not in output
            )
            blocked = bool(test_result.returncode == 0 and "ATTACK_TX_BLOCKED" in output)
            checked = "ATTACK_TX_REPLAY_CHECKED" in output or blocked
            reproduced_before_patch = "ATTACK_TX_BEFORE_OK" in output
            output_path = ""
            if entry_artifact_dir is not None:
                output_path = str(entry_artifact_dir / "forge_output.txt")
                Path(output_path).write_text(output)

            results.append(
                {
                    "tx_hash": tx_hash,
                    "from": tx["from"],
                    "to": tx["to"],
                    "value_wei": tx["value_wei"],
                    "block_number": block_number,
                    "creation_block": creation_block,
                    "replay_block": replay_block,
                    "reproduced_before_patch": reproduced_before_patch,
                    "blocked": blocked,
                    "checked": checked,
                    "compile_failed": compile_failed,
                    "returncode": test_result.returncode,
                    "test_path": str(test_file),
                    "forge_output_path": output_path,
                    "test_output": output[-1000:] if output else "",
                }
            )

        payload["results"] = results
        payload["checked_count"] = sum(1 for item in results if item.get("checked"))
        payload["blocked_count"] = sum(1 for item in results if item.get("blocked"))
        payload["compile_failures"] = sum(1 for item in results if item.get("compile_failed"))
        payload["compile_ok"] = bool(results) and not any(
            item.get("compile_failed") for item in results
        )
        payload["all_blocked"] = bool(results) and all(item.get("blocked") for item in results)
        payload["ok"] = bool(results)
        payload["summary"] = (
            f"replayed {len(results)} historical attack transaction(s); "
            f"{payload['blocked_count']} blocked by patch"
        )
        return _finalize_payload(payload, artifact_dir)
    except subprocess.TimeoutExpired:
        payload["error"] = "forge timed out during attack transaction replay validation"
        return _finalize_payload(payload, artifact_dir)
    except FileNotFoundError:
        payload["error"] = "forge executable was not found"
        return _finalize_payload(payload, artifact_dir)
    finally:
        for path in temp_files:
            if path.exists():
                path.unlink()
        cleanup_isolated_eval_workspace(workspace)


def _finalize_payload(payload: dict[str, object], artifact_dir: Path | None) -> dict[str, object]:
    if artifact_dir is not None:
        report_path = artifact_dir / "attack_tx_replay.json"
        report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        payload["report_path"] = str(report_path)
    return payload


# Backwards-compatible alias
validate_fix_attack_transactions = validate_patch_attack_transactions
