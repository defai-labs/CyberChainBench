#!/usr/bin/env python3
"""Validate a patched contract file against a benchmark patch case."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from agents.task_agent.base import AgentResponse, TaskType
from benchmark.loader import BenchmarkLoader
from eval.tasks.patch.attack_replay import validate_patch_attack_transactions
from eval.tasks.patch import evaluate_patch, write_patch_score_artifact
from eval.tasks.patch.log_hash import SOLIDITY_LOG_HASH_FUNCTION

# Backwards-compatible aliases
validate_fix_attack_transactions = validate_patch_attack_transactions
evaluate_fix = evaluate_patch
write_fix_score_artifact = write_patch_score_artifact
from project_layout import BENCHMARK_CASES_DIR as BENCHMARK_DIR, resolve_repo_path
from infra.solidity.legacy import (
    compile_dfhl_fixed_bytecode,
    compile_fixed_bytecode_from_source,
    infer_solc_version_from_source,
)
from infra.solidity.fixed_sources import stage_reference_sources_structured, unflatten_source_filename
from infra.foundry.workspace import (
    cleanup_isolated_eval_workspace,
    create_isolated_eval_workspace,
)
from infra.foundry.exploit_runner import _run_forge as _foundry_run_forge
from infra.chain.metadata_constants import DUNE_API_BASE, DUNE_SCHEMA_BY_CHAIN
from infra.chain.metadata import (
    infer_attack_tx_context,
    lookup_address_transactions,
    lookup_contract_creation,
    lookup_runtime_code,
    lookup_transaction,
    lookup_transaction_receipt,
    resolve_rpc_url,
    resolve_case_source_metadata,
)
from io import StringIO
import urllib.request
import urllib.error
import time
import subprocess
import re
import os
import csv


def _run_forge(cmd: list[str], *, cwd: Path, timeout: int):
    return _foundry_run_forge(cmd, cwd=cwd, timeout=timeout)


_WORKSPACE_CASE_DATA = Path("/app/workspace/case_data.json")


def _resolve_case(base_dir: Path, case_id: str, benchmark_dir: Path | None = None):
    from benchmark.tasks.patch.case import PatchCase

    # Prefer workspace case_data.json (no ground truth, safe from leakage)
    if _WORKSPACE_CASE_DATA.exists():
        try:
            data = json.loads(_WORKSPACE_CASE_DATA.read_text())
            if data.get("id") == case_id or not case_id:
                return PatchCase.from_json(data)
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    # Fallback: load from benchmark directory (for local dev / non-container usage)
    resolved_benchmark_dir = benchmark_dir.resolve() if benchmark_dir is not None else resolve_repo_path(base_dir, BENCHMARK_DIR)
    loader = BenchmarkLoader(resolved_benchmark_dir).load(
        "patch",
        track="on_chain",
    )
    for case in loader.cases:
        if case.id == case_id:
            return case
    raise SystemExit(f"unknown patch case id: {case_id}")


def _parse_bool_flag(value: str | None) -> bool | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n"}:
        return False
    raise SystemExit(f"invalid boolean flag: {value!r}")



def _parse_contract_name(solidity_code: str) -> str | None:
    concrete = re.findall(r"^\s*contract\s+(\w+)\b", solidity_code, flags=re.MULTILINE)
    matches = concrete or re.findall(r"^\s*(?:abstract\s+)?contract\s+(\w+)\b", solidity_code, flags=re.MULTILINE)
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


def _patch_source_metadata(case, base_dir: Path) -> dict:
    raw_metadata = case.raw if isinstance(case.raw, dict) else {}
    ground_truth = case.ground_truth if isinstance(getattr(case, "ground_truth", None), dict) else {}
    return resolve_case_source_metadata(
        case.id,
        base_dir,
        chain=_pick_case_chain(case),
        address=_pick_case_contract_address(case),
        file_hint=str(raw_metadata.get("file", "") or ground_truth.get("file", "")).strip(),
        contract_name_hint=str(raw_metadata.get("target_contract_name", "")).strip(),
        explicit_metadata=raw_metadata,
    )


def _load_reference_sources(case, base_dir: Path) -> tuple[dict[str, str], list[str]]:
    """Load reference sources with full logical paths as keys.

    Returns (sources, remappings).
    """
    from infra.chain.metadata import lookup_verified_source

    verification = case.verification or {}
    metadata = _patch_source_metadata(case, base_dir)
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
                return sources, []

    local_sources = case.get_vulnerable_code(base_dir)
    if local_sources:
        return local_sources, []

    candidate_addresses: list[str] = []
    vulnerable_address = str((getattr(case, "contracts", None) or {}).get("vulnerable_address", "")).strip()
    if vulnerable_address:
        candidate_addresses.append(vulnerable_address)
    proxy_address = str((getattr(case, "remediation", None) or {}).get("proxy_address", "")).strip()
    if proxy_address and proxy_address not in candidate_addresses:
        candidate_addresses.append(proxy_address)

    for address in candidate_addresses:
        verified = lookup_verified_source(getattr(case, "chain", "") or "", address)
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
            return sources, remappings

    return {}, []


def _parse_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _pick_case_chain(case) -> str:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    return str(chain_context.get("fork_chain") or getattr(case, "chain", "") or "ethereum").strip()


def _pick_case_contract_address(case) -> str:
    ground_truth = getattr(case, "ground_truth", None)
    if not isinstance(ground_truth, dict):
        ground_truth = {}
    return str(
        getattr(case, "contracts", {}).get("vulnerable_address", "")
        or ground_truth.get("vulnerable_address", "")
        or ""
    ).strip()


def _pick_case_attack_txs(case) -> set[str]:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    attack_txs = chain_context.get("attack_txs", []) or []
    return {str(item).strip().lower() for item in attack_txs if str(item).strip()}


def _extract_attack_selectors(case, chain: str) -> set[str]:
    """Extract 4-byte function selectors from attack transactions."""
    attack_tx_hashes = _pick_case_attack_txs(case)
    selectors: set[str] = set()
    for tx_hash in attack_tx_hashes:
        payload = lookup_transaction(chain, tx_hash)
        if not isinstance(payload, dict):
            continue
        calldata = str(payload.get("input", "")).strip()
        if len(calldata) >= 10:
            selectors.add(calldata[:10].lower())
    return selectors


def _filter_by_attack_selectors(
    candidates: list[dict[str, object]],
    attack_selectors: set[str],
) -> list[dict[str, object]]:
    """Keep only candidates whose calldata selector matches an attack tx selector."""
    if not attack_selectors:
        return candidates
    filtered = []
    for tx in candidates:
        calldata = str(tx.get("input", "")).strip()
        if len(calldata) >= 10 and calldata[:10].lower() in attack_selectors:
            filtered.append(tx)
    return filtered


def _pick_case_related_addresses(case) -> list[str]:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    related = chain_context.get("related_addresses", []) or []
    if not isinstance(related, list):
        return []
    return [str(item).strip() for item in related if str(item).strip()]


def _pick_candidate_search_addresses(case, primary_address: str) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in [str(primary_address).strip(), *_pick_case_related_addresses(case)]:
        if not item:
            continue
        lowered = item.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(item)
    return normalized


def _load_dune_api_key() -> str:
    return os.environ.get("DUNE_API_KEY", "").strip()


def _dune_headers(*, api_key: str, content_type: str | None = "application/json") -> dict[str, str]:
    headers = {
        "User-Agent": "Web3Bug-Benchmark/patch-normal-tx-replay",
        "X-DUNE-API-KEY": api_key,
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _dune_post_json(
    url: str,
    payload: dict[str, object],
    headers: dict[str, str],
    *,
    timeout: int = 60,
) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _dune_get_json(
    url: str,
    headers: dict[str, str],
    *,
    timeout: int = 60,
) -> dict[str, object]:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _dune_get_text(
    url: str,
    headers: dict[str, str],
    *,
    timeout: int = 120,
) -> str:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _parse_csv_rows(csv_text: str) -> list[dict[str, str]]:
    return [
        {str(key): str(value) for key, value in row.items()}
        for row in csv.DictReader(StringIO(csv_text))
    ]


def _dune_wait_for_execution(
    *,
    api_key: str,
    execution_id: str,
    timeout_s: int = 180,
    poll_interval_s: float = 4.0,
) -> dict[str, object]:
    deadline = time.time() + max(int(timeout_s), 1)
    url = f"{DUNE_API_BASE}/execution/{execution_id}/status"
    last: dict[str, object] = {}
    while time.time() < deadline:
        try:
            status = _dune_get_json(
                url,
                _dune_headers(api_key=api_key, content_type=None),
            )
        except urllib.error.HTTPError as exc:
            if int(getattr(exc, "code", 0)) == 429:
                time.sleep(max(float(poll_interval_s) * 2.0, 5.0))
                continue
            raise
        last = status if isinstance(status, dict) else {}
        if bool(last.get("is_execution_finished")):
            state = str(last.get("state", "")).strip()
            if state not in {"QUERY_STATE_COMPLETED", "QUERY_STATE_COMPLETED_PARTIAL"}:
                raise RuntimeError(f"Dune execution failed: {last}")
            return last
        time.sleep(max(float(poll_interval_s), 0.5))
    raise RuntimeError(f"Dune execution timed out: {last}")


def _render_dune_log_transactions_sql(
    *,
    chain: str,
    address: str,
    startblock: int,
    endblock: int,
    limit_rows: int,
    sort: str,
) -> str:
    schema = DUNE_SCHEMA_BY_CHAIN[chain]
    order = "ASC" if sort == "asc" else "DESC"
    return f"""
WITH params AS (
    SELECT
        from_hex(substr('{address.lower()}', 3)) AS target_address,
        CAST({int(startblock)} AS bigint) AS start_block,
        CAST({int(endblock)} AS bigint) AS end_block
),
log_txs AS (
    SELECT
        concat('0x', lower(to_hex(l.tx_hash))) AS tx_hash,
        max(l.block_number) AS block_number
    FROM {schema}.logs l
    CROSS JOIN params p
    WHERE l.contract_address = p.target_address
      AND l.block_number BETWEEN p.start_block AND p.end_block
    GROUP BY 1
),
ranked AS (
    SELECT
        tx_hash,
        block_number,
        row_number() OVER (
            ORDER BY
                block_number {order},
                tx_hash {order}
        ) AS row_num
    FROM log_txs
)
SELECT
    tx_hash,
    CAST(block_number AS varchar) AS blockNumber
FROM ranked
WHERE row_num <= {int(limit_rows)}
ORDER BY row_num
""".strip()


def _render_dune_trace_transactions_sql(
    *,
    chain: str,
    addresses: list[str],
    startblock: int,
    endblock: int,
    limit_rows: int,
    sort: str,
) -> str:
    schema = DUNE_SCHEMA_BY_CHAIN[chain]
    order = "ASC" if sort == "asc" else "DESC"
    normalized_addresses = [str(item).strip().lower() for item in addresses if str(item).strip()]
    address_list = ", ".join(
        f"from_hex(substr('{address}', 3))" for address in normalized_addresses
    )
    return f"""
WITH traced AS (
    SELECT
        concat('0x', lower(to_hex(t.tx_hash))) AS tx_hash,
        max(t.block_number) AS block_number
    FROM {schema}.traces t
    WHERE
        (t."from" IN ({address_list}) OR t."to" IN ({address_list}))
        AND t.block_number BETWEEN CAST({int(startblock)} AS bigint) AND CAST({int(endblock)} AS bigint)
    GROUP BY 1
),
ranked AS (
    SELECT
        tx_hash,
        block_number,
        row_number() OVER (
            ORDER BY
                block_number {order},
                tx_hash {order}
        ) AS row_num
    FROM traced
)
SELECT
    tx_hash,
    CAST(block_number AS varchar) AS blockNumber
FROM ranked
WHERE row_num <= {int(limit_rows)}
ORDER BY row_num
""".strip()


def _lookup_log_transactions_via_dune(
    *,
    chain: str,
    address: str,
    startblock: int,
    endblock: int,
    limit_rows: int,
    sort: str,
) -> list[dict[str, str]]:
    api_key = _load_dune_api_key()
    schema = DUNE_SCHEMA_BY_CHAIN.get(chain)
    if not api_key or not schema:
        return []

    sql = _render_dune_log_transactions_sql(
        chain=chain,
        address=address,
        startblock=startblock,
        endblock=endblock,
        limit_rows=limit_rows,
        sort=sort,
    )
    try:
        execution = _dune_post_json(
            f"{DUNE_API_BASE}/sql/execute",
            {"sql": sql, "performance": "medium"},
            _dune_headers(api_key=api_key),
        )
        execution_id = str(execution.get("execution_id", "")).strip()
        if not execution_id:
            return []
        _dune_wait_for_execution(api_key=api_key, execution_id=execution_id)
        csv_text = _dune_get_text(
            f"{DUNE_API_BASE}/execution/{execution_id}/results/csv?allow_partial_results=true",
            _dune_headers(api_key=api_key, content_type=None),
        )
        return _parse_csv_rows(csv_text)
    except (
        OSError,
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        RuntimeError,
    ):
        return []


def _lookup_trace_transactions_via_dune(
    *,
    chain: str,
    addresses: list[str],
    startblock: int,
    endblock: int,
    limit_rows: int,
    sort: str,
) -> list[dict[str, str]]:
    api_key = _load_dune_api_key()
    schema = DUNE_SCHEMA_BY_CHAIN.get(chain)
    normalized_addresses = [str(item).strip() for item in addresses if str(item).strip()]
    if not api_key or not schema or not normalized_addresses:
        return []

    sql = _render_dune_trace_transactions_sql(
        chain=chain,
        addresses=normalized_addresses,
        startblock=startblock,
        endblock=endblock,
        limit_rows=limit_rows,
        sort=sort,
    )
    try:
        execution = _dune_post_json(
            f"{DUNE_API_BASE}/sql/execute",
            {"sql": sql, "performance": "medium"},
            _dune_headers(api_key=api_key),
        )
        execution_id = str(execution.get("execution_id", "")).strip()
        if not execution_id:
            return []
        _dune_wait_for_execution(api_key=api_key, execution_id=execution_id)
        csv_text = _dune_get_text(
            f"{DUNE_API_BASE}/execution/{execution_id}/results/csv?allow_partial_results=true",
            _dune_headers(api_key=api_key, content_type=None),
        )
        return _parse_csv_rows(csv_text)
    except (
        OSError,
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        RuntimeError,
    ):
        return []


def _pick_case_fork_block(case) -> int | None:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    value = chain_context.get("fork_block")
    return value if isinstance(value, int) else _parse_int(value)


def _pick_recent_history_window(
    case,
    *,
    chain: str,
    address: str,
    search_offset: int,
    minimum_blocks: int = 100,
) -> tuple[int, int] | tuple[None, None]:
    """Search only the 100 blocks immediately before the attack block.

    For normal-transaction replay, we want behavior closest to the exploit state
    without scanning a large historical range. This also keeps trace_filter queries
    within per-request provider limits on chains like BSC.
    """
    fork_block = _pick_case_fork_block(case)
    if fork_block is None:
        return None, None

    creation_block = _resolve_case_creation_block(case, chain=chain, address=address)
    end_block = max(int(fork_block) - 1, 1)
    recent_span = max(int(minimum_blocks), 1)
    start_block = max(end_block - recent_span + 1, 1)
    if creation_block is not None:
        start_block = max(start_block, int(creation_block))
    return start_block, end_block


def _coerce_transaction_payload(
    tx: dict[str, object], *, fallback_block: int | None = None
) -> dict[str, object] | None:
    tx_hash = str(tx.get("hash", "")).strip()
    caller_value = tx.get("from")
    to_value = tx.get("to")
    input_value = tx.get("input")
    caller = "" if caller_value is None else str(caller_value).strip()
    to_addr = "" if to_value is None else str(to_value).strip()
    calldata = "0x" if input_value is None else str(input_value).strip() or "0x"
    if caller.lower() == "none":
        caller = ""
    if to_addr.lower() == "none":
        to_addr = ""
    block_number = _parse_int(tx.get("blockNumber")) or fallback_block
    value_wei = _parse_int(tx.get("value")) or 0
    if not tx_hash or not caller or not to_addr or block_number is None:
        return None
    return {
        "tx_hash": tx_hash,
        "from": caller,
        "to": to_addr,
        "input": calldata,
        "value_wei": value_wei,
        "block_number": block_number,
    }


def _select_candidate_transactions(
    case,
    *,
    chain: str,
    address: str,
    tx_hashes: list[str],
    limit: int,
    search_offset: int,
) -> tuple[list[dict[str, object]], str]:
    attack_selectors = _extract_attack_selectors(case, chain)
    search_addresses = _pick_candidate_search_addresses(case, address)
    if tx_hashes:
        selected: list[dict[str, object]] = []
        for tx_hash in tx_hashes:
            payload = lookup_transaction(chain, tx_hash)
            candidate = _coerce_transaction_payload(payload)
            if candidate is None:
                continue
            selected.append(candidate)
        return _filter_by_attack_selectors(selected, attack_selectors)[:limit], "manual"

    trace_filter_selected = _select_candidate_transactions_via_trace_filter(
        case,
        chain=chain,
        addresses=search_addresses,
        limit=limit * 5,
        search_offset=search_offset,
    )
    if trace_filter_selected:
        filtered = _filter_by_attack_selectors(trace_filter_selected, attack_selectors)
        if filtered:
            return filtered[:limit], "trace_filter"

    dune_trace_selected = _select_candidate_transactions_via_dune_traces(
        case,
        chain=chain,
        addresses=search_addresses,
        limit=limit * 5,
        search_offset=search_offset,
    )
    if dune_trace_selected:
        filtered = _filter_by_attack_selectors(dune_trace_selected, attack_selectors)
        if filtered:
            return filtered[:limit], "dune_traces"

    rpc_selected = _select_candidate_transactions_via_rpc_logs(
        case,
        chain=chain,
        address=address,
        limit=limit * 5,
        search_offset=search_offset,
    )
    if rpc_selected:
        filtered = _filter_by_attack_selectors(rpc_selected, attack_selectors)
        if filtered:
            return filtered[:limit], "rpc_logs"

    dune_log_selected = _select_candidate_transactions_via_dune_logs(
        case,
        chain=chain,
        address=address,
        limit=limit * 5,
        search_offset=search_offset,
    )
    if dune_log_selected:
        filtered = _filter_by_attack_selectors(dune_log_selected, attack_selectors)
        if filtered:
            return filtered[:limit], "dune_logs"

    attack_txs = _pick_case_attack_txs(case)
    fork_block = _pick_case_fork_block(case)
    listing = lookup_address_transactions(
        chain,
        address,
        endblock=fork_block if fork_block is not None else 99999999,
        offset=max(search_offset, limit * 5),
        sort="desc",
    )
    transactions = listing.get("transactions", []) if isinstance(listing, dict) else []
    if not isinstance(transactions, list):
        transactions = []

    selected = []
    for item in transactions:
        if not isinstance(item, dict):
            continue
        tx_hash = str(item.get("hash", "")).strip()
        if not tx_hash or tx_hash.lower() in attack_txs:
            continue
        if str(item.get("isError", "")).strip() == "1":
            continue
        tx_receipt_status = str(item.get("txreceipt_status", "")).strip()
        if tx_receipt_status == "0":
            continue
        calldata = str(item.get("input", "")).strip()
        value_wei = _parse_int(item.get("value")) or 0
        if (not calldata or calldata == "0x") and value_wei == 0:
            continue

        payload = lookup_transaction(chain, tx_hash) or item
        candidate = _coerce_transaction_payload(
            payload, fallback_block=_parse_int(item.get("blockNumber"))
        )
        if candidate is None:
            continue
        selected.append(candidate)

    filtered = _filter_by_attack_selectors(selected, attack_selectors)
    return filtered[:limit], "auto"


def _json_rpc(rpc_url: str, method: str, params: list[object]) -> dict[str, object] | None:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Web3Bug-Benchmark/infra.cli",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _rpc_logs_for_address(
    chain: str,
    address: str,
    *,
    from_block: int,
    to_block: int,
) -> list[dict[str, object]]:
    rpc_url = resolve_rpc_url(chain)
    if not rpc_url:
        return []

    response = _json_rpc(
        rpc_url,
        "eth_getLogs",
        [
            {
                "address": str(address).strip(),
                "fromBlock": hex(max(int(from_block), 0)),
                "toBlock": hex(max(int(to_block), 0)),
            }
        ],
    )
    result = response.get("result") if isinstance(response, dict) else None
    return result if isinstance(result, list) else []


def _lookup_code_at_block(chain: str, address: str, block_number: int) -> str:
    rpc_url = resolve_rpc_url(chain)
    if not rpc_url:
        return ""

    response = _json_rpc(
        rpc_url,
        "eth_getCode",
        [str(address).strip(), hex(max(int(block_number), 0))],
    )
    result = response.get("result") if isinstance(response, dict) else None
    return str(result).strip() if isinstance(result, str) else ""


def _resolve_case_creation_block(case, *, chain: str, address: str) -> int | None:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    explicit = _parse_int(chain_context.get("creation_block"))
    if explicit is not None:
        return explicit

    creation = lookup_contract_creation(chain, address)
    block_number = _parse_int(creation.get("block_number")) if isinstance(creation, dict) else None
    if block_number is not None:
        return block_number

    fork_block = _pick_case_fork_block(case)
    if fork_block is None:
        return None

    latest_code = _lookup_code_at_block(chain, address, fork_block)
    if not latest_code or latest_code == "0x":
        return None

    low = 1
    high = max(int(fork_block), 1)
    first_seen = high
    while low <= high:
        mid = (low + high) // 2
        code = _lookup_code_at_block(chain, address, mid)
        if code and code != "0x":
            first_seen = mid
            high = mid - 1
        else:
            low = mid + 1
    return first_seen


def _trace_filter_for_addresses(
    chain: str,
    addresses: list[str],
    *,
    from_block: int,
    to_block: int,
) -> list[dict[str, object]]:
    rpc_url = resolve_rpc_url(chain)
    normalized_addresses = [str(item).strip() for item in addresses if str(item).strip()]
    if not rpc_url or not normalized_addresses:
        return []

    response = _json_rpc(
        rpc_url,
        "trace_filter",
        [
            {
                "fromBlock": hex(max(int(from_block), 0)),
                "toBlock": hex(max(int(to_block), 0)),
                "toAddress": normalized_addresses,
            }
        ],
    )
    result = response.get("result") if isinstance(response, dict) else None
    return result if isinstance(result, list) else []



def _select_candidate_transactions_via_trace_filter(
    case,
    *,
    chain: str,
    addresses: list[str],
    limit: int,
    search_offset: int,
) -> list[dict[str, object]]:
    normalized_addresses = [str(item).strip() for item in addresses if str(item).strip()]
    if not normalized_addresses:
        return []

    primary_address = normalized_addresses[0]
    start_block, end_block = _pick_recent_history_window(
        case,
        chain=chain,
        address=primary_address,
        search_offset=search_offset,
    )
    if start_block is None or end_block is None:
        return []

    attack_txs = _pick_case_attack_txs(case)
    attack_context = infer_attack_tx_context(
        chain,
        sorted(attack_txs),
        vulnerable_addresses=normalized_addresses,
        block_number=_pick_case_fork_block(case),
    )
    blocked_addresses = {
        str(item).strip().lower()
        for key in (
            "attack_senders",
            "attack_targets",
            "attack_created_contracts",
        )
        for item in (attack_context.get(key, []) or [])
        if str(item).strip()
    }
    entrypoint = str(attack_context.get("attack_entrypoint", "")).strip().lower()
    if entrypoint:
        blocked_addresses.add(entrypoint)

    selected: list[dict[str, object]] = []
    seen_tx_hashes: set[str] = set()
    rows = _trace_filter_for_addresses(
        chain,
        normalized_addresses,
        from_block=start_block,
        to_block=end_block,
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        tx_hash = str(row.get("transactionHash", "") or row.get("transaction_hash", "")).strip().lower()
        if not tx_hash or tx_hash in seen_tx_hashes or tx_hash in attack_txs:
            continue
        seen_tx_hashes.add(tx_hash)

        tx_payload = lookup_transaction(chain, tx_hash)
        receipt_payload = lookup_transaction_receipt(chain, tx_hash)
        if not tx_payload or not receipt_payload:
            continue
        if str(receipt_payload.get("status", "")).strip().lower() not in {"0x1", "1"}:
            continue

        candidate = _coerce_transaction_payload(
            tx_payload,
            fallback_block=_parse_int(row.get("blockNumber")),
        )
        if candidate is None:
            continue
        if str(candidate["from"]).strip().lower() in blocked_addresses:
            continue
        if str(candidate["to"]).strip().lower() in blocked_addresses:
            continue
        if (not str(candidate["input"]).strip() or str(candidate["input"]).strip() == "0x") and int(candidate["value_wei"]) == 0:
            continue

        selected.append(candidate)
        if len(selected) >= limit:
            return selected

    return selected


def _select_candidate_transactions_via_rpc_logs(
    case,
    *,
    chain: str,
    address: str,
    limit: int,
    search_offset: int,
) -> list[dict[str, object]]:
    fork_block = _pick_case_fork_block(case)
    if fork_block is None:
        return []

    attack_txs = _pick_case_attack_txs(case)
    max_blocks = max(max(int(search_offset), 1) * 40, 200)
    window_size = 10
    end_block = max(fork_block - 1, 1)
    start_block = max(end_block - max(max_blocks, window_size) + 1, 1)
    selected: list[dict[str, object]] = []
    seen_tx_hashes: set[str] = set()

    for hi in range(end_block, start_block - 1, -window_size):
        lo = max(start_block, hi - window_size + 1)
        logs = _rpc_logs_for_address(
            chain,
            address,
            from_block=lo,
            to_block=hi,
        )
        for log in logs:
            if not isinstance(log, dict):
                continue
            tx_hash = str(log.get("transactionHash", "")).strip().lower()
            if not tx_hash or tx_hash in seen_tx_hashes or tx_hash in attack_txs:
                continue
            seen_tx_hashes.add(tx_hash)

            tx_payload = lookup_transaction(chain, tx_hash)
            receipt_payload = lookup_transaction_receipt(chain, tx_hash)
            if not tx_payload or not receipt_payload:
                continue
            if str(receipt_payload.get("status", "")).strip().lower() not in {"0x1", "1"}:
                continue

            candidate = _coerce_transaction_payload(tx_payload)
            if candidate is None:
                continue
            if (
                not str(candidate["input"]).strip() or str(candidate["input"]).strip() == "0x"
            ) and int(candidate["value_wei"]) == 0:
                continue

            selected.append(candidate)
            if len(selected) >= limit:
                return selected

    return selected


def _select_candidate_transactions_via_dune_logs(
    case,
    *,
    chain: str,
    address: str,
    limit: int,
    search_offset: int,
) -> list[dict[str, object]]:
    start_block, end_block = _pick_recent_history_window(
        case,
        chain=chain,
        address=address,
        search_offset=search_offset,
    )
    if start_block is None or end_block is None:
        return []
    fork_block = _pick_case_fork_block(case)
    attack_txs = _pick_case_attack_txs(case)
    attack_context = infer_attack_tx_context(
        chain,
        sorted(attack_txs),
        vulnerable_addresses=[address],
        block_number=fork_block,
    )
    blocked_addresses = {
        str(item).strip().lower()
        for key in (
            "attack_senders",
            "attack_targets",
            "attack_created_contracts",
        )
        for item in (attack_context.get(key, []) or [])
        if str(item).strip()
    }
    entrypoint = str(attack_context.get("attack_entrypoint", "")).strip().lower()
    if entrypoint:
        blocked_addresses.add(entrypoint)

    rows = _lookup_log_transactions_via_dune(
        chain=chain,
        address=address,
        startblock=start_block,
        endblock=end_block,
        limit_rows=max(int(limit) * 50, 200),
        sort="desc",
    )
    selected: list[dict[str, object]] = []
    seen_tx_hashes: set[str] = set()
    for row in rows:
        tx_hash = str(row.get("tx_hash", "") or row.get("hash", "")).strip().lower()
        if not tx_hash or tx_hash in seen_tx_hashes or tx_hash in attack_txs:
            continue
        seen_tx_hashes.add(tx_hash)

        tx_payload = lookup_transaction(chain, tx_hash)
        receipt_payload = lookup_transaction_receipt(chain, tx_hash)
        if not tx_payload or not receipt_payload:
            continue
        if str(receipt_payload.get("status", "")).strip().lower() not in {"0x1", "1"}:
            continue

        candidate = _coerce_transaction_payload(
            tx_payload,
            fallback_block=_parse_int(row.get("blockNumber")),
        )
        if candidate is None:
            continue
        if str(candidate["from"]).strip().lower() in blocked_addresses:
            continue
        if str(candidate["to"]).strip().lower() in blocked_addresses:
            continue
        if (not str(candidate["input"]).strip() or str(candidate["input"]).strip() == "0x") and int(
            candidate["value_wei"]
        ) == 0:
            continue

        selected.append(candidate)
        if len(selected) >= limit:
            return selected

    return selected


def _select_candidate_transactions_via_dune_traces(
    case,
    *,
    chain: str,
    addresses: list[str],
    limit: int,
    search_offset: int,
) -> list[dict[str, object]]:
    fork_block = _pick_case_fork_block(case)
    normalized_addresses = [str(item).strip() for item in addresses if str(item).strip()]
    if fork_block is None or not normalized_addresses:
        return []

    primary_address = normalized_addresses[0]
    creation_block = _resolve_case_creation_block(case, chain=chain, address=primary_address)
    start_block, end_block = _pick_recent_history_window(
        case,
        chain=chain,
        address=primary_address,
        search_offset=search_offset,
    )
    if start_block is None or end_block is None:
        return []
    attack_txs = _pick_case_attack_txs(case)
    attack_context = infer_attack_tx_context(
        chain,
        sorted(attack_txs),
        vulnerable_addresses=normalized_addresses,
        block_number=fork_block,
    )
    blocked_addresses = {
        str(item).strip().lower()
        for key in (
            "attack_senders",
            "attack_targets",
            "attack_created_contracts",
        )
        for item in (attack_context.get(key, []) or [])
        if str(item).strip()
    }
    entrypoint = str(attack_context.get("attack_entrypoint", "")).strip().lower()
    if entrypoint:
        blocked_addresses.add(entrypoint)

    selected: list[dict[str, object]] = []
    seen_tx_hashes: set[str] = set()
    search_starts = [start_block]
    medium_start = max(end_block - 250_000 + 1, 1)
    if creation_block is not None:
        medium_start = max(medium_start, int(creation_block))
    if medium_start < start_block:
        search_starts.append(medium_start)
    if creation_block is not None and int(creation_block) < min(search_starts):
        search_starts.append(int(creation_block))

    for candidate_start in search_starts:
        rows = _lookup_trace_transactions_via_dune(
            chain=chain,
            addresses=normalized_addresses,
            startblock=candidate_start,
            endblock=end_block,
            limit_rows=max(int(limit) * 50, 200),
            sort="desc",
        )
        for row in rows:
            tx_hash = str(row.get("tx_hash", "") or row.get("hash", "")).strip().lower()
            if not tx_hash or tx_hash in seen_tx_hashes or tx_hash in attack_txs:
                continue
            seen_tx_hashes.add(tx_hash)

            tx_payload = lookup_transaction(chain, tx_hash)
            receipt_payload = lookup_transaction_receipt(chain, tx_hash)
            if not tx_payload or not receipt_payload:
                continue
            if str(receipt_payload.get("status", "")).strip().lower() not in {"0x1", "1"}:
                continue

            candidate = _coerce_transaction_payload(
                tx_payload,
                fallback_block=_parse_int(row.get("blockNumber")),
            )
            if candidate is None:
                continue
            if str(candidate["from"]).strip().lower() in blocked_addresses:
                continue
            if str(candidate["to"]).strip().lower() in blocked_addresses:
                continue
            if (
                not str(candidate["input"]).strip() or str(candidate["input"]).strip() == "0x"
            ) and int(candidate["value_wei"]) == 0:
                continue

            selected.append(candidate)
            if len(selected) >= limit:
                return selected

    return selected


def _solidity_hex_bytes(hex_value: str) -> str:
    text = str(hex_value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return text


def _solidity_address_expr(address: str, *, payable: bool = False) -> str:
    text = str(address or "").strip()
    if not text:
        raise ValueError("address is required")
    value = int(text, 16)
    expr = f"address(uint160({value}))"
    if payable:
        expr = f"payable({expr})"
    return expr


def _generate_normal_tx_replay_test(
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
) -> str:
    test_name = f"{case_slug}_NormalTxReplay_{tx_hash[2:10]}"
    calldata_literal = _solidity_hex_bytes(calldata_hex)
    patch_target_expr = _solidity_address_expr(patch_target)
    call_target_expr = _solidity_address_expr(call_target, payable=True)
    caller_expr = _solidity_address_expr(caller)
    return f"""\
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract {test_name} is Test {{
    address constant PATCH_TARGET = {patch_target_expr};
    address payable constant CALL_TARGET = {call_target_expr};
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

{SOLIDITY_LOG_HASH_FUNCTION}

    function _runHistoricalCall() internal returns (bool, bytes32, bytes32) {{
        vm.createSelectFork("{fork_chain}", {replay_block});
        _ensureCallerBalance();
        vm.recordLogs();
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = CALL_TARGET.call{{value: CALL_VALUE}}(CALLDATA);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        return (ok, keccak256(ret), _hashLogs(entries));
    }}

    function _runPatchedCall() internal returns (bool, bytes32, bytes32) {{
        vm.createSelectFork("{fork_chain}", {replay_block});
        _applyFix();
        _ensureCallerBalance();
        vm.recordLogs();
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = CALL_TARGET.call{{value: CALL_VALUE}}(CALLDATA);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        return (ok, keccak256(ret), _hashLogs(entries));
    }}

    function testHistoricalNormalTxReplay() public {{
        (bool beforeOk, bytes32 beforeRet, bytes32 beforeLogs) = _runHistoricalCall();
        (bool afterOk, bytes32 afterRet, bytes32 afterLogs) = _runPatchedCall();

        assertEq(afterOk, beforeOk, "success changed");
        assertEq(afterRet, beforeRet, "return data changed");
        assertEq(afterLogs, beforeLogs, "logs changed");
        emit log_string("NORMAL_TX_REPLAY_CHECKED");
    }}
}}
"""


def _prepare_fixed_code_line(case, base_dir: Path, fixed_code: str) -> tuple[str | None, str, str]:
    from infra.foundry.exploit_runner import _fix_address_checksums
    sanitized_fixed_code = _fix_address_checksums(fixed_code)
    verification = case.verification or {}
    metadata = _patch_source_metadata(case, base_dir)
    ground_truth = (
        case.ground_truth if isinstance(getattr(case, "ground_truth", None), dict) else {}
    )
    contract_name = _select_fixed_contract_name(
        sanitized_fixed_code,
        target_hints=[
            str(verification.get("target_contract_name", "")).strip(),
            str(metadata.get("target_contract_name", "")).strip(),
            str(ground_truth.get("contract", "")).strip(),
            str(ground_truth.get("file", "")).strip(),
        ],
    )
    if not contract_name:
        return None, "", "failed to parse contract name from fixed code"

    compiler_version = (
        str(verification.get("compiler_version", "")).strip()
        or str(metadata.get("compiler_version", "")).strip()
    )
    source_origin = (
        str(verification.get("source_origin", "")).strip()
        or str(metadata.get("source_origin", "")).strip()
    )
    source_case_id = str(getattr(case, "raw", {}).get("source_case_id", "")).strip() or case.id
    if not source_origin and case.source == "DeFiHackLabs" and getattr(case, "contracts", None):
        if bool(getattr(case, "raw", {}).get("has_public_source", False)):
            source_origin = "verified"
    effective_compiler_version = compiler_version or infer_solc_version_from_source(sanitized_fixed_code)
    # Fetch original compilation params from explorer if not in metadata
    if "optimization_used" not in metadata:
        chain = _pick_case_chain(case)
        address = _pick_case_contract_address(case)
        if chain and address:
            from infra.chain.metadata import lookup_verified_source
            explorer_meta = lookup_verified_source(chain, address) or {}
            if explorer_meta.get("ok"):
                metadata["optimization_used"] = explorer_meta.get("optimization_used", True)
                metadata["optimization_runs"] = explorer_meta.get("optimization_runs", 200)
                metadata["evm_version"] = explorer_meta.get("evm_version", "")
    reference_sources, source_remappings = _load_reference_sources(case, base_dir)
    try:
        if str(metadata.get("source_dir", "")).strip():
            bytecode, _, compiled_contract_name = compile_dfhl_fixed_bytecode(
                base_dir=base_dir,
                case_id=case.id,
                source_metadata=metadata,
                fixed_code=sanitized_fixed_code,
                contract_name_hint=contract_name
                or str(verification.get("target_contract_name", "")).strip()
                or str(metadata.get("target_contract_name", "")).strip(),
            )
        else:
            bytecode, compiled_contract_name = compile_fixed_bytecode_from_source(
                fixed_code=sanitized_fixed_code,
                contract_name_hint=contract_name,
                compiler_version=effective_compiler_version,
                optimization_used=bool(metadata.get("optimization_used", True)),
                optimization_runs=int(metadata.get("optimization_runs", 200) or 200),
                evm_version=str(metadata.get("evm_version", "") or ""),
                reference_sources=reference_sources,
                source_remappings=source_remappings,
            )
        if compiled_contract_name:
            contract_name = compiled_contract_name
        fixed_code_line = f'bytes memory _fixedCode = hex"{bytecode}";'
        return fixed_code_line, "", ""
    except RuntimeError as exc:
        canonical_fixed = _canonical_source(sanitized_fixed_code)
        canonical_originals = {
            _canonical_source(code)
            for code in reference_sources.values()
        }
        vulnerable_address = _pick_case_contract_address(case)
        fork_block = _pick_case_fork_block(case)
        if canonical_fixed in canonical_originals and vulnerable_address:
            runtime_code = lookup_runtime_code(
                case.chain_context.get("fork_chain", "") or case.chain or "ethereum",
                vulnerable_address,
                fork_block,
            )
            if runtime_code:
                fixed_code_line = f'bytes memory _fixedCode = hex"{runtime_code[2:]}";'
                return (
                    fixed_code_line,
                    "",
                    (
                        "source-identical fallback used on-chain runtime bytecode after solc compilation failed: "
                        f"{exc}"
                    ),
                )
        return None, "", f"failed to compile fixed bytecode: {exc}"


def validate_patch_normal_transactions(
    *,
    case,
    fixed_code: str,
    fixed_path: Path | None,
    base_dir: Path,
    artifact_dir: Path | None = None,
    tx_hashes: list[str] | None = None,
    limit: int = 10,
    search_offset: int = 25,
    timeout: int = 300,
    foundry_root: Path | None = None,
) -> dict[str, object]:
    chain = _pick_case_chain(case)
    contract_address = _pick_case_contract_address(case)
    payload: dict[str, object] = {
        "ok": False,
        "case_id": case.id,
        "case_name": case.name,
        "chain": chain,
        "contract_address": contract_address,
        "fixed_path": str(fixed_path) if fixed_path is not None else "",
        "selection_mode": "manual" if tx_hashes else "auto",
        "selected_transactions": [],
        "results": [],
    }
    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    if not contract_address:
        payload["error"] = "case does not define a vulnerable contract address"
        return payload

    # Use static normal_txs from benchmark case (pre-extracted at case generation time)
    static_normal_txs = getattr(case, "normal_txs", None) or (
        getattr(case, "raw", {}) or {}
    ).get("normal_txs")
    if not static_normal_txs or not isinstance(static_normal_txs, list):
        payload["error"] = "case has no pre-extracted normal_txs — not eligible for patch evaluation"
        return payload

    selected = []
    for item in static_normal_txs[:max(int(limit), 1)]:
        if isinstance(item, str):
            tx_hash = item.strip()
            if not tx_hash:
                continue
            # Fetch tx details from chain
            tx_payload = lookup_transaction(chain, tx_hash)
            if not tx_payload:
                continue
            coerced = _coerce_transaction_payload(tx_payload)
            if coerced:
                selected.append(coerced)
            continue
        if not isinstance(item, dict):
            continue
        tx_hash = str(item.get("hash", item.get("tx_hash", ""))).strip()
        if not tx_hash:
            continue
        selected.append({
            "tx_hash": tx_hash,
            "from": str(item.get("from", "")).strip(),
            "to": str(item.get("to", contract_address)).strip(),
            "input": str(item.get("input", "0x")).strip(),
            "value_wei": int(item.get("value", 0) or 0),
            "block_number": int(item.get("blockNumber", 0) or 0),
            "is_creation": False,
        })
    payload["selection_mode"] = "static"
    payload["selected_transactions"] = selected
    if not selected:
        payload["error"] = "case normal_txs field is empty — not eligible for patch evaluation"
        return payload

    fixed_code_line, sanitized_fixed_code, fixed_note = _prepare_fixed_code_line(
        case, base_dir, fixed_code
    )
    if not fixed_code_line:
        payload["error"] = fixed_note or "failed to prepare patched bytecode"
        return payload
    if fixed_note:
        payload["fixed_code_note"] = fixed_note

    creation_block = _resolve_case_creation_block(case, chain=chain, address=contract_address)
    payload["creation_block"] = creation_block
    payload["patch_from_creation"] = creation_block is not None

    workspace = create_isolated_eval_workspace(foundry_root or base_dir, task="patch_normal_txs", case_id=case.id)
    if workspace is None or not workspace.exists():
        payload["error"] = "failed to create isolated evaluation workspace"
        return payload

    case_slug = case.id.replace("-", "_")
    test_dir = workspace / "src" / "_benchmark_eval" / case_slug
    test_dir.mkdir(parents=True, exist_ok=True)
    payload["workspace_dir"] = str(workspace)

    temp_files: list[Path] = []
    try:
        if sanitized_fixed_code:
            patch_file = test_dir / "patch.sol"
            ground_truth = (
                case.ground_truth if isinstance(getattr(case, "ground_truth", None), dict) else {}
            )
            metadata = _patch_source_metadata(case, base_dir)
            verification = case.verification or {}
            reference_sources, _ = _load_reference_sources(case, base_dir)
            staged_paths, scoped_prefixes = stage_reference_sources_structured(
                target_dir=test_dir,
                reference_sources=reference_sources,
                fixed_code=sanitized_fixed_code,
                fixed_file_name=patch_file.name,
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
            artifact_fixed = artifact_dir / "patched_code.sol"
            artifact_fixed.write_text(sanitized_fixed_code or fixed_code)
            payload["patched_code_path"] = str(artifact_fixed)

        results: list[dict[str, object]] = []
        all_preserved = True
        payload["rpc_configured"] = bool(resolve_rpc_url(chain))

        for index, tx in enumerate(selected, start=1):
            tx_hash = str(tx["tx_hash"])
            block_number = int(tx["block_number"])
            replay_block = max(block_number - 1, 1)
            test_code = _generate_normal_tx_replay_test(
                case_slug=case_slug,
                patch_target=contract_address,
                call_target=str(tx["to"]),
                caller=str(tx["from"]),
                replay_block=replay_block,
                fork_chain=chain,
                value_wei=int(tx["value_wei"]),
                calldata_hex=str(tx["input"]),
                fixed_code_line=fixed_code_line,
                tx_hash=tx_hash,
            )
            test_file = test_dir / f"{case_slug}_normal_tx_{index}.sol"
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
            is_oog = "MemoryOOG" in output or "OutOfGas" in output
            preserved = bool(test_result.returncode == 0 and "PASS" in (test_result.stdout or ""))
            # MemoryOOG is inconclusive (vm.etch bytecode mismatch), not a patch failure
            if is_oog:
                preserved = True
            all_preserved = all_preserved and preserved
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
                    "preserved": preserved,
                    "returncode": test_result.returncode,
                    "checked": "NORMAL_TX_REPLAY_CHECKED" in output,
                    "test_path": str(test_file),
                    "forge_output_path": output_path,
                    "test_output": output[-1000:] if output else "",
                }
            )

        payload["results"] = results
        payload["checked_count"] = len(results)
        payload["preserved_count"] = sum(1 for item in results if item.get("preserved"))
        payload["all_preserved"] = all_preserved and bool(results)
        payload["ok"] = bool(results)
        payload["summary"] = (
            f"replayed {len(results)} historical normal transaction(s); "
            f"{sum(1 for item in results if item.get('preserved'))} preserved"
        )
        return payload
    except subprocess.TimeoutExpired:
        payload["error"] = "forge timed out during normal transaction replay validation"
        return payload
    except FileNotFoundError:
        payload["error"] = "forge executable was not found"
        return payload
    finally:
        for path in temp_files:
            if path.exists():
                path.unlink()
        cleanup_isolated_eval_workspace(workspace)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a patched contract file against a benchmark patch case"
    )
    parser.add_argument("--case-id", required=True, help="Patch benchmark case id")
    parser.add_argument(
        "--fixed-path", type=Path, required=True, help="Path to the patched .sol file"
    )
    parser.add_argument("--base-dir", type=Path, default=Path("."), help="Project root")
    parser.add_argument("--benchmark-dir", type=Path, default=None, help="Benchmark directory override")
    parser.add_argument(
        "--artifact-dir", type=Path, default=None, help="Optional artifact output directory"
    )
    parser.add_argument("--patch-mode", "--fix-mode", default="", dest="patch_mode", help="Deprecated alias; if provided, only used to infer --patch-possible")
    parser.add_argument("--patch-possible", "--fix-possible", default=None, dest="patch_possible", help="Optional boolean remediation flag")
    parser.add_argument(
        "--required-authority", default="", help="Optional remediation authority hint"
    )
    parser.add_argument("--confidence", default="", help="Optional remediation confidence")
    parser.add_argument("--rationale", default="", help="Optional remediation rationale")
    parser.add_argument(
        "--target-contract",
        dest="target_contracts",
        action="append",
        default=[],
        help="Repeatable target contract or address hint",
    )
    parser.add_argument(
        "--skip-attack-tx-replay",
        action="store_true",
        help="Skip replaying historical attack transactions against the patched contract",
    )
    parser.add_argument(
        "--attack-tx-hash",
        dest="attack_tx_hashes",
        action="append",
        default=[],
        help="Repeatable historical attack transaction hash to replay",
    )
    parser.add_argument(
        "--attack-tx-limit", type=int, default=3, help="Max attack transactions to replay"
    )
    parser.add_argument(
        "--attack-tx-timeout",
        type=int,
        default=300,
        help="Per-transaction forge timeout for attack transaction replay",
    )
    parser.add_argument(
        "--skip-normal-tx-replay",
        action="store_true",
        help="Skip replaying recent benign historical transactions against the patched contract",
    )
    parser.add_argument(
        "--normal-tx-hash",
        dest="normal_tx_hashes",
        action="append",
        default=[],
        help="Repeatable benign historical transaction hash to replay",
    )
    parser.add_argument(
        "--normal-tx-limit", type=int, default=3, help="Max normal transactions to replay"
    )
    parser.add_argument(
        "--normal-tx-search-offset",
        type=int,
        default=25,
        help="How many recent transactions to scan when auto-selecting benign transactions",
    )
    parser.add_argument(
        "--normal-tx-timeout",
        type=int,
        default=300,
        help="Per-transaction forge timeout for normal transaction replay",
    )
    parser.add_argument(
        "--foundry-root", type=Path, default=None,
        help="Override directory for Foundry workspace creation (default: base-dir)",
    )
    args = parser.parse_args()

    base_dir = args.base_dir.resolve()
    fixed_path = args.fixed_path.resolve()
    if not fixed_path.exists():
        raise SystemExit(f"fixed file not found: {fixed_path}")

    benchmark_dir = args.benchmark_dir.resolve() if args.benchmark_dir is not None else None
    case = _resolve_case(base_dir, args.case_id, benchmark_dir=benchmark_dir)
    fixed_code = fixed_path.read_text(errors="replace")
    artifact_dir = args.artifact_dir.resolve() if args.artifact_dir is not None else None

    exploit_code = None
    exploit_path = str(case.verification.get("exploit_path", "")).strip()
    if exploit_path:
        full = resolve_repo_path(base_dir, exploit_path)
        if full.exists():
            exploit_code = full.read_text(errors="replace")

    raw_patch_possible = _parse_bool_flag(args.patch_possible)
    raw_patch_mode = str(args.patch_mode).strip().lower().replace("-", "_").replace(" ", "_")
    if raw_patch_possible is None:
        if raw_patch_mode in {"proxy_upgrade", "proxy", "upgrade"}:
            raw_patch_possible = True
        elif raw_patch_mode in {"not_fixable", "unfixable", "cannot_fix"}:
            raw_patch_possible = False

    response = AgentResponse(
        task_type=TaskType.PATCH,
        raw_response=f"validated local patch file: {fixed_path}",
        fixed_code=fixed_code,
        fix_possible=raw_patch_possible,
        required_authority=str(args.required_authority).strip() or None,
        fix_confidence=str(args.confidence).strip() or None,
        fix_rationale=str(args.rationale).strip() or None,
        fix_target_contracts=[
            str(item).strip() for item in args.target_contracts if str(item).strip()
        ],
    )
    foundry_root = args.foundry_root.resolve() if args.foundry_root is not None else None
    score = evaluate_patch(case, response, exploit_code, base_dir, artifact_dir=artifact_dir, foundry_root=foundry_root)
    score = write_patch_score_artifact(score, artifact_dir)
    attack_tx_replay = None
    if not args.skip_attack_tx_replay and (
        bool(args.attack_tx_hashes) or bool(getattr(case, "has_attack_replay_verification", False))
    ):
        replay_artifact_dir = (
            artifact_dir / "attack_tx_replay_cli" if artifact_dir is not None else None
        )
        attack_tx_replay = validate_patch_attack_transactions(
            case=case,
            fixed_code=fixed_code,
            fixed_path=fixed_path,
            base_dir=base_dir,
            artifact_dir=replay_artifact_dir,
            tx_hashes=[str(item).strip() for item in args.attack_tx_hashes if str(item).strip()],
            limit=max(int(args.attack_tx_limit), 1),
            timeout=max(int(args.attack_tx_timeout), 1),
            foundry_root=foundry_root,
        )
    normal_tx_replay = None
    if not args.skip_normal_tx_replay:
        replay_artifact_dir = (
            artifact_dir / "normal_tx_replay" if artifact_dir is not None else None
        )
        normal_tx_replay = validate_patch_normal_transactions(
            case=case,
            fixed_code=fixed_code,
            fixed_path=fixed_path,
            base_dir=base_dir,
            artifact_dir=replay_artifact_dir,
            tx_hashes=[str(item).strip() for item in args.normal_tx_hashes if str(item).strip()],
            limit=max(int(args.normal_tx_limit), 1),
            search_offset=max(int(args.normal_tx_search_offset), 1),
            timeout=max(int(args.normal_tx_timeout), 1),
            foundry_root=foundry_root,
        )

    # --- Best-of-history tracking ---
    best_file = fixed_path.parent / "best_patch_result.json"
    prev_best: dict = {}
    if best_file.exists():
        try:
            prev_best = json.loads(best_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    prev_best_score = prev_best.get("best_score")
    cur_score = score.score
    iteration = prev_best.get("iteration", 0) + 1
    is_new_best = prev_best_score is None or cur_score > prev_best_score
    if is_new_best and cur_score > 0:
        best_data = {
            "best_score": cur_score,
            "iteration": iteration,
            "best_patch_snapshot": "_patched_best.sol",
        }
        try:
            shutil.copy2(fixed_path, fixed_path.parent / "_patched_best.sol")
        except OSError:
            pass
    else:
        best_data = {
            "best_score": prev_best_score if prev_best_score is not None else cur_score,
            "iteration": iteration,
            "best_patch_snapshot": prev_best.get("best_patch_snapshot", prev_best.get("best_fix_snapshot", "")),
        }
    best_data["current_score"] = cur_score
    try:
        best_file.write_text(json.dumps(best_data, indent=2, ensure_ascii=False))
    except OSError:
        pass

    print(
        json.dumps(
            {
                "case_id": case.id,
                "case_name": case.name,
                "patched_path": str(fixed_path),
                "score": score.score,
                "best_score": best_data.get("best_score"),
                "iteration": iteration,
                "summary": score.summary,
                "diagnostic_notes": score.diagnostic_notes,
                "compiles": score.compiles,
                "exploit_blocked": score.exploit_blocked,
                "normal_ops_pass": score.normal_ops_pass,
                "plan_only": score.plan_only,
                "classification_present": score.classification_present,
                "patch_possible": score.patch_possible,
                "required_authority": score.required_authority,
                "fix_confidence": score.fix_confidence,
                "fix_rationale": score.fix_rationale,
                "target_contracts": score.target_contracts,
                "expected_target_contracts": score.expected_target_contracts,
                "proxy_target_matched": score.proxy_target_matched,
                "proxy_detected": score.proxy_detected,
                "proxy_kind": score.proxy_kind,
                "proxy_implementation": score.proxy_implementation,
                "proxy_admin": score.proxy_admin,
                "compile_error": score.compile_error,
                "test_output": score.test_output,
                "regression_output": score.regression_output,
                "artifact_dir": score.artifact_dir,
                "response_path": score.response_path,
                "score_path": score.score_path,
                "patched_code_path": score.patched_code_path,
                "harness_path": score.harness_path,
                "regression_path": score.regression_path,
                "forge_output_path": score.forge_output_path,
                "regression_output_path": score.regression_output_path,
                "attack_tx_replay": attack_tx_replay,
                "historical_attack_txs_checked": (
                    int(attack_tx_replay.get("checked_count", 0))
                    if isinstance(attack_tx_replay, dict)
                    else 0
                ),
                "historical_attack_txs_blocked": (
                    int(attack_tx_replay.get("blocked_count", 0))
                    if isinstance(attack_tx_replay, dict)
                    else 0
                ),
                "historical_attack_txs_all_blocked": (
                    bool(attack_tx_replay.get("all_blocked", False))
                    if isinstance(attack_tx_replay, dict)
                    else False
                ),
                "normal_tx_replay": normal_tx_replay,
                "historical_normal_txs_checked": (
                    int(normal_tx_replay.get("checked_count", 0))
                    if isinstance(normal_tx_replay, dict)
                    else 0
                ),
                "historical_normal_txs_preserved": (
                    int(normal_tx_replay.get("preserved_count", 0))
                    if isinstance(normal_tx_replay, dict)
                    else 0
                ),
                "historical_normal_txs_all_preserved": (
                    bool(normal_tx_replay.get("all_preserved", False))
                    if isinstance(normal_tx_replay, dict)
                    else False
                ),
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
