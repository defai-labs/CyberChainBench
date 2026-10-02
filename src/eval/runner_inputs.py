"""Case-input assembly helpers for benchmark runner tasks."""

from __future__ import annotations

from pathlib import Path

from benchmark.tasks.detect.case import DetectCase
from benchmark.tasks.exploit.case import ExploitCase
from benchmark.tasks.patch.case import PatchCase as FixCase


def _detect_input_lines(
    case: DetectCase,
    *,
    tool_capable: bool,
    contract_code: dict[str, str],
) -> list[str]:
    _ = tool_capable
    _ = contract_code
    raw = dict(getattr(case, "raw", {}) or {})
    return [
        f"chain: {str(raw.get('chain', case.chain)).strip()}",
        f"contract_address: {str(raw.get('vulnerable_address', '')).strip()}",
        f"proxy_address: {str(raw.get('proxy_address', '')).strip()}",
        f"block_number: {raw.get('block_number', '')}",
    ]


def _exploit_input_lines(
    case: ExploitCase,
    base_dir: Path,
    *,
    review_mode: bool = False,
    benchmark_dir: Path | None = None,
) -> list[str]:
    _ = base_dir
    _ = review_mode
    _ = benchmark_dir
    raw = dict(getattr(case, "raw", {}) or {})
    return [
        f"chain: {str(raw.get('chain', case.chain)).strip()}",
        f"contract_address: {str(raw.get('vulnerable_address', '')).strip()}",
        f"type: {str(raw.get('type', '')).strip()}",
        f"file: {str(raw.get('file', '')).strip()}",
        f"function: {str(raw.get('function', '')).strip()}",
        f"proxy_address: {str(raw.get('proxy_address', '')).strip()}",
        f"block_number: {raw.get('block_number', '')}",
    ]


def _fix_input_lines(
    case: FixCase,
    base_dir: Path,
    *,
    contract_code: dict[str, str] | None = None,
    proxy_info: dict[str, object] | None = None,
    review_mode: bool = False,
    benchmark_dir: Path | None = None,
) -> list[str]:
    _ = base_dir
    _ = contract_code
    _ = proxy_info
    _ = review_mode
    _ = benchmark_dir
    raw = dict(getattr(case, "raw", {}) or {})
    raw_proxy = raw.get("proxy_address")
    proxy_address = "" if raw_proxy is None else str(raw_proxy).strip()
    lines = [
        f"chain: {str(raw.get('chain', case.chain)).strip()}",
        f"contract_address: {str(raw.get('vulnerable_address', '')).strip()}",
        f"type: {str(raw.get('type', '')).strip()}",
        f"file: {str(raw.get('file', '')).strip()}",
        f"function: {str(raw.get('function', '')).strip()}",
        f"proxy_address: {proxy_address}",
        f"block_number: {raw.get('block_number', '')}",
    ]
    attack_txs = raw.get("attack_txs", [])
    if isinstance(attack_txs, list):
        txs = [str(item).strip() for item in attack_txs if str(item).strip()]
        if txs:
            lines.append("attack_txs: " + ", ".join(txs[:3]))
    return lines


__all__ = ["_detect_input_lines", "_exploit_input_lines", "_fix_input_lines"]
