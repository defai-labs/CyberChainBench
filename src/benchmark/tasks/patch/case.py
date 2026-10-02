"""Patch benchmark case type."""

from __future__ import annotations

from dataclasses import dataclass, field
import ast
import json

from benchmark.base import _CaseBase




def _coerce_string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
            except Exception:
                continue
            if isinstance(parsed, (list, tuple)):
                return [str(item).strip() for item in parsed if str(item).strip()]
        return [text]
    return []


@dataclass
class PatchCase(_CaseBase):
    """A single patch benchmark case."""

    analysis_inputs: dict = field(default_factory=dict)
    ground_truth: dict = field(default_factory=dict)
    vulnerability_description: str = ""
    verification: dict = field(default_factory=dict)
    remediation: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> PatchCase:
        contracts = dict(data.get("contracts", {}) or {})
        verification = dict(data.get("verification", {}) or {})
        exploit_path = str(contracts.get("exploit", "")).strip()
        if exploit_path and not str(verification.get("exploit_path", "")).strip():
            verification["exploit_path"] = exploit_path

        ground_truth = dict(data.get("ground_truth", {}) or {})
        flat_vulnerable = str(data.get("vulnerable_address", "")).strip()
        flat_type = str(data.get("type", "")).strip()
        flat_file = str(data.get("file", "")).strip()
        flat_function = str(data.get("function", "")).strip()
        raw_proxy = data.get("proxy_address")
        flat_proxy = "" if raw_proxy is None else str(raw_proxy).strip()
        flat_fixable = data.get("fixable") if isinstance(data.get("fixable"), bool) else None
        flat_attack_txs = _coerce_string_list(data.get("attack_txs", []))
        flat_block_raw = data.get("block_number") if data.get("block_number") not in (None, "") else data.get("block")
        try:
            flat_block_number = int(flat_block_raw) if flat_block_raw not in (None, "") else None
        except (TypeError, ValueError):
            flat_block_number = None

        vulnerable_address = str(
            flat_vulnerable
            or ground_truth.get("vulnerable_address", "")
            or ground_truth.get("vulnerable_contract", "")
            or contracts.get("vulnerable_address", "")
        ).strip()
        ground_truth.pop("vulnerable_contract", None)
        if vulnerable_address and not str(ground_truth.get("vulnerable_address", "")).strip():
            ground_truth["vulnerable_address"] = vulnerable_address
        if flat_type and not str(ground_truth.get("type", "")).strip():
            ground_truth["type"] = flat_type
        if flat_file and not str(ground_truth.get("file", "")).strip():
            ground_truth["file"] = flat_file
        if flat_function and not str(ground_truth.get("function", "")).strip():
            ground_truth["function"] = flat_function
        if vulnerable_address and not str(contracts.get("vulnerable_address", "")).strip():
            contracts["vulnerable_address"] = vulnerable_address

        chain_context = dict(data.get("chain_context", {}) or {})
        if flat_attack_txs and not chain_context.get("attack_txs"):
            chain_context["attack_txs"] = flat_attack_txs
        if flat_block_number is not None:
            chain_context.setdefault("block", flat_block_number)
            chain_context.setdefault("fork_block", max(flat_block_number - 1, 1))

        remediation = data.get("remediation", {}) if isinstance(data.get("remediation"), dict) else {}
        if flat_proxy and not str(remediation.get("proxy_address", "")).strip():
            remediation = dict(remediation)
            remediation["proxy_address"] = flat_proxy
        if flat_fixable is False and not flat_proxy:
            remediation = dict(remediation)
            remediation.pop("proxy_address", None)

        return cls(
            id=data["id"],
            name=data["name"],
            source=data["source"],
            case_link=data.get("case_link", ""),
            category=str(data.get("category", "")).strip() or flat_type,
            severity=data.get("severity", ""),
            chain=data.get("chain", ""),
            date=data.get("date", ""),
            description=data.get("description", ""),
            contracts=contracts,
            language=data.get("language", ""),
            vm_family=data.get("vm_family", ""),
            cross_chain=bool(data.get("cross_chain", False)),
            chains_involved=data.get("chains_involved", []),
            analysis_inputs=data.get("analysis_inputs", {}),
            chain_context=chain_context,
            state_context=data.get("state_context", {}),
            annotation_hints=data.get("annotation_hints", {}) or {},
            ground_truth=ground_truth,
            vulnerability_description=data.get("vulnerability_description", "")
            or data.get("description", ""),
            verification=verification,
            remediation=remediation,
            raw=data,
        )

    @property
    def has_verification_exploit(self) -> bool:
        return bool(self.verification.get("exploit_path"))

    @property
    def attack_transactions(self) -> list[str]:
        chain_context = self.chain_context if isinstance(self.chain_context, dict) else {}
        seen: set[str] = set()
        ordered: list[str] = []
        raw_items = _coerce_string_list(chain_context.get("attack_txs", []))
        raw_items.extend(_coerce_string_list(chain_context.get("attack_tx_hashes", [])))
        for item in raw_items:
            tx_hash = str(item).strip()
            if not tx_hash:
                continue
            lowered = tx_hash.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            ordered.append(tx_hash)
        return ordered

    @property
    def has_attack_replay_verification(self) -> bool:
        return bool(self.attack_transactions)


# Backwards-compatible alias
FixCase = PatchCase
