from __future__ import annotations

import unittest
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from unittest.mock import patch

from benchmark.tasks.patch.case import PatchCase
from eval.runner_inputs import _fix_input_lines
from eval.tasks.patch import attack_replay
from infra.cli.validate_patch import _resolve_case

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_CASES = REPO_ROOT / "data" / "benchmark" / "cases"
VULNERABLE_ADDRESS = "0x1111111111111111111111111111111111111111"
PROXY_ADDRESS = "0x2222222222222222222222222222222222222222"


def _case_data(*, proxy_address: object = ...) -> dict:
    data = {
        "id": "bench-test",
        "name": "Patch proxy normalization test",
        "source": "unit-test",
        "vulnerable_address": VULNERABLE_ADDRESS,
    }
    if proxy_address is not ...:
        data["proxy_address"] = proxy_address
    return data


def _proxy_input_line(case: PatchCase) -> str:
    return next(
        line for line in _fix_input_lines(case, REPO_ROOT) if line.startswith("proxy_address:")
    )


class PatchCaseProxyAddressTests(unittest.TestCase):
    def test_null_proxy_address_remains_absent(self) -> None:
        case = PatchCase.from_json(_case_data(proxy_address=None))

        self.assertIsNone(case.raw.get("proxy_address"))
        self.assertNotIn("proxy_address", case.remediation)
        self.assertEqual(_proxy_input_line(case), "proxy_address: ")

    def test_missing_proxy_address_remains_absent(self) -> None:
        case = PatchCase.from_json(_case_data())

        self.assertIsNone(case.raw.get("proxy_address"))
        self.assertNotIn("proxy_address", case.remediation)
        self.assertEqual(_proxy_input_line(case), "proxy_address: ")

    def test_empty_proxy_address_remains_empty(self) -> None:
        case = PatchCase.from_json(_case_data(proxy_address=""))

        self.assertEqual(case.raw.get("proxy_address"), "")
        self.assertNotIn("proxy_address", case.remediation)
        self.assertEqual(_proxy_input_line(case), "proxy_address: ")

    def test_valid_proxy_address_is_preserved(self) -> None:
        case = PatchCase.from_json(_case_data(proxy_address=PROXY_ADDRESS))

        self.assertEqual(case.raw.get("proxy_address"), PROXY_ADDRESS)
        self.assertEqual(case.remediation.get("proxy_address"), PROXY_ADDRESS)
        self.assertEqual(_proxy_input_line(case), f"proxy_address: {PROXY_ADDRESS}")

    def test_bench_567_null_proxy_uses_vulnerable_address_for_replay(self) -> None:
        case = _resolve_case(REPO_ROOT, "bench-567", benchmark_dir=BENCHMARK_CASES)
        transaction = {
            "tx_hash": "0x" + "3" * 64,
            "from": "0x3333333333333333333333333333333333333333",
            "to": "0x4444444444444444444444444444444444444444",
            "input": "0x",
            "value_wei": 0,
            "block_number": 2,
            "is_creation": False,
        }

        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir()
            with (
                patch.object(
                    attack_replay,
                    "_select_attack_transactions",
                    return_value=([transaction], "case_attack_txs"),
                ),
                patch.object(attack_replay, "_resolve_case_creation_block", return_value=None),
                patch.object(
                    attack_replay,
                    "create_isolated_eval_workspace",
                    return_value=workspace,
                ),
                patch.object(attack_replay, "cleanup_isolated_eval_workspace"),
                patch.object(attack_replay, "resolve_rpc_url", return_value=None),
                patch.object(
                    attack_replay,
                    "_run_forge",
                    return_value=CompletedProcess([], 0, "ATTACK_TX_REPLAY_CHECKED", ""),
                ),
            ):
                result = attack_replay.validate_patch_attack_transactions(
                    case=case,
                    fixed_code="",
                    fixed_path=None,
                    base_dir=REPO_ROOT,
                    _fixed_code_line_override='bytes memory _fixedCode = hex"00";',
                )

        self.assertTrue(result["ok"])
        self.assertEqual(_proxy_input_line(case), "proxy_address: ")


if __name__ == "__main__":
    unittest.main()
