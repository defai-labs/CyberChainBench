from __future__ import annotations

import unittest

from eval.tasks.patch.replay_accounting import (
    summarize_attack_replay_results,
    summarize_normal_replay_results,
)
from infra.cli.validate_patch import _generate_normal_tx_replay_test


class NormalReplayProducerTests(unittest.TestCase):
    def test_checked_marker_precedes_semantic_assertions(self) -> None:
        source = _generate_normal_tx_replay_test(
            case_slug="bench_test",
            patch_target="0x1111111111111111111111111111111111111111",
            call_target="0x2222222222222222222222222222222222222222",
            caller="0x3333333333333333333333333333333333333333",
            replay_block=123,
            fork_chain="ethereum",
            value_wei=0,
            calldata_hex="0x1234",
            fixed_code_line='bytes memory _fixedCode = hex"00";',
            tx_hash="0x" + "44" * 32,
        )

        comparison = """
        emit log_string("NORMAL_TX_REPLAY_CHECKED");
        assertEq(afterOk, beforeOk, "success changed");
        assertEq(afterRet, beforeRet, "return data changed");
        assertEq(afterLogs, beforeLogs, "logs changed");
"""
        self.assertIn(comparison, source)
        self.assertLess(source.index("_runHistoricalCall();"), source.index(comparison))
        self.assertLess(source.index("_runPatchedCall();"), source.index(comparison))

        semantic_failure = summarize_normal_replay_results(
            [{"checked": True, "preserved": False, "returncode": 1}],
            selected_count=1,
        )
        self.assertEqual(semantic_failure["checked_count"], 1)
        self.assertFalse(semantic_failure["ok"])
        self.assertFalse(semantic_failure["all_preserved"])


class NormalReplayAccountingTests(unittest.TestCase):
    def test_failed_rpc_rows_are_not_counted_as_checked(self) -> None:
        rows = [
            {"checked": False, "preserved": False, "returncode": 1}
            for _ in range(3)
        ]

        self.assertEqual(
            summarize_normal_replay_results(rows, selected_count=3),
            {
                "checked_count": 0,
                "ok": False,
                "preserved_count": 0,
                "all_preserved": False,
            },
        )

    def test_all_successful_rows_are_admitted(self) -> None:
        rows = [
            {"checked": True, "preserved": True, "returncode": 0},
            {"checked": True, "preserved": True, "returncode": 0},
        ]

        self.assertEqual(
            summarize_normal_replay_results(rows, selected_count=2),
            {
                "checked_count": 2,
                "ok": True,
                "preserved_count": 2,
                "all_preserved": True,
            },
        )

    def test_mixed_and_resource_failed_rows_fail_closed(self) -> None:
        rows = [
            {"checked": True, "preserved": True, "returncode": 0},
            {
                "checked": False,
                "preserved": True,
                "returncode": 1,
                "resource_failure": True,
            },
        ]

        self.assertEqual(
            summarize_normal_replay_results(rows, selected_count=2),
            {
                "checked_count": 1,
                "ok": False,
                "preserved_count": 1,
                "all_preserved": False,
            },
        )

    def test_zero_rows_are_not_admitted(self) -> None:
        result = summarize_normal_replay_results([], selected_count=1)

        self.assertFalse(result["ok"])
        self.assertFalse(result["all_preserved"])

    def test_checked_semantic_change_is_valid_coverage_but_not_preserved(self) -> None:
        rows = [{"checked": True, "preserved": False, "returncode": 0}]

        result = summarize_normal_replay_results(rows, selected_count=1)

        self.assertEqual(result["checked_count"], 1)
        self.assertTrue(result["ok"])
        self.assertEqual(result["preserved_count"], 0)
        self.assertFalse(result["all_preserved"])

    def test_checked_resource_failure_is_counted_but_not_admitted(self) -> None:
        rows = [
            {
                "checked": True,
                "preserved": True,
                "returncode": 0,
                "resource_failure": True,
            }
        ]

        result = summarize_normal_replay_results(rows, selected_count=1)

        self.assertEqual(result["checked_count"], 1)
        self.assertEqual(result["preserved_count"], 1)
        self.assertFalse(result["ok"])
        self.assertFalse(result["all_preserved"])


class AttackReplayAccountingTests(unittest.TestCase):
    def test_all_successful_rows_are_admitted(self) -> None:
        rows = [
            {"checked": True, "blocked": True, "returncode": 0},
            {"checked": True, "blocked": True, "returncode": 0},
        ]

        self.assertEqual(
            summarize_attack_replay_results(rows, selected_count=2),
            {
                "checked_count": 2,
                "ok": True,
                "blocked_count": 2,
                "all_blocked": True,
            },
        )

    def test_mixed_rows_fail_closed(self) -> None:
        rows = [
            {"checked": True, "blocked": True, "returncode": 0},
            {"checked": False, "blocked": False, "returncode": 1},
        ]

        self.assertEqual(
            summarize_attack_replay_results(rows, selected_count=2),
            {
                "checked_count": 1,
                "ok": False,
                "blocked_count": 1,
                "all_blocked": False,
            },
        )

    def test_zero_usable_rows_are_not_admitted(self) -> None:
        rows = [
            {
                "checked": False,
                "blocked": True,
                "returncode": 1,
                "resource_failure": True,
            }
        ]

        result = summarize_attack_replay_results(rows, selected_count=1)

        self.assertEqual(result["blocked_count"], 0)
        self.assertFalse(result["ok"])
        self.assertFalse(result["all_blocked"])

    def test_checked_unblocked_attack_is_valid_coverage(self) -> None:
        rows = [{"checked": True, "blocked": False, "returncode": 0}]

        result = summarize_attack_replay_results(rows, selected_count=1)

        self.assertEqual(result["checked_count"], 1)
        self.assertTrue(result["ok"])
        self.assertEqual(result["blocked_count"], 0)
        self.assertFalse(result["all_blocked"])


if __name__ == "__main__":
    unittest.main()
