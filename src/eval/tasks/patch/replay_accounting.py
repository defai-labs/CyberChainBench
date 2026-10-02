"""Fail-closed accounting for historical transaction replay results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


ReplayRow = Mapping[str, Any]


def _completed(row: ReplayRow) -> bool:
    return bool(
        row.get("checked")
        and row.get("returncode") == 0
        and not row.get("resource_failure")
    )


def _base_counts(results: Sequence[ReplayRow], *, selected_count: int) -> dict[str, object]:
    checked_count = sum(1 for row in results if row.get("checked"))
    usable_count = sum(1 for row in results if _completed(row))
    all_selected_usable = bool(selected_count) and (
        len(results) == selected_count and usable_count == selected_count
    )
    return {
        "checked_count": checked_count,
        "ok": all_selected_usable,
    }


def summarize_normal_replay_results(
    results: Sequence[ReplayRow],
    *,
    selected_count: int,
) -> dict[str, object]:
    """Count only completed normal replay oracles and reject partial coverage."""

    summary = _base_counts(results, selected_count=selected_count)
    preserved_count = sum(
        1 for row in results if row.get("checked") and row.get("preserved")
    )
    summary.update(
        {
            "preserved_count": preserved_count,
            "all_preserved": bool(summary["ok"] and preserved_count == selected_count),
        }
    )
    return summary


def summarize_attack_replay_results(
    results: Sequence[ReplayRow],
    *,
    selected_count: int,
) -> dict[str, object]:
    """Count only completed attack replay oracles and reject partial coverage."""

    summary = _base_counts(results, selected_count=selected_count)
    blocked_count = sum(1 for row in results if row.get("checked") and row.get("blocked"))
    summary.update(
        {
            "blocked_count": blocked_count,
            "all_blocked": bool(summary["ok"] and blocked_count == selected_count),
        }
    )
    return summary
