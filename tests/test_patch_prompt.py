"""Keep the public Patch instruction consistent with its executable score."""

from __future__ import annotations

import ast
import itertools
from pathlib import Path
import runpy
import unittest


ROOT = Path(__file__).resolve().parents[1]


def render_patch_instruction() -> str:
    """Execute the native renderer without importing paid-run dependencies."""
    benchmark_path = ROOT / "src/scripts/1_benchmark/benchmark.py"
    tree = ast.parse(benchmark_path.read_text())
    namespace = runpy.run_path(str(ROOT / "src/prompts/patch.py"))
    namespace.update(runpy.run_path(str(ROOT / "src/prompts/taxonomy.py")))
    nodes = [
        node for node in tree.body
        if (isinstance(node, ast.FunctionDef)
            and node.name in {"_get_type_descriptions", "_render_instruction"})
        or (isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "TOOL_GUIDES"
                    for target in node.targets))
    ]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(benchmark_path), "exec"), namespace)
    return namespace["_render_instruction"]("patch", None, [])


class PatchPromptTests(unittest.TestCase):
    def test_rendered_instruction_describes_binary_score_conditions(self) -> None:
        instruction = render_patch_instruction()
        self.assertFalse("partial credit" in instruction.lower())
        for requirement in (
            "Patch scoring is binary.", "not skipped",
            "passing unpatched baseline when one was checked",
            "the exploit to be blocked",
            "at least one historical normal transaction checked",
            "normal operations to pass", "All other outcomes score 0.",
        ):
            self.assertIn(requirement, instruction)

    def test_binary_conditions_match_every_scoring_boundary(self) -> None:
        score_type = runpy.run_path(str(ROOT / "src/eval/tasks/patch/score.py"))["PatchScore"]
        fields = ("skipped", "baseline_checked", "baseline_passed", "exploit_blocked",
                  "normal_ops_pass", "compiles")
        for flags in itertools.product((False, True), repeat=len(fields)):
            for count in (-1, 0, 1, 2):
                values = dict(zip(fields, flags), historical_normal_txs_checked=count)
                with self.subTest(**values):
                    expected = float(
                        not values["skipped"]
                        and (not values["baseline_checked"] or values["baseline_passed"])
                        and values["exploit_blocked"] and count > 0
                        and values["normal_ops_pass"]
                    )
                    self.assertEqual(score_type(**values).score, expected)


if __name__ == "__main__":
    unittest.main()
