from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agents.task_agent.base import AgentResponse, TaskType
from eval.tasks.patch.evaluator import evaluate_patch
from infra.cli.validate_patch import _prepare_fixed_code_line, _resolve_case


def _case() -> SimpleNamespace:
    return SimpleNamespace(
        id="bench-source-identity",
        raw={"file": "contracts/Target.sol", "fixable": True},
        contracts={"vulnerable_address": "0x" + "11" * 20},
        verification={},
        ground_truth={},
        source="public",
        chain="ethereum",
        chain_context={"fork_chain": "ethereum", "fork_block": 100},
        state_context={},
        remediation={},
    )


class PatchSourceIdentityCallerTests(unittest.TestCase):
    def test_workspace_case_retains_public_case_input_file_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            case_data = Path(temp_dir) / "case_data.json"
            case_data.write_text(
                json.dumps(
                    {
                        "id": "bench-source-identity",
                        "name": "source identity",
                        "source": "public",
                        "contracts": {},
                    }
                )
            )
            with (
                mock.patch("infra.cli.validate_patch._WORKSPACE_CASE_DATA", case_data),
                mock.patch(
                    "infra.cli.validate_patch._workspace_public_file_hint",
                    return_value="contracts/Target.sol",
                ),
            ):
                case = _resolve_case(Path(temp_dir), "bench-source-identity")

        self.assertEqual(case.raw["file"], "contracts/Target.sol")
        self.assertEqual(case.ground_truth["file"], "contracts/Target.sol")

    def test_cli_passes_exact_public_source_identity_to_compiler(self) -> None:
        case = _case()
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "contracts/Dependency.sol": "library Dependency {}",
        }
        candidate = "contract Target { function fixedVersion() external {} }"

        with (
            mock.patch(
                "infra.cli.validate_patch._patch_source_metadata",
                return_value={
                    "compiler_version": "0.8.20",
                    "optimization_used": True,
                    "optimization_runs": 200,
                },
            ),
            mock.patch(
                "infra.cli.validate_patch._load_reference_sources",
                return_value=(sources, [], {"contract_name": "Target"}),
            ),
            mock.patch(
                "infra.cli.validate_patch.compile_fixed_bytecode_from_source",
                return_value=("6001", "Target"),
            ) as compile_fixed,
        ):
            fixed_line, sanitized, note = _prepare_fixed_code_line(case, Path("."), candidate)

        self.assertEqual(fixed_line, 'bytes memory _fixedCode = hex"6001";')
        self.assertEqual((sanitized, note), ("", ""))
        self.assertEqual(
            compile_fixed.call_args.kwargs["target_source_unit"],
            "contracts/Target.sol",
        )
        self.assertEqual(
            compile_fixed.call_args.kwargs["artifact_source_unit"],
            "contracts/Target.sol",
        )
        self.assertEqual(compile_fixed.call_args.kwargs["contract_name_hint"], "Target")

    def test_cli_unchanged_fallback_does_not_match_a_dependency(self) -> None:
        case = _case()
        dependency = "library Dependency { function value() internal pure returns (uint256) { return 1; } }"
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "contracts/Dependency.sol": dependency,
        }

        with (
            mock.patch(
                "infra.cli.validate_patch._patch_source_metadata",
                return_value={"compiler_version": "0.8.20", "optimization_used": True},
            ),
            mock.patch(
                "infra.cli.validate_patch._load_reference_sources",
                return_value=(sources, [], {"contract_name": "Target"}),
            ),
            mock.patch(
                "infra.cli.validate_patch.compile_fixed_bytecode_from_source",
                side_effect=RuntimeError("compile failed"),
            ),
            mock.patch("infra.cli.validate_patch.lookup_runtime_code", return_value="0x6001") as runtime,
        ):
            fixed_line, _sanitized, note = _prepare_fixed_code_line(
                case,
                Path("."),
                dependency,
            )

        self.assertIsNone(fixed_line)
        self.assertIn("failed to compile fixed bytecode", note)
        runtime.assert_not_called()

    def test_cli_separates_patch_source_from_runtime_artifact_source(self) -> None:
        case = _case()
        case.raw["file"] = "contracts/CToken.sol"
        sources = {
            "contracts/CToken.sol": "contract CToken {}",
            "contracts/CErc20Delegate.sol": (
                'import "./CToken.sol";\ncontract CErc20Delegate is CToken {}'
            ),
        }

        with (
            mock.patch(
                "infra.cli.validate_patch._patch_source_metadata",
                return_value={"compiler_version": "0.8.20", "optimization_used": True},
            ),
            mock.patch(
                "infra.cli.validate_patch._load_reference_sources",
                return_value=(sources, [], {"contract_name": "CErc20Delegate"}),
            ),
            mock.patch(
                "infra.cli.validate_patch.compile_fixed_bytecode_from_source",
                return_value=("6003", "CErc20Delegate"),
            ) as compile_fixed,
        ):
            fixed_line, _sanitized, note = _prepare_fixed_code_line(
                case,
                Path("."),
                "contract CToken { function patchedBase() external {} }",
            )

        self.assertEqual(fixed_line, 'bytes memory _fixedCode = hex"6003";')
        self.assertEqual(note, "")
        self.assertEqual(
            compile_fixed.call_args.kwargs["target_source_unit"],
            "contracts/CToken.sol",
        )
        self.assertEqual(
            compile_fixed.call_args.kwargs["artifact_source_unit"],
            "contracts/CErc20Delegate.sol",
        )
        self.assertEqual(
            compile_fixed.call_args.kwargs["contract_name_hint"],
            "CErc20Delegate",
        )

    def test_cli_compiles_interface_only_patch_unit_for_trusted_runtime(self) -> None:
        case = _case()
        case.raw["file"] = "contracts/IBase.sol"
        sources = {
            "contracts/IBase.sol": "interface IBase {}",
            "contracts/Target.sol": (
                'import "./IBase.sol";\ncontract Target is IBase {}'
            ),
        }

        with (
            mock.patch(
                "infra.cli.validate_patch._patch_source_metadata",
                return_value={"compiler_version": "0.8.20", "optimization_used": True},
            ),
            mock.patch(
                "infra.cli.validate_patch._load_reference_sources",
                return_value=(sources, [], {"contract_name": "Target"}),
            ),
            mock.patch(
                "infra.cli.validate_patch.compile_fixed_bytecode_from_source",
                return_value=("6005", "Target"),
            ) as compile_fixed,
        ):
            fixed_line, _sanitized, note = _prepare_fixed_code_line(
                case,
                Path("."),
                "interface IBase { function value() external view returns (uint256); }",
            )

        self.assertEqual(fixed_line, 'bytes memory _fixedCode = hex"6005";')
        self.assertEqual(note, "")
        self.assertEqual(
            compile_fixed.call_args.kwargs["target_source_unit"],
            "contracts/IBase.sol",
        )
        self.assertEqual(
            compile_fixed.call_args.kwargs["artifact_source_unit"],
            "contracts/Target.sol",
        )

    def test_evaluator_compiles_declaration_free_patch_unit_for_trusted_runtime(self) -> None:
        case = _case()
        case.raw["file"] = "contracts/Types.sol"
        sources = {
            "contracts/Types.sol": "struct Shared { uint256 value; }",
            "contracts/Target.sol": (
                'import "./Types.sol";\ncontract Target { Shared private item; }'
            ),
        }
        response = AgentResponse(
            task_type=TaskType.PATCH,
            raw_response="",
            fixed_code="struct Shared { uint256 value; uint256 updatedAt; }",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir()
            (workspace / "src").mkdir()
            with (
                mock.patch("eval.tasks.patch.evaluator._apply_patch_expectations"),
                mock.patch(
                    "eval.tasks.patch.evaluator.create_isolated_eval_workspace",
                    return_value=workspace,
                ),
                mock.patch("eval.tasks.patch.evaluator.cleanup_isolated_eval_workspace"),
                mock.patch(
                    "eval.tasks.patch.evaluator._patch_source_metadata",
                    return_value={"compiler_version": "0.8.20"},
                ),
                mock.patch(
                    "eval.tasks.patch.evaluator._load_reference_sources",
                    return_value=(sources, [], {"contract_name": "Target"}),
                ),
                mock.patch(
                    "eval.tasks.patch.evaluator.compile_fixed_bytecode_from_source",
                    side_effect=RuntimeError("compile failed"),
                ) as compile_fixed,
                mock.patch("eval.tasks.patch.evaluator.lookup_runtime_code") as runtime,
            ):
                score = evaluate_patch(
                    case,
                    response,
                    "contract Exploit {}",
                    Path(temp_dir),
                )

        self.assertFalse(score.compiles)
        self.assertIn("compile failed", score.compile_error)
        self.assertEqual(
            compile_fixed.call_args.kwargs["target_source_unit"],
            "contracts/Types.sol",
        )
        self.assertEqual(
            compile_fixed.call_args.kwargs["artifact_source_unit"],
            "contracts/Target.sol",
        )
        runtime.assert_not_called()

    def test_evaluator_passes_exact_public_source_identity_to_compiler(self) -> None:
        case = _case()
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "contracts/Dependency.sol": "library Dependency {}",
        }
        response = AgentResponse(
            task_type=TaskType.PATCH,
            raw_response="",
            fixed_code="contract Target { function fixedVersion() external {} }",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir()
            (workspace / "src").mkdir()
            with (
                mock.patch("eval.tasks.patch.evaluator._apply_patch_expectations"),
                mock.patch(
                    "eval.tasks.patch.evaluator.create_isolated_eval_workspace",
                    return_value=workspace,
                ),
                mock.patch("eval.tasks.patch.evaluator.cleanup_isolated_eval_workspace"),
                mock.patch(
                    "eval.tasks.patch.evaluator._patch_source_metadata",
                    return_value={"compiler_version": "0.8.20"},
                ),
                mock.patch(
                    "eval.tasks.patch.evaluator._load_reference_sources",
                    return_value=(sources, [], {"contract_name": "Target"}),
                ),
                mock.patch(
                    "eval.tasks.patch.evaluator.compile_fixed_bytecode_from_source",
                    side_effect=RuntimeError("compile failed"),
                ) as compile_fixed,
                mock.patch("eval.tasks.patch.evaluator.lookup_runtime_code") as runtime,
            ):
                score = evaluate_patch(
                    case,
                    response,
                    "contract Exploit {}",
                    Path(temp_dir),
                )

        self.assertFalse(score.compiles)
        self.assertIn("compile failed", score.compile_error)
        self.assertEqual(
            compile_fixed.call_args.kwargs["target_source_unit"],
            "contracts/Target.sol",
        )
        self.assertEqual(
            compile_fixed.call_args.kwargs["artifact_source_unit"],
            "contracts/Target.sol",
        )
        self.assertEqual(compile_fixed.call_args.kwargs["contract_name_hint"], "Target")
        runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()
