from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from infra.solidity.fixed_sources import (
    resolve_staged_source_path,
    stage_reference_sources_structured,
)
from infra.foundry.workspace import write_structured_source_remappings
from infra.solidity.legacy import _forge_compile_fallback


class SoliditySourcePathTests(unittest.TestCase):
    def test_root_relative_logical_path_stays_inside_staging_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            destination = resolve_staged_source_path(root, "/contracts/Token.sol")

            self.assertEqual(destination, root / "contracts" / "Token.sol")

    def test_harmless_relative_segments_remain_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for source_path in ("./contracts/Token.sol", "contracts//Token.sol"):
                with self.subTest(source_path=source_path):
                    self.assertEqual(
                        resolve_staged_source_path(root, source_path),
                        root / "contracts" / "Token.sol",
                    )

    def test_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "unsafe Solidity source path"):
                resolve_staged_source_path(Path(temp_dir), "/contracts/../../outside.sol")

    def test_unsupported_source_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for source_path in (
                "/",
                "//contracts/Token.sol",
                "C:/contracts/Token.sol",
                r"contracts\Token.sol",
            ):
                with self.subTest(source_path=source_path):
                    with self.assertRaises(RuntimeError):
                        resolve_staged_source_path(root, source_path)

    def test_normalized_source_path_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "duplicate staged Solidity source path"):
                stage_reference_sources_structured(
                    target_dir=Path(temp_dir),
                    reference_sources={
                        "/contracts/Token.sol": "contract Token {}",
                        "contracts/Token.sol": "contract OtherToken {}",
                    },
                    fixed_code="contract Token {}",
                    fixed_file_name="patch.sol",
                    target_hints=["Token"],
                )

    def test_structured_remappings_use_confined_root_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            write_structured_source_remappings(
                workspace,
                "_benchmark_eval/case",
                {"/Root.sol", "/contracts", "@openzeppelin"},
            )

            self.assertEqual(
                (workspace / "remappings.txt").read_text().splitlines(),
                [
                    "/Root.sol=src/_benchmark_eval/case/Root.sol",
                    "/contracts/=src/_benchmark_eval/case/contracts/",
                    "@openzeppelin/=src/_benchmark_eval/case/@openzeppelin/",
                ],
            )

    def test_rooted_scoped_package_keeps_package_import_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            staged, prefixes = stage_reference_sources_structured(
                target_dir=root,
                reference_sources={"/@scope/package/Token.sol": "contract Token {}"},
                fixed_code="contract Token { function fixedVersion() external {} }",
                fixed_file_name="patch.sol",
                target_hints=["Token"],
            )

            self.assertIn(root / "@scope" / "package" / "Token.sol", staged)
            self.assertEqual(prefixes, {"@scope", "/@scope"})

    def test_structured_staging_confines_root_relative_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            staged, prefixes = stage_reference_sources_structured(
                target_dir=root,
                reference_sources={
                    "/contracts/Token.sol": "contract Token {}",
                    "/contracts/Dependency.sol": "contract Dependency {}",
                },
                fixed_code="contract Token { function fixedVersion() external {} }",
                fixed_file_name="patch.sol",
                target_hints=["Token"],
            )

            self.assertIn(root / "contracts" / "Token.sol", staged)
            self.assertIn(root / "contracts" / "Dependency.sol", staged)
            self.assertTrue((root / "contracts" / "Token.sol").is_file())
            self.assertEqual(prefixes, {"/contracts"})

    def test_forge_fallback_confines_root_relative_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir) / "forge-project"
            project.mkdir()
            out_dir = project / "out"

            def fake_run(*_args, **_kwargs):
                out_dir.mkdir(parents=True, exist_ok=True)
                return subprocess.CompletedProcess([], 0, "", "")

            with (
                mock.patch("infra.solidity.legacy.tempfile.mkdtemp", return_value=str(project)),
                mock.patch("infra.solidity.legacy.shutil.rmtree"),
                mock.patch("infra.solidity.legacy._build_foundry_env", return_value={}),
                mock.patch("infra.solidity.legacy._resolve_forge_bin", return_value="forge"),
                mock.patch("infra.solidity.legacy.subprocess.run", side_effect=fake_run),
                mock.patch(
                    "infra.solidity.legacy._extract_bytecode_from_forge_out",
                    return_value=("6000", "Token"),
                ),
            ):
                result = _forge_compile_fallback(
                    {
                        "fix.sol": "contract Token { function fixedVersion() external {} }",
                        "/contracts/Token.sol": "contract Token {}",
                        "/@scope/package/Library.sol": "library Library {}",
                        "/Root.sol": "contract Root {}",
                    },
                    compiler_version="0.8.17",
                    contract_name_hint="Token",
                    target_file="fix.sol",
                    source_remappings=["alias/=/contracts/"],
                )

            self.assertEqual(result, ("6000", "Token"))
            self.assertEqual(
                (project / "src" / "contracts" / "Token.sol").read_text(),
                "contract Token {}",
            )
            self.assertIn(
                "fixedVersion",
                (project / "src" / "fix.sol").read_text(),
            )
            self.assertEqual(
                (project / "remappings.txt").read_text().splitlines(),
                [
                    "alias/=src/contracts/",
                    "/contracts/=src/contracts/",
                    "@scope/=src/@scope/",
                    "/@scope/=src/@scope/",
                    "/Root.sol=src/Root.sol",
                ],
            )


if __name__ == "__main__":
    unittest.main()
