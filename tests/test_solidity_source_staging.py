from __future__ import annotations

import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from infra.solidity.fixed_sources import (
    resolve_reference_contract_source_unit,
    resolve_staged_source_path,
    resolve_reference_source_unit,
    stage_reference_sources_structured,
)
from infra.foundry.workspace import write_structured_source_remappings
from infra.solidity.legacy import (
    _extract_bytecode_from_forge_out,
    _forge_compile_fallback,
    _pick_target_file,
    compile_dfhl_fixed_bytecode,
    compile_fixed_bytecode_from_source,
)


class SoliditySourcePathTests(unittest.TestCase):
    def test_full_source_unit_hint_wins_over_duplicate_contract_names(self) -> None:
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "vendor/Target.sol": "contract Target {}",
        }

        self.assertEqual(
            resolve_reference_source_unit(
                reference_sources=sources,
                source_unit_hints=["contracts/Target.sol"],
                contract_name_hint="Target",
            ),
            "contracts/Target.sol",
        )

    def test_ambiguous_source_unit_hint_is_rejected(self) -> None:
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "vendor/Target.sol": "contract Target {}",
        }

        with self.assertRaisesRegex(RuntimeError, "ambiguous verified source-unit basename"):
            resolve_reference_source_unit(
                reference_sources=sources,
                source_unit_hints=["Target.sol"],
                contract_name_hint="Target",
            )

    def test_absent_or_case_mismatched_source_unit_hint_is_rejected(self) -> None:
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "contracts/Dependency.sol": "library Dependency {}",
        }

        for hint in ("Missing.sol", "target.sol"):
            with self.subTest(hint=hint):
                with self.assertRaisesRegex(RuntimeError, "source-unit hint not found"):
                    resolve_reference_source_unit(
                        reference_sources=sources,
                        source_unit_hints=[hint],
                        contract_name_hint="Target",
                    )

    def test_unsafe_exact_source_unit_hint_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "invalid verified source-unit hint"):
            resolve_reference_source_unit(
                reference_sources={"../Target.sol": "contract Target {}"},
                source_unit_hints=["../Target.sol"],
                contract_name_hint="Target",
            )

    def test_conflicting_source_unit_hints_are_rejected(self) -> None:
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "vendor/Other.sol": "contract Other {}",
        }

        with self.assertRaisesRegex(RuntimeError, "conflicting verified source-unit hints"):
            resolve_reference_source_unit(
                reference_sources=sources,
                source_unit_hints=["contracts/Target.sol", "vendor/Other.sol"],
                contract_name_hint="Target",
            )

    def test_duplicate_contract_declarations_are_ambiguous_without_file_hint(self) -> None:
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "vendor/Other.sol": "contract Target {}",
        }

        with self.assertRaisesRegex(RuntimeError, "declared in multiple verified source units"):
            resolve_reference_source_unit(
                reference_sources=sources,
                contract_name_hint="Target",
            )

    def test_artifact_identity_ignores_comments_and_string_literals(self) -> None:
        sources = {
            "contracts/Decoy.sol": (
                'string constant TEXT = "contract Target {}";\n'
                "/* contract Target {} */\n"
                "// contract Target {}\n"
                "contract Decoy {}"
            ),
            "contracts/Target.sol": "pragma solidity ^0.8.20; contract Target {}",
        }

        self.assertEqual(
            resolve_reference_contract_source_unit(
                reference_sources=sources,
                contract_name="Target",
            ),
            "contracts/Target.sol",
        )

    def test_artifact_identity_accepts_solidity_dollar_identifiers(self) -> None:
        for contract_name in ("$Target", "Tar$get"):
            with self.subTest(contract_name=contract_name):
                self.assertEqual(
                    resolve_reference_contract_source_unit(
                        reference_sources={
                            "contracts/Target.sol": f"contract {contract_name} {{}}",
                        },
                        contract_name=contract_name,
                    ),
                    "contracts/Target.sol",
                )

    def test_artifact_identity_does_not_match_keyword_inside_identifier(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not declared"):
            resolve_reference_contract_source_unit(
                reference_sources={
                    "contracts/Decoy.sol": "$contract Target {}",
                },
                contract_name="Target",
            )

    def test_artifact_identity_rejects_missing_or_empty_trusted_contract(self) -> None:
        sources = {"contracts/Only.sol": "contract Other {}"}

        for contract_name, message in (
            ("", "missing trusted artifact contract name"),
            ("Target", "not declared in the verified source bundle"),
        ):
            with self.subTest(contract_name=contract_name):
                with self.assertRaisesRegex(RuntimeError, message):
                    resolve_reference_contract_source_unit(
                        reference_sources=sources,
                        contract_name=contract_name,
                    )

    def test_artifact_identity_rejects_duplicate_real_declarations(self) -> None:
        sources = {
            "contracts/Target.sol": "contract Target {}",
            "vendor/Target.sol": "contract Target {}",
        }

        with self.assertRaisesRegex(RuntimeError, "declared in multiple verified source units"):
            resolve_reference_contract_source_unit(
                reference_sources=sources,
                contract_name="Target",
            )

    def test_compile_replaces_only_exact_source_unit_and_selects_exact_contract(self) -> None:
        captured: dict = {}

        def compile_standard(payload, *, solc_binary):
            captured.update(payload)
            self.assertEqual(solc_binary, "/solc")
            return {
                "contracts": {
                    "contracts/Target.sol": {
                        "Target": {"evm": {"deployedBytecode": {"object": "6001"}}}
                    },
                    "vendor/Target.sol": {
                        "WrongTarget": {"evm": {"deployedBytecode": {"object": "6002"}}}
                    },
                }
            }

        fake_solcx = types.SimpleNamespace(
            compile_standard=compile_standard,
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )
        original_target = 'import "./Dependency.sol"; contract Target {}'
        candidate = (
            'import "./Dependency.sol"; '
            "contract Target { function fixedVersion() external pure returns (uint256) { return 1; } }"
        )
        sources = {
            "contracts/Target.sol": original_target,
            "contracts/Dependency.sol": "library Dependency {}",
            "vendor/Target.sol": "contract WrongTarget {}",
        }

        with (
            mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
            mock.patch("infra.solidity.legacy.get_or_install_solc", return_value="/solc"),
        ):
            bytecode, contract_name = compile_fixed_bytecode_from_source(
                fixed_code=candidate,
                contract_name_hint="Target",
                compiler_version="0.8.20",
                reference_sources=sources,
                target_source_unit="contracts/Target.sol",
                artifact_source_unit="contracts/Target.sol",
            )

        self.assertEqual((bytecode, contract_name), ("6001", "Target"))
        compiler_sources = captured["sources"]
        self.assertEqual(set(compiler_sources), set(sources))
        self.assertEqual(compiler_sources["contracts/Target.sol"]["content"], candidate)
        self.assertEqual(
            compiler_sources["contracts/Dependency.sol"]["content"],
            sources["contracts/Dependency.sol"],
        )
        self.assertEqual(
            compiler_sources["vendor/Target.sol"]["content"],
            sources["vendor/Target.sol"],
        )

    def test_compile_accepts_one_renamed_runtime_from_exact_patched_unit(self) -> None:
        fake_solcx = types.SimpleNamespace(
            compile_standard=lambda *_args, **_kwargs: {
                "contracts": {
                    "contracts/Target.sol": {
                        "PoC_CCBPATCH": {
                            "evm": {"deployedBytecode": {"object": "6001"}}
                        },
                        "IHelper": {"evm": {"deployedBytecode": {"object": ""}}},
                    },
                    "vendor/Other.sol": {
                        "Unrelated": {
                            "evm": {"deployedBytecode": {"object": "6002"}}
                        }
                    },
                }
            },
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )

        with (
            mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
            mock.patch("infra.solidity.legacy.get_or_install_solc", return_value="/solc"),
        ):
            result = compile_fixed_bytecode_from_source(
                fixed_code="contract PoC_CCBPATCH {}",
                contract_name_hint="Target",
                compiler_version="0.8.20",
                reference_sources={
                    "contracts/Target.sol": "contract Target {}",
                    "vendor/Other.sol": "contract Unrelated {}",
                },
                target_source_unit="contracts/Target.sol",
                artifact_source_unit="contracts/Target.sol",
            )

        self.assertEqual(result, ("6001", "PoC_CCBPATCH"))

    def test_compile_rejects_multiple_renamed_runtimes_from_patched_unit(self) -> None:
        fake_solcx = types.SimpleNamespace(
            compile_standard=lambda *_args, **_kwargs: {
                "contracts": {
                    "contracts/Target.sol": {
                        "First": {"evm": {"deployedBytecode": {"object": "6001"}}},
                        "Second": {"evm": {"deployedBytecode": {"object": "6002"}}},
                    }
                }
            },
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )

        with (
            mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
            mock.patch("infra.solidity.legacy.get_or_install_solc", return_value="/solc"),
            mock.patch(
                "infra.solidity.legacy._forge_compile_fallback",
                side_effect=RuntimeError("forge rejected ambiguous artifacts"),
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "expected one deployed runtime artifact.*found 2",
            ),
        ):
            compile_fixed_bytecode_from_source(
                fixed_code="contract First {} contract Second {}",
                contract_name_hint="Target",
                compiler_version="0.8.20",
                reference_sources={"contracts/Target.sol": "contract Target {}"},
                target_source_unit="contracts/Target.sol",
                artifact_source_unit="contracts/Target.sol",
            )

    def test_compile_does_not_select_trusted_name_from_wrong_source_unit(self) -> None:
        fake_solcx = types.SimpleNamespace(
            compile_standard=lambda *_args, **_kwargs: {
                "contracts": {
                    "contracts/Target.sol": {
                        "Other": {"evm": {"deployedBytecode": {"object": "6001"}}}
                    },
                    "vendor/Target.sol": {
                        "Target": {"evm": {"deployedBytecode": {"object": "6002"}}}
                    },
                }
            },
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )

        with (
            mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
            mock.patch("infra.solidity.legacy.get_or_install_solc", return_value="/solc"),
        ):
            result = compile_fixed_bytecode_from_source(
                fixed_code="contract Target {}",
                contract_name_hint="Target",
                compiler_version="0.8.20",
                reference_sources={
                    "contracts/Target.sol": "contract Target {}",
                    "vendor/Target.sol": "contract Other {}",
                },
                target_source_unit="contracts/Target.sol",
                artifact_source_unit="contracts/Target.sol",
            )

        self.assertEqual(result, ("6001", "Other"))

    def test_compile_separates_patched_base_unit_from_runtime_artifact_unit(self) -> None:
        captured: dict = {}

        def compile_standard(payload, *, solc_binary):
            captured.update(payload)
            return {
                "contracts": {
                    "contracts/CToken.sol": {
                        "CToken": {"evm": {"deployedBytecode": {"object": ""}}}
                    },
                    "contracts/CErc20Delegate.sol": {
                        "CErc20Delegate": {
                            "evm": {"deployedBytecode": {"object": "6003"}}
                        }
                    },
                }
            }

        fake_solcx = types.SimpleNamespace(
            compile_standard=compile_standard,
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )
        candidate = "contract CToken { function patchedBase() external {} }"
        sources = {
            "contracts/CToken.sol": "contract CToken {}",
            "contracts/CErc20Delegate.sol": (
                'import "./CToken.sol"; contract CErc20Delegate is CToken {}'
            ),
        }

        with (
            mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
            mock.patch("infra.solidity.legacy.get_or_install_solc", return_value="/solc"),
        ):
            bytecode, contract_name = compile_fixed_bytecode_from_source(
                fixed_code=candidate,
                contract_name_hint="CErc20Delegate",
                compiler_version="0.8.20",
                reference_sources=sources,
                target_source_unit="contracts/CToken.sol",
                artifact_source_unit="contracts/CErc20Delegate.sol",
            )

        self.assertEqual((bytecode, contract_name), ("6003", "CErc20Delegate"))
        self.assertEqual(captured["sources"]["contracts/CToken.sol"]["content"], candidate)
        self.assertEqual(
            captured["sources"]["contracts/CErc20Delegate.sol"]["content"],
            sources["contracts/CErc20Delegate.sol"],
        )

    def test_real_solc_compiles_interface_patch_into_concrete_runtime(self) -> None:
        sources = {
            "contracts/IBase.sol": (
                "pragma solidity ^0.8.20;\n"
                "interface IBase { function value() external view returns (uint256); }"
            ),
            "contracts/Target.sol": (
                "pragma solidity ^0.8.20;\n"
                'import "./IBase.sol";\n'
                "contract Target is IBase { "
                "function value() external pure returns (uint256) { return 1; } }"
            ),
        }

        bytecode, contract_name = compile_fixed_bytecode_from_source(
            fixed_code=(
                "pragma solidity ^0.8.20;\n"
                "interface IBase { function value() external view returns (uint256); }"
            ),
            contract_name_hint="Target",
            compiler_version="0.8.20",
            reference_sources=sources,
            target_source_unit="contracts/IBase.sol",
            artifact_source_unit="contracts/Target.sol",
        )

        self.assertEqual(contract_name, "Target")
        self.assertTrue(bytecode)

    def test_candidate_cannot_redirect_pre_resolved_runtime_artifact(self) -> None:
        captured: dict = {}

        def compile_standard(payload, *, solc_binary):
            captured.update(payload)
            return {
                "contracts": {
                    "contracts/CToken.sol": {
                        "CErc20Delegate": {
                            "evm": {"deployedBytecode": {"object": "6004"}}
                        }
                    },
                    "contracts/CErc20Delegate.sol": {
                        "CErc20Delegate": {
                            "evm": {"deployedBytecode": {"object": "6003"}}
                        }
                    },
                }
            }

        fake_solcx = types.SimpleNamespace(
            compile_standard=compile_standard,
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )
        sources = {
            "contracts/CToken.sol": "abstract contract CToken {}",
            "contracts/CErc20Delegate.sol": (
                'import "./CToken.sol";\ncontract CErc20Delegate is CToken {}'
            ),
        }

        with (
            mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
            mock.patch("infra.solidity.legacy.get_or_install_solc", return_value="/solc"),
        ):
            bytecode, contract_name = compile_fixed_bytecode_from_source(
                fixed_code="contract CErc20Delegate {}",
                contract_name_hint="CErc20Delegate",
                compiler_version="0.8.20",
                reference_sources=sources,
                target_source_unit="contracts/CToken.sol",
                artifact_source_unit="contracts/CErc20Delegate.sol",
            )

        self.assertEqual((bytecode, contract_name), ("6003", "CErc20Delegate"))
        self.assertEqual(
            captured["sources"]["contracts/CToken.sol"]["content"],
            "contract CErc20Delegate {}",
        )

    def test_renamed_runtime_fallback_is_disabled_for_dependency_patch(self) -> None:
        fake_solcx = types.SimpleNamespace(
            compile_standard=lambda *_args, **_kwargs: {
                "contracts": {
                    "contracts/CToken.sol": {
                        "PoC_CCBPATCH": {
                            "evm": {"deployedBytecode": {"object": "6004"}}
                        }
                    },
                    "contracts/CErc20Delegate.sol": {
                        "CErc20Delegate": {
                            "evm": {"deployedBytecode": {"object": ""}}
                        }
                    },
                }
            },
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )

        with (
            mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
            mock.patch("infra.solidity.legacy.get_or_install_solc", return_value="/solc"),
            mock.patch(
                "infra.solidity.legacy._forge_compile_fallback",
                side_effect=RuntimeError("forge rejected missing trusted runtime"),
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "no deployed bytecode produced.*CErc20Delegate",
            ),
        ):
            compile_fixed_bytecode_from_source(
                fixed_code="contract PoC_CCBPATCH {}",
                contract_name_hint="CErc20Delegate",
                compiler_version="0.8.20",
                reference_sources={
                    "contracts/CToken.sol": "abstract contract CToken {}",
                    "contracts/CErc20Delegate.sol": (
                        'import "./CToken.sol"; contract CErc20Delegate is CToken {}'
                    ),
                },
                target_source_unit="contracts/CToken.sol",
                artifact_source_unit="contracts/CErc20Delegate.sol",
            )

    def test_forge_artifact_selection_rejects_same_contract_from_wrong_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            wrong_dir = out_dir / "Wrong.sol"
            wrong_dir.mkdir()
            (wrong_dir / "Target.json").write_text(
                """{
                    "deployedBytecode": {"object": "0x6002"},
                    "metadata": {"settings": {"compilationTarget": {
                        "src/vendor/Target.sol": "Target"
                    }}}
                }"""
            )

            with self.assertRaisesRegex(RuntimeError, "no deployed bytecode"):
                _extract_bytecode_from_forge_out(
                    out_dir,
                    "Target",
                    "contracts/Target.sol",
                )

    def test_forge_artifact_selection_uses_exact_source_unit_and_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            for directory, source, bytecode in (
                ("Wrong.sol", "src/vendor/Target.sol", "0x6002"),
                ("Right.sol", "src/contracts/Target.sol", "0x6001"),
            ):
                artifact_dir = out_dir / directory
                artifact_dir.mkdir()
                (artifact_dir / "Target.json").write_text(
                    """{{
                        "deployedBytecode": {{"object": "{bytecode}"}},
                        "metadata": {{"settings": {{"compilationTarget": {{
                            "{source}": "Target"
                        }}}}}}
                    }}""".format(bytecode=bytecode, source=source)
                )

            self.assertEqual(
                _extract_bytecode_from_forge_out(
                    out_dir,
                    "Target",
                    "contracts/Target.sol",
                ),
                ("6001", "Target"),
            )

    def test_forge_artifact_selection_accepts_one_renamed_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            for directory, source, contract_name, bytecode in (
                ("Patch.sol", "src/contracts/Target.sol", "PoC_CCBPATCH", "0x6001"),
                ("Other.sol", "src/vendor/Other.sol", "Unrelated", "0x6002"),
            ):
                artifact_dir = out_dir / directory
                artifact_dir.mkdir()
                (artifact_dir / f"{contract_name}.json").write_text(
                    """{{
                        "deployedBytecode": {{"object": "{bytecode}"}},
                        "metadata": {{"settings": {{"compilationTarget": {{
                            "{source}": "{contract_name}"
                        }}}}}}
                    }}""".format(
                        bytecode=bytecode,
                        source=source,
                        contract_name=contract_name,
                    )
                )

            self.assertEqual(
                _extract_bytecode_from_forge_out(
                    out_dir,
                    "Target",
                    "contracts/Target.sol",
                    allow_unique_source_unit_fallback=True,
                ),
                ("6001", "PoC_CCBPATCH"),
            )

    def test_forge_artifact_selection_rejects_multiple_renamed_runtimes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            for contract_name, bytecode in (("First", "0x6001"), ("Second", "0x6002")):
                artifact_dir = out_dir / f"{contract_name}.sol"
                artifact_dir.mkdir()
                (artifact_dir / f"{contract_name}.json").write_text(
                    """{{
                        "deployedBytecode": {{"object": "{bytecode}"}},
                        "metadata": {{"settings": {{"compilationTarget": {{
                            "src/contracts/Target.sol": "{contract_name}"
                        }}}}}}
                    }}""".format(
                        bytecode=bytecode,
                        contract_name=contract_name,
                    )
                )

            with self.assertRaisesRegex(
                RuntimeError,
                "expected one deployed Forge runtime artifact.*found 2",
            ):
                _extract_bytecode_from_forge_out(
                    out_dir,
                    "Target",
                    "contracts/Target.sol",
                    allow_unique_source_unit_fallback=True,
                )

    def test_forge_artifact_selection_rejects_creation_bytecode_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            artifact_dir = out_dir / "Target.sol"
            artifact_dir.mkdir()
            (artifact_dir / "Target.json").write_text(
                """{
                    "bytecode": {"object": "0x6001"},
                    "deployedBytecode": {"object": "0x"},
                    "metadata": {"settings": {"compilationTarget": {
                        "src/contracts/Target.sol": "Target"
                    }}}
                }"""
            )

            with self.assertRaisesRegex(RuntimeError, "no deployed bytecode"):
                _extract_bytecode_from_forge_out(
                    out_dir,
                    "Target",
                    "contracts/Target.sol",
                )

    def test_real_forge_compile_preserves_relative_import_source_identity(self) -> None:
        sources = {
            "contracts/Target.sol": (
                'pragma solidity ^0.8.20; import "./Dependency.sol"; '
                "contract Target { function value() external pure returns (uint256) { "
                "return Dependency.value(); } }"
            ),
            "contracts/Dependency.sol": (
                "pragma solidity ^0.8.20; library Dependency { "
                "function value() internal pure returns (uint256) { return 1; } }"
            ),
            "vendor/Other.sol": (
                "pragma solidity ^0.8.20; contract Target { "
                "function value() external pure returns (uint256) { return 2; } }"
            ),
        }

        target_bytecode, target_name = _forge_compile_fallback(
            sources,
            compiler_version="0.8.20",
            contract_name_hint="Target",
            target_file="contracts/Target.sol",
        )
        other_bytecode, other_name = _forge_compile_fallback(
            sources,
            compiler_version="0.8.20",
            contract_name_hint="Target",
            target_file="vendor/Other.sol",
        )

        self.assertEqual((target_name, other_name), ("Target", "Target"))
        self.assertTrue(target_bytecode)
        self.assertTrue(other_bytecode)
        self.assertNotEqual(target_bytecode, other_bytecode)

    def test_dfhl_flat_cache_resolves_unique_public_source_basename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir)
            metadata = {
                "files": [
                    "contracts_Target.sol",
                    "contracts_Dependency.sol",
                ]
            }

            self.assertEqual(
                _pick_target_file(
                    source_dir,
                    metadata,
                    "Target",
                    "contracts/Target.sol",
                ),
                "contracts_Target.sol",
            )

    def test_dfhl_flat_cache_rejects_ambiguous_recovered_basename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir)
            metadata = {
                "files": [
                    "contracts_Target.sol",
                    "vendor_Target.sol",
                ]
            }

            with self.assertRaisesRegex(RuntimeError, "ambiguous target source unit"):
                _pick_target_file(
                    source_dir,
                    metadata,
                    "Target",
                    "Target.sol",
                )

    def test_dfhl_compile_requires_both_trusted_source_identities(self) -> None:
        fake_solcx = types.SimpleNamespace(
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            source_dir = base_dir / "sources"
            source_dir.mkdir()
            (source_dir / "Target.sol").write_text("contract Target {}")
            metadata = {
                "source_dir": "sources",
                "compiler_version": "0.8.20",
                "files": ["Target.sol"],
            }
            for target_source_unit, artifact_source_unit, message in (
                ("", "Target.sol", "missing trusted patch source unit"),
                ("Target.sol", "", "missing trusted artifact source unit"),
            ):
                with self.subTest(
                    target_source_unit=target_source_unit,
                    artifact_source_unit=artifact_source_unit,
                ):
                    with (
                        mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
                        mock.patch(
                            "infra.solidity.legacy.resolve_case_source_metadata",
                            return_value=metadata,
                        ),
                        self.assertRaisesRegex(RuntimeError, message),
                    ):
                        compile_dfhl_fixed_bytecode(
                            base_dir=base_dir,
                            case_id="bench-test",
                            fixed_code="contract Target {}",
                            contract_name_hint="Target",
                            target_source_unit=target_source_unit,
                            artifact_source_unit=artifact_source_unit,
                        )

    def test_dfhl_rejects_distinct_logical_units_collapsed_by_flat_cache(self) -> None:
        fake_solcx = types.SimpleNamespace(
            exceptions=types.SimpleNamespace(SolcError=RuntimeError),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            source_dir = base_dir / "sources"
            source_dir.mkdir()
            (source_dir / "Target.sol").write_text("contract Target {}")
            metadata = {
                "source_dir": "sources",
                "compiler_version": "0.8.20",
                "files": ["Target.sol"],
            }
            for target_source_unit, artifact_source_unit in (
                ("base/Target.sol", "runtime/Target.sol"),
                ("/contracts/Target.sol", "contracts/Target.sol"),
            ):
                with self.subTest(
                    target_source_unit=target_source_unit,
                    artifact_source_unit=artifact_source_unit,
                ):
                    with (
                        mock.patch.dict(sys.modules, {"solcx": fake_solcx}),
                        mock.patch(
                            "infra.solidity.legacy.resolve_case_source_metadata",
                            return_value=metadata,
                        ),
                        self.assertRaisesRegex(
                            RuntimeError,
                            "distinct trusted source units collapse",
                        ),
                    ):
                        compile_dfhl_fixed_bytecode(
                            base_dir=base_dir,
                            case_id="bench-test",
                            fixed_code="contract Renamed {}",
                            contract_name_hint="Target",
                            target_source_unit=target_source_unit,
                            artifact_source_unit=artifact_source_unit,
                        )

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
