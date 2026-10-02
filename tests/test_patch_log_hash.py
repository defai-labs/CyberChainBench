from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from eval.tasks.patch.attack_replay import _generate_attack_tx_replay_test
from eval.tasks.patch.log_hash import SOLIDITY_LOG_HASH_FUNCTION
from infra.cli.validate_patch import _generate_normal_tx_replay_test

SOLIDITY_TEST = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }
}

contract LogHashTest {
__LOG_HASH_FUNCTION__

    function _referenceHash(Vm.Log[] memory entries) internal pure returns (bytes32) {
        bytes memory encoded;
        for (uint256 i = 0; i < entries.length; i++) {
            encoded = abi.encodePacked(encoded, entries[i].emitter, entries[i].data);
            for (uint256 j = 0; j < entries[i].topics.length; j++) {
                encoded = abi.encodePacked(encoded, entries[i].topics[j]);
            }
        }
        return keccak256(encoded);
    }

    function _entry(uint256 seed, uint256 length, uint256 topicCount)
        internal pure returns (Vm.Log memory item)
    {
        item.emitter = address(uint160(uint256(keccak256(abi.encode(seed, "emitter")))));
        item.data = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            item.data[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i)))));
        }
        item.topics = new bytes32[](topicCount);
        for (uint256 i = 0; i < topicCount; i++) {
            item.topics[i] = keccak256(abi.encode(seed, i, "topic"));
        }
    }

    function testEmptyAndPackedOrder() public pure {
        Vm.Log[] memory empty = new Vm.Log[](0);
        require(_hashLogs(empty) == keccak256(""), "empty digest differs");

        Vm.Log[] memory entries = new Vm.Log[](2);
        entries[0] = _entry(1, 1, 2);
        entries[1] = _entry(2, 33, 1);
        bytes32 expected = keccak256(
            abi.encodePacked(
                entries[0].emitter,
                entries[0].data,
                entries[0].topics[0],
                entries[0].topics[1],
                entries[1].emitter,
                entries[1].data,
                entries[1].topics[0]
            )
        );
        require(_hashLogs(entries) == expected, "packed order differs");
    }

    function testBoundaryLengthsAndTopics() public pure {
        uint256[9] memory lengths = [uint256(0), 1, 2, 31, 32, 33, 63, 64, 65];
        Vm.Log[] memory entries = new Vm.Log[](lengths.length);
        for (uint256 i = 0; i < lengths.length; i++) {
            entries[i] = _entry(i + 10, lengths[i], i % 5);
        }
        require(_hashLogs(entries) == _referenceHash(entries), "boundary digest differs");
    }

    function _largeEntries() internal pure returns (Vm.Log[] memory entries) {
        entries = new Vm.Log[](64);
        for (uint256 i = 0; i < entries.length; i++) {
            entries[i].emitter = address(uint160(i + 1));
            entries[i].data = new bytes(1024);
            entries[i].data[0] = bytes1(uint8(i));
            entries[i].data[1023] = bytes1(uint8(i + 1));
            entries[i].topics = new bytes32[](4);
            for (uint256 j = 0; j < 4; j++) {
                entries[i].topics[j] = keccak256(abi.encode(i, j));
            }
        }
    }

    function testLinearLargeInput() public pure {
        require(_hashLogs(_largeEntries()) != bytes32(0), "unexpected digest");
    }

    function quadraticLargeProbe() public pure {
        require(_referenceHash(_largeEntries()) != bytes32(0), "unexpected digest");
    }
}
""".replace("__LOG_HASH_FUNCTION__", SOLIDITY_LOG_HASH_FUNCTION)


def _run_forge(source: str, *extra_args: str) -> subprocess.CompletedProcess[str]:
    forge = shutil.which("forge")
    if forge is None:
        raise unittest.SkipTest("forge is unavailable")
    with tempfile.TemporaryDirectory(prefix="ccb-log-hash-test-") as temp_dir:
        root = Path(temp_dir)
        (root / "src").mkdir()
        (root / "foundry.toml").write_text(
            "[profile.default]\nsrc = 'src'\ntest = 'src'\nsolc = '0.8.20'\n"
            "optimizer = true\noptimizer_runs = 200\n",
            encoding="utf-8",
        )
        (root / "src" / "LogHash.t.sol").write_text(source, encoding="utf-8")
        return subprocess.run(
            [forge, "test", "--root", str(root), *extra_args],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )


class PatchLogHashTests(unittest.TestCase):
    def test_both_replay_producers_use_the_shared_helper(self) -> None:
        common = {
            "case_slug": "bench_log_hash",
            "patch_target": "0x" + "11" * 20,
            "call_target": "0x" + "22" * 20,
            "caller": "0x" + "33" * 20,
            "replay_block": 1,
            "fork_chain": "ethereum",
            "value_wei": 0,
            "calldata_hex": "0x",
            "fixed_code_line": 'bytes memory _fixedCode = hex"00";',
            "tx_hash": "0x" + "44" * 32,
        }
        attack = _generate_attack_tx_replay_test(**common)
        normal = _generate_normal_tx_replay_test(**common)

        for generated in (attack, normal):
            self.assertEqual(generated.count(SOLIDITY_LOG_HASH_FUNCTION), 1)
            self.assertNotIn("abi.encodePacked(encoded", generated)
            self.assertEqual(generated.count("new bytes(totalLength + 32)"), 1)

    def test_solidity_digest_matches_native_packed_encoding(self) -> None:
        completed = _run_forge(
            SOLIDITY_TEST,
            "--match-test",
            "test(EmptyAndPackedOrder|BoundaryLengthsAndTopics)",
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_large_input_stays_within_a_bounded_gas_budget(self) -> None:
        linear = _run_forge(
            SOLIDITY_TEST,
            "--match-test",
            "testLinearLargeInput",
            "--gas-limit",
            "10000000",
        )
        self.assertEqual(linear.returncode, 0, linear.stdout + linear.stderr)

        quadratic_source = SOLIDITY_TEST.replace(
            "function quadraticLargeProbe() public pure",
            "function testQuadraticLargeProbe() public pure",
        )
        quadratic = _run_forge(
            quadratic_source,
            "--match-test",
            "testQuadraticLargeProbe",
            "--gas-limit",
            "10000000",
        )
        self.assertNotEqual(quadratic.returncode, 0)
        self.assertRegex(quadratic.stdout + quadratic.stderr, r"(?:MemoryOOG|OutOfGas)")


if __name__ == "__main__":
    unittest.main()
