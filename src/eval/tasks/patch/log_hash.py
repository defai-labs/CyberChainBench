"""Shared Solidity log hashing helper for Patch replay tests."""

SOLIDITY_LOG_HASH_FUNCTION = """\
    function _hashLogs(Vm.Log[] memory entries) internal pure returns (bytes32) {
        uint256 totalLength;
        for (uint256 i = 0; i < entries.length; i++) {
            totalLength += 20 + entries[i].data.length + (32 * entries[i].topics.length);
        }

        // Keep one scratch word so fixed-width stores never cross the allocation.
        bytes memory encoded = new bytes(totalLength + 32);
        assembly ("memory-safe") {
            mstore(encoded, totalLength)
        }
        uint256 offset;
        for (uint256 i = 0; i < entries.length; i++) {
            address emitter = entries[i].emitter;
            assembly ("memory-safe") {
                mstore(add(add(encoded, 0x20), offset), shl(96, emitter))
            }
            offset += 20;

            bytes memory logData = entries[i].data;
            uint256 j;
            for (; j + 32 <= logData.length; j += 32) {
                bytes32 word;
                assembly ("memory-safe") {
                    word := mload(add(add(logData, 0x20), j))
                    mstore(add(add(add(encoded, 0x20), offset), j), word)
                }
            }
            for (; j < logData.length; j++) {
                encoded[offset + j] = logData[j];
            }
            offset += logData.length;

            for (j = 0; j < entries[i].topics.length; j++) {
                bytes32 topic = entries[i].topics[j];
                assembly ("memory-safe") {
                    mstore(add(add(encoded, 0x20), offset), topic)
                }
                offset += 32;
            }
        }
        return keccak256(encoded);
    }
"""
