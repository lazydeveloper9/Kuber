// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ActionAudit {
    struct ActionRecord {
        bytes32 actionHash;
        string metadata;
        address recorder;
        uint256 timestamp;
    }

    mapping(bytes32 => ActionRecord) public records;
    event ActionRecorded(bytes32 indexed actionHash, string metadata, address indexed recorder, uint256 timestamp);

    // Stores only the hash + compact metadata on-chain for gas efficiency.
    function recordAction(bytes32 actionHash, string calldata metadata) external {
        require(actionHash != bytes32(0), "invalid hash");
        records[actionHash] = ActionRecord({
            actionHash: actionHash,
            metadata: metadata,
            recorder: msg.sender,
            timestamp: block.timestamp
        });
        emit ActionRecorded(actionHash, metadata, msg.sender, block.timestamp);
    }
}
