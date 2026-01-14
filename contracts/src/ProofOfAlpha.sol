// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockVerifier.sol";

contract ProofOfAlpha {
    MockVerifier public verifier;
    
    // Maps User -> Reputation Score (e.g., ROI * 100)
    mapping(address => uint256) public reputationScores;
    
    event ScoreVerified(address indexed user, uint256 score);

    constructor(address _verifier) {
        verifier = MockVerifier(_verifier);
    }

    /**
     * @notice Submits a ZK proof of trading performance.
     * @param score The public input (e.g., claimed ROI).
     * @param proof The cryptographic proof generated off-chain (EZKL).
     */
    function submitProof(uint256 score, bytes calldata proof) external {
        uint256[] memory pubInputs = new uint256[](1);
        pubInputs[0] = score;

        // 1. Verify the proof on-chain
        bool verified = verifier.verify(pubInputs, proof);
        require(verified, "Invalid ZK Proof");

        // 2. Update on-chain reputation
        reputationScores[msg.sender] = score;
        
        emit ScoreVerified(msg.sender, score);
    }
}