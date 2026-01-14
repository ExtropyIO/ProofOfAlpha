// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ProofOfAlpha.sol";
import "../src/MockVerifier.sol";

contract ProofOfAlphaTest is Test {
    ProofOfAlpha public proofOfAlpha;
    MockVerifier public verifier;

    function setUp() public {
        verifier = new MockVerifier();
        proofOfAlpha = new ProofOfAlpha(address(verifier));
    }

    function test_VerifyReputation() public {
        // 1. Simulate a user (Trader)
        address trader = address(0x123);
        vm.startPrank(trader);

        // 2. Simulate data (Claiming 25% ROI)
        uint256 claimedScore = 25;
        bytes memory mockProof = hex"deadbeef"; // Mock proof

        // 3. Execute the transaction
        proofOfAlpha.submitProof(claimedScore, mockProof);

        // 4. Assert the reputation was updated
        assertEq(proofOfAlpha.reputationScores(trader), 25);
        
        console.log("ZK Proof Verified. User Reputation Updated.");
        vm.stopPrank();
    }
}