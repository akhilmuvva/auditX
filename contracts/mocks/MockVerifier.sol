// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../interfaces/IResumeVerifier.sol";

contract MockVerifier is IResumeVerifier {
    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[3] calldata
    ) external pure override returns (bool) {
        return true;
    }
}
