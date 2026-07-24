// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable: no access control for administrative transfer of funds
    // Missing onlyOwner modifier!
    function sovereignWithdraw(address payable target, uint256 amount) external {
        // Missing require(msg.sender == owner)
        (bool success, ) = target.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");

        // Reentrancy vulnerability
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }
}
