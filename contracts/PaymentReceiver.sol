// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract PaymentReceiver is Ownable {
    IERC20 public usdcToken;
    uint256 public constant PRO_MONTHLY_RATE = 49 * 10**6; // $49 USDC (6 decimals)

    event ProUpgraded(address indexed user, uint256 months, uint256 amountPaid);

    constructor(address _usdcToken) Ownable(msg.sender) {
        usdcToken = IERC20(_usdcToken);
    }

    function acceptPayment(uint256 months) external {
        require(months > 0, "Must buy at least 1 month");
        uint256 totalCost = PRO_MONTHLY_RATE * months;

        require(usdcToken.transferFrom(msg.sender, address(this), totalCost), "USDC Transfer failed");

        emit ProUpgraded(msg.sender, months, totalCost);
    }

    function withdraw() external onlyOwner {
        // Owner withdraw contract USDC balance
    }
}
