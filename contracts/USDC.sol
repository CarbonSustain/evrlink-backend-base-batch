// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USD Coin", "mUSDC") {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }

    // For testing: anyone can mint tokens
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
