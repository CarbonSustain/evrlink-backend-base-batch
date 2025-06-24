const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Minting MockUSDC with the account:", deployer.address);

  const MockUSDC = await ethers.getContractFactory("MockUSDC");
  const usdc = MockUSDC.attach("0x4cdf78D4947aF64A9f2b2DDce73e08f336DFea7A");

  const recipient = "0x293764e72f3411a1bea362869a6cc0812562ee92";
  const mintAmount = ethers.parseUnits("10000000"); // 10 USDC with 6 decimals

  console.log("Minting 10 USDC to address:", recipient);

  const tx = await usdc.mint(recipient, mintAmount);
  await tx.wait();

  console.log(
    `Minted ${ethers.formatUnits(mintAmount, 6)} USDC to ${recipient}`
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
