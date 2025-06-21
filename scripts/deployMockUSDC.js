// scripts/deployMockUSDC.js
// Usage: npx hardhat run scripts/deployMockUSDC.js --network <network>

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  const MockUSDC = await ethers.getContractFactory("MockUSDC");
  const usdc = await MockUSDC.deploy();
  await usdc.waitForDeployment();
  console.log("MockUSDC deployed to:", await usdc.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
