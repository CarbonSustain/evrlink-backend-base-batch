require("dotenv").config();
const hre = require("hardhat");

async function main() {
  console.log("🚀 Deploying MockUSDC contract...");

  const [deployer] = await hre.ethers.getSigners();
  console.log("👤 Deploying with account:", deployer.address);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("💰 Account balance:", hre.ethers.formatEther(balance), "ETH");

  if (parseFloat(hre.ethers.formatEther(balance)) < 0.001) {
    console.error("❌ Insufficient balance to deploy the contract.");
    process.exit(1);
  }

  const MockUSDC = await hre.ethers.getContractFactory("MockUSDC");
  const mockUsdc = await MockUSDC.deploy();
  await mockUsdc.waitForDeployment();

  const address = mockUsdc.target;
  console.log("✅ MockUSDC deployed to:", address);
  console.log("🔗 Transaction hash:", mockUsdc.deploymentTransaction().hash);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error.message);
    process.exit(1);
  });
