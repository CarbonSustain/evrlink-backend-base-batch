require("dotenv").config();
const hre = require("hardhat");

async function main() {
  console.log("🚀 Deploying NFTGiftMarketplace contract...");

  // Get the deployer account
  const [deployer] = await hre.ethers.getSigners();
  console.log("👤 Deploying with account:", deployer.address);

  // Get the balance of the deployer
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("💰 Account balance:", hre.ethers.formatEther(balance), "ETH");

  // Check if the deployer has enough balance
  if (parseFloat(hre.ethers.formatEther(balance)) < 0.01) {
    console.error("❌ Insufficient balance to deploy the contract.");
    process.exit(1);
  }

  // Read constructor arguments from environment variables
  const platformAddress = process.env.PLATFORM_ADDRESS;
  const climateAddress = process.env.CLIMATE_ADDRESS;
  const taxAddress = process.env.TAX_ADDRESS;

  if (!platformAddress || !climateAddress || !taxAddress) {
    console.error(
      "❌ PLATFORM_ADDRESS, CLIMATE_ADDRESS, or TAX_ADDRESS not set in .env"
    );
    process.exit(1);
  }

  // Deploy the contract with constructor arguments
  console.log("📦 Deploying the NFTGiftMarketplace contract...");
  const NFTGiftMarketplace = await hre.ethers.getContractFactory(
    "NFTGiftMarketplace"
  );
  const nftGiftMarketplace = await NFTGiftMarketplace.deploy(
    platformAddress,
    climateAddress,
    taxAddress
  );
  await nftGiftMarketplace.waitForDeployment();

  // Get the deployed contract address
  const address = await nftGiftMarketplace.getAddress();
  console.log("✅ NFTGiftMarketplace deployed to:", address);
  console.log(
    "🔗 Transaction hash:",
    nftGiftMarketplace.deploymentTransaction().hash
  );

  // Wait for a few block confirmations
  console.log("⏳ Waiting for 5 block confirmations...");
  await nftGiftMarketplace.deploymentTransaction().wait(5);

  // Verify the contract on Etherscan
  if (process.env.ETHERSCAN_API_KEY) {
    console.log("🔍 Verifying contract on Etherscan...");
    try {
      await hre.run("verify:verify", {
        address: address,
        constructorArguments: [platformAddress, climateAddress, taxAddress],
      });
      console.log("✅ Contract verified on Etherscan!");
    } catch (error) {
      console.error("❌ Error verifying contract:", error.message);
    }
  } else {
    console.log(
      "⚠️ Skipping Etherscan verification. ETHERSCAN_API_KEY is not set."
    );
  }
}

// Execute the deployment script
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error.message);
    process.exit(1);
  });
