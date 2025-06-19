require("dotenv").config();
const { ethers } = require("hardhat");

async function main() {
  console.log("🚀 Deploying NFTGiftMarketplace contract...");

  const [deployer] = await hre.ethers.getSigners();
  console.log("👤 Deploying with account:", deployer.address);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("💰 Account balance:", hre.ethers.formatEther(balance), "ETH");

  if (parseFloat(hre.ethers.formatEther(balance)) < 0.001) {
    console.error("❌ Insufficient balance to deploy the contract.");
    process.exit(1);
  }

  console.log("PLATFORM_ADDRESS:", process.env.PLATFORM_ADDRESS);
  console.log("CLIMATE_ADDRESS:", process.env.CLIMATE_ADDRESS);
  console.log("TAX_ADDRESS:", process.env.TAX_ADDRESS);
  console.log("USDC_TOKEN_ADDRESS:", process.env.USDC_TOKEN_ADDRESS);
  const checksummed = "0xd9Aa594f1bCEB10f0AE9E090b43B6c388e6F2D65";
  console.log(checksummed);

  const platformAddress = ethers.getAddress(process.env.PLATFORM_ADDRESS);
  const climateAddress = ethers.getAddress(process.env.CLIMATE_ADDRESS);
  const taxAddress = ethers.getAddress(process.env.TAX_ADDRESS);
  const usdcTokenAddress = ethers.getAddress(process.env.USDC_TOKEN_ADDRESS);

  const NFTGiftMarketplace = await hre.ethers.getContractFactory(
    "NFTGiftMarketplace"
  );

  const deploymentTx = NFTGiftMarketplace.getDeployTransaction(
    platformAddress,
    climateAddress,
    taxAddress,
    usdcTokenAddress
  );

  const estimatedGas = await hre.ethers.provider.estimateGas({
    ...deploymentTx,
    from: deployer.address,
  });

  const feeData = await hre.ethers.provider.getFeeData();
  const currentGasPrice = feeData.gasPrice;
  const estimatedCost = estimatedGas * currentGasPrice;

  console.log(
    `🧮 Estimated deployment cost: ${ethers.formatEther(
      estimatedCost.toString()
    )} ETH (Estimated gas: ${estimatedGas}, Gas price: ${ethers.formatUnits(
      currentGasPrice,
      "gwei"
    )} gwei)`
  );

  console.log("📦 Deploying the NFTGiftMarketplace contract...");
  const nftGiftMarketplace = await NFTGiftMarketplace.deploy(
    platformAddress,
    climateAddress,
    taxAddress,
    usdcTokenAddress
  );

  await nftGiftMarketplace.waitForDeployment();

  // ✅ FIX: Use .target instead of getAddress()
  const address = nftGiftMarketplace.target;

  console.log("✅ NFTGiftMarketplace deployed to:", address);
  console.log(
    "🔗 Transaction hash:",
    nftGiftMarketplace.deploymentTransaction().hash
  );

  console.log("⏳ Waiting for 5 block confirmations...");
  await nftGiftMarketplace.deploymentTransaction().wait(5);

  if (process.env.ETHERSCAN_API_KEY) {
    console.log("🔍 Verifying contract on Etherscan...");
    try {
      await hre.run("verify:verify", {
        address: address,
        constructorArguments: [
          platformAddress,
          climateAddress,
          taxAddress,
          usdcTokenAddress,
        ],
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

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error.message);
    process.exit(1);
  });
