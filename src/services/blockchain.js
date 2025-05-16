const { ethers } = require("ethers");
const NFTGiftMarketplace = require("../../artifacts/contracts/GiftCard.sol/NFTGiftMarketplace.json");

class BlockchainService {
  constructor() {
    this.provider = null;
    this.contract = null;
    this.initialized = false;
  }

  async initialize() {
    try {
      // Connect to Alchemy Sepolia provider
      this.provider = new ethers.providers.JsonRpcProvider(
        process.env.SEPOLIA_RPC_URL
      );

      // Initialize contract with your deployed address
      this.contract = new ethers.Contract(
        process.env.CONTRACT_ADDRESS,
        NFTGiftMarketplace.abi,
        this.provider
      );

      // Add your contract wallet
      const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, this.provider);
      this.contract = this.contract.connect(wallet);

      this.initialized = true;
      console.log("🔗 Blockchain service initialized successfully");
      console.log("Contract address:", process.env.CONTRACT_ADDRESS);
    } catch (error) {
      console.error("❌ Failed to initialize blockchain service:", error);
      throw error;
    }
  }

  async getContractBalance() {
    if (!this.initialized) {
      throw new Error("Blockchain service not initialized");
    }
    const balance = await this.provider.getBalance(
      process.env.CONTRACT_ADDRESS
    );
    return ethers.utils.formatEther(balance);
  }
}

module.exports = new BlockchainService();
