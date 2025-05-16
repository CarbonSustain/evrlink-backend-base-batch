/**
 * AgentKit Integration for Evrlink
 *
 * This file sets up the AgentKit and WalletProvider for the onchain agent.
 */

const {
  AgentKit,
  CdpWalletProvider,
  cdpApiActionProvider,
  cdpWalletActionProvider,
  erc20ActionProvider,
  erc721ActionProvider,
  pythActionProvider,
  SmartWalletProvider,
  walletActionProvider,
  WalletProvider,
  wethActionProvider,
} = require("@coinbase/agentkit");
const { privateKeyToAccount } = require("viem/accounts");

/**
 * Prepares the AgentKit and WalletProvider.
 *
 * @function prepareAgentkitAndWalletProvider
 * @param {string} [userId="default"] - The user ID for the wallet data
 * @returns {Promise<{ agentkit: AgentKit, walletProvider: WalletProvider }>} The initialized AI agent.
 *
 * @description Handles agent setup
 *
 * @throws {Error} If the agent initialization fails.
 */
async function prepareAgentkitAndWalletProvider(userId = "default") {
  try {
    // Use the specified wallet address and private key
    const walletAddress = process.env.WALLET_ADDRESS;
    const privateKey = process.env.PRIVATE_KEY_AGENT;

    if (!privateKey || !walletAddress) {
      throw new Error('WALLET_ADDRESS and PRIVATE_KEY_AGENT must be set in environment variables');
    }

    // Add 0x prefix if not present
    const formattedPrivateKey = privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`;
    console.log('Using wallet:', { address: walletAddress });

    // Create the signer from the private key
    const signer = privateKeyToAccount(formattedPrivateKey);

    // Initialize a basic WalletProvider with the signer
    const walletProvider = new WalletProvider({
      networkId: process.env.NETWORK_ID || "base-sepolia",
      signer
    });

    // Initialize AgentKit with action providers
    const erc721 = erc721ActionProvider();
    const pyth = pythActionProvider();
    const wallet = walletActionProvider();
    
    // Check if CDP API keys are available
    const cdpApiKeyName = process.env.CDP_API_KEY_NAME || "";
    const cdpApiKeyPrivateKey = process.env.CDP_API_KEY_PRIVATE_KEY?.replace(/\n/g, "\n") || "";
    
    // Initialize CDP providers with fallbacks for missing environment variables
    const cdp = cdpApiActionProvider({
      apiKeyName: cdpApiKeyName,
      apiKeyPrivateKey: cdpApiKeyPrivateKey,
    });
    const cdpWallet = cdpWalletActionProvider({
      apiKeyName: cdpApiKeyName,
      apiKeyPrivateKey: cdpApiKeyPrivateKey,
    });
    const weth = wethActionProvider();
    const erc20 = erc20ActionProvider();
    
    const agentkit = await AgentKit.from({
      walletProvider,
      actionProviders: [erc721, pyth, wallet, cdp, cdpWallet, weth, erc20],
    });

    const smartWalletAddress = await walletProvider.getAddress();
    console.log('Smart wallet configured:', { address: smartWalletAddress });

    return { agentkit, walletProvider };
  } catch (error) {
    console.error("Error initializing agent:", error);
    throw new Error("Failed to initialize agent");
  }
}

module.exports = {
  prepareAgentkitAndWalletProvider,
};