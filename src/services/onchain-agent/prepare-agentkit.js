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
  wethActionProvider,
} = require("@coinbase/agentkit");
const fs = require("fs");
const { generatePrivateKey, privateKeyToAccount } = require("viem/accounts");

// Configure a file to persist the agent's Smart Wallet + Private Key data
const WALLET_DATA_FILE = "wallet_data.txt";

/**
 * Prepares the AgentKit and WalletProvider.
 *
 * @function prepareAgentkitAndWalletProvider
 * @returns {Promise<{ agentkit: AgentKit, walletProvider: WalletProvider }>} The initialized AI agent.
 *
 * @description Handles agent setup
 *
 * @throws {Error} If the agent initialization fails.
 */
async function prepareAgentkitAndWalletProvider() {
  try {
    let walletData = null;
    let privateKey = null;

    // Read existing wallet data if available
    if (fs.existsSync(WALLET_DATA_FILE)) {
      try {
        walletData = JSON.parse(fs.readFileSync(WALLET_DATA_FILE, "utf8"));
        privateKey = walletData.privateKey;
      } catch (error) {
        console.error("Error reading wallet data:", error);
        // Continue without wallet data
      }
    }

    if (!privateKey) {
      if (walletData?.smartWalletAddress) {
        throw new Error(
          `Smart wallet found but no private key provided. Either provide the private key, or delete ${WALLET_DATA_FILE} and try again.`,
        );
      }
      privateKey = process.env.PRIVATE_KEY || generatePrivateKey();
    }

    const signer = privateKeyToAccount(privateKey);

    // Initialize WalletProvider
    const walletProvider = await SmartWalletProvider.configureWithWallet({
      networkId: process.env.NETWORK_ID || "base-sepolia",
      signer,
      smartWalletAddress: walletData?.smartWalletAddress,
      paymasterUrl: undefined, // Sponsor transactions
    });

    // Initialize AgentKit
    const erc721 = erc721ActionProvider();
    const pyth = pythActionProvider();
    const wallet = walletActionProvider(); // default action package: get balance, native transfer, and get wallet details
    const cdp = cdpApiActionProvider({
      apiKeyName: process.env.CDP_API_KEY_NAME,
      apiKeyPrivateKey: process.env.CDP_API_KEY_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    });
    const cdpWallet = cdpWalletActionProvider();
    const weth = wethActionProvider();
    const erc20 = erc20ActionProvider();
    
    const agentkit = await AgentKit.from({
      walletProvider,
      actionProviders: [erc721, pyth, wallet, cdp, cdpWallet, weth, erc20],
    });

    // Save wallet data
    const smartWalletAddress = await walletProvider.getAddress();
    fs.writeFileSync(
      WALLET_DATA_FILE,
      JSON.stringify({
        privateKey,
        smartWalletAddress,
      }),
    );

    return { agentkit, walletProvider };
  } catch (error) {
    console.error("Error initializing agent:", error);
    throw new Error("Failed to initialize agent");
  }
}

module.exports = {
  prepareAgentkitAndWalletProvider,
};
