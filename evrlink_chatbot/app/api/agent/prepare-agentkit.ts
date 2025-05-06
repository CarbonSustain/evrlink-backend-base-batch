import {
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
} from "@coinbase/agentkit";
import * as fs from "fs";
import { Address, Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

/**
 * AgentKit Integration Route
 *
 * This file is your gateway to integrating AgentKit with your product.
 * It defines the core capabilities of your agent through WalletProvider
 * and ActionProvider configuration.
 *
 * Key Components:
 * 1. WalletProvider Setup:
 *    - Configures the blockchain wallet integration
 *    - Learn more: https://github.com/coinbase/agentkit/tree/main/typescript/agentkit#evm-wallet-providers
 *
 * 2. ActionProviders Setup:
 *    - Defines the specific actions your agent can perform
 *    - Choose from built-in providers or create custom ones:
 *      - Built-in: https://github.com/coinbase/agentkit/tree/main/typescript/agentkit#action-providers
 *      - Custom: https://github.com/coinbase/agentkit/tree/main/typescript/agentkit#creating-an-action-provider
 *
 * # Next Steps:
 * - Explore the AgentKit README: https://github.com/coinbase/agentkit
 * - Experiment with different LLM configurations
 * - Fine-tune agent parameters for your use case
 *
 * ## Want to contribute?
 * Join us in shaping AgentKit! Check out the contribution guide:
 * - https://github.com/coinbase/agentkit/blob/main/CONTRIBUTING.md
 * - https://discord.gg/CDP
 */

// Configure file paths for persisting wallet data
// First, try to use the existing wallet_data.txt file
const LEGACY_WALLET_DATA_FILE = "wallet_data.txt";
const WALLET_DATA_DIR = "wallet_data";

// Function to get wallet data file path
const getWalletDataFilePath = (userId: string = "default") => {
  // If the legacy wallet data file exists and this is the default user, use that
  if (userId === "default" && fs.existsSync(LEGACY_WALLET_DATA_FILE)) {
    return LEGACY_WALLET_DATA_FILE;
  }
  
  // Otherwise, use the new per-user directory structure
  // Create the directory if it doesn't exist
  if (!fs.existsSync(WALLET_DATA_DIR)) {
    fs.mkdirSync(WALLET_DATA_DIR, { recursive: true });
  }
  return `${WALLET_DATA_DIR}/${userId}.json`;
};

type WalletData = {
  privateKey: Hex;
  smartWalletAddress: Address;
};

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
export async function prepareAgentkitAndWalletProvider(userId: string = "default"): Promise<{
  agentkit: AgentKit;
  walletProvider: WalletProvider;
}> {
  try {
    let walletData: WalletData | null = null;
    let privateKey: Hex | null = null;
    
    const walletDataFile = getWalletDataFilePath(userId);

    // Read existing wallet data if available
    if (fs.existsSync(walletDataFile)) {
      try {
        walletData = JSON.parse(fs.readFileSync(walletDataFile, "utf8")) as WalletData;
        privateKey = walletData.privateKey;
      } catch (error) {
        console.error(`Error reading wallet data for user ${userId}:`, error);
        // Continue without wallet data
      }
    }

    if (!privateKey) {
      if (walletData?.smartWalletAddress) {
        throw new Error(
          `Smart wallet found for user ${userId} but no private key provided. Either provide the private key, or delete ${walletDataFile} and try again.`,
        );
      }
      // Try to read from the legacy wallet data file first
      if (fs.existsSync(LEGACY_WALLET_DATA_FILE)) {
        try {
          const legacyWalletData = JSON.parse(fs.readFileSync(LEGACY_WALLET_DATA_FILE, "utf8"));
          // Add 0x prefix if not present
          privateKey = legacyWalletData.privateKey.startsWith("0x") 
            ? legacyWalletData.privateKey as Hex
            : `0x${legacyWalletData.privateKey}` as Hex;
          console.log("Using existing wallet from wallet_data.txt");
        } catch (error) {
          console.error("Error reading legacy wallet data:", error);
          // Fall back to environment variable or generate a new key
          privateKey = (process.env.PRIVATE_KEY || generatePrivateKey()) as Hex;
        }
      } else {
        // Fall back to environment variable or generate a new key
        privateKey = (process.env.PRIVATE_KEY || generatePrivateKey()) as Hex;
      }
    }

    const signer = privateKeyToAccount(privateKey);

    // Initialize WalletProvider: https://docs.cdp.coinbase.com/agentkit/docs/wallet-management
    const walletProvider = await SmartWalletProvider.configureWithWallet({
      networkId: process.env.NETWORK_ID || "base-sepolia",
      signer,
      smartWalletAddress: walletData?.smartWalletAddress,
      paymasterUrl: undefined, // Sponsor transactions: https://docs.cdp.coinbase.com/paymaster/docs/welcome
    });

    // Initialize AgentKit: https://docs.cdp.coinbase.com/agentkit/docs/agent-actions
    const erc721 = erc721ActionProvider();
    const pyth = pythActionProvider();
    const wallet = walletActionProvider(); // default action package: get balance, native transfer, and get wallet details
    
    // Check if CDP API keys are available
    const cdpApiKeyName = process.env.CDP_API_KEY_NAME || "";
    const cdpApiKeyPrivateKey = process.env.CDP_API_KEY_PRIVATE_KEY?.replace(/\\n/g, "\n") || "";
    
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

    // Save wallet data
    const smartWalletAddress = await walletProvider.getAddress();
    fs.writeFileSync(
      walletDataFile,
      JSON.stringify({
        privateKey,
        smartWalletAddress,
        userId, // Store the userId with the wallet data
      } as WalletData & { userId: string }),
    );
    
    console.log(`Wallet data saved for user ${userId} at ${walletDataFile}`);
    console.log(`Smart wallet address: ${smartWalletAddress}`);

    return { agentkit, walletProvider };
  } catch (error) {
    console.error("Error initializing agent:", error);
    throw new Error("Failed to initialize agent");
  }
}
