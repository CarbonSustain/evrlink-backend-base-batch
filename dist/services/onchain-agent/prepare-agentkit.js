"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.prepareAgentkitAndWalletProvider = prepareAgentkitAndWalletProvider;
const agentkit_1 = require("@coinbase/agentkit");
const fs = __importStar(require("fs"));
const accounts_1 = require("viem/accounts");
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
const getWalletDataFilePath = (userId = "default") => {
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
async function prepareAgentkitAndWalletProvider(userId = "default") {
    try {
        let walletData = null;
        // Use specifically WALLET_ADDRESS and PRIVATE_KEY_AGENT as requested
        console.log("Using specifically provided wallet address and private key agent");
        // Get private key from PRIVATE_KEY_AGENT environment variable
        const privateKeyFromEnv = process.env.PRIVATE_KEY_AGENT;
        if (!privateKeyFromEnv) {
            throw new Error("PRIVATE_KEY_AGENT environment variable is required but not set");
        }
        // Get wallet address from WALLET_ADDRESS environment variable
        const walletAddressFromEnv = process.env.WALLET_ADDRESS;
        if (!walletAddressFromEnv) {
            throw new Error("WALLET_ADDRESS environment variable is required but not set");
        }
        // Format the private key (ensure it has 0x prefix)
        const formattedPrivateKey = privateKeyFromEnv.startsWith("0x")
            ? privateKeyFromEnv
            : `0x${privateKeyFromEnv}`;
        // Format the wallet address (ensure it has 0x prefix)
        const formattedWalletAddress = walletAddressFromEnv.startsWith("0x")
            ? walletAddressFromEnv
            : `0x${walletAddressFromEnv}`;
        const account = (0, accounts_1.privateKeyToAccount)(formattedPrivateKey);
        // Create a signer object that implements the required sign method
        const signer = {
            address: account.address,
            // Add a sign method that matches the expected Signer interface
            sign: async (parameters) => {
                // Convert the hash to a message for signing
                return account.signMessage({ message: parameters.hash });
            },
            // Add getName method that's required by the wallet provider
            getName: () => {
                return "Evrlink SmartWallet";
            }
        };
        // Initialize WalletProvider: https://docs.cdp.coinbase.com/agentkit/docs/wallet-management
        // Using the static configureWithWallet method since constructor is private
        const walletProvider = await agentkit_1.SmartWalletProvider.configureWithWallet({
            networkId: process.env.NETWORK_ID || "base-sepolia",
            signer,
            smartWalletAddress: formattedWalletAddress
        });
        if (process.env.WALLET_ADDRESS) {
            console.log(`Using wallet address from environment variables: ${process.env.WALLET_ADDRESS}`);
        }
        // Initialize AgentKit: https://docs.cdp.coinbase.com/agentkit/docs/agent-actions
        const erc721 = (0, agentkit_1.erc721ActionProvider)();
        const pyth = (0, agentkit_1.pythActionProvider)();
        const wallet = (0, agentkit_1.walletActionProvider)(); // default action package: get balance, native transfer, and get wallet details
        // Check if CDP API keys are available
        const cdpApiKeyName = process.env.CDP_API_KEY_NAME || "";
        const cdpApiKeyPrivateKey = process.env.CDP_API_KEY_PRIVATE_KEY?.replace(/\\n/g, "\n") || "";
        // Initialize CDP providers with fallbacks for missing environment variables
        const cdp = (0, agentkit_1.cdpApiActionProvider)({
            apiKeyName: cdpApiKeyName,
            apiKeyPrivateKey: cdpApiKeyPrivateKey,
        });
        const cdpWallet = (0, agentkit_1.cdpWalletActionProvider)({
            apiKeyName: cdpApiKeyName,
            apiKeyPrivateKey: cdpApiKeyPrivateKey,
        });
        const weth = (0, agentkit_1.wethActionProvider)();
        const erc20 = (0, agentkit_1.erc20ActionProvider)();
        const agentkit = await agentkit_1.AgentKit.from({
            walletProvider,
            actionProviders: [erc721, pyth, wallet, cdp, cdpWallet, weth, erc20],
        });
        // Get the smart wallet address for logging
        const smartWalletAddress = await walletProvider.getAddress();
        // Log wallet information instead of saving to file
        console.log(`Using wallet address: ${smartWalletAddress} for user ${userId}`);
        console.log(`Private key is securely stored in environment variables`);
        return { agentkit, walletProvider };
    }
    catch (error) {
        console.error("Error initializing agent:", error);
        throw new Error("Failed to initialize agent");
    }
}
