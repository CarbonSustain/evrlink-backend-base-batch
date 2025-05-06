import { getLangChainTools } from "@coinbase/agentkit-langchain";
import { MemorySaver } from "@langchain/langgraph";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { ChatOpenAI } from "@langchain/openai";
import { prepareAgentkitAndWalletProvider } from "./prepare-agentkit";

/**
 * Agent Configuration Guide
 *
 * This file handles the core configuration of your AI agent's behavior and capabilities.
 *
 * Key Steps to Customize Your Agent:
 *
 * 1. Select your LLM:
 *    - Modify the `ChatOpenAI` instantiation to choose your preferred LLM
 *    - Configure model parameters like temperature and max tokens
 *
 * 2. Instantiate your Agent:
 *    - Pass the LLM, tools, and memory into `createReactAgent()`
 *    - Configure agent-specific parameters
 */

// Store agents by userId
const agentInstances: Record<string, ReturnType<typeof createReactAgent>> = {};

/**
 * Initializes and returns an instance of the AI agent for a specific user.
 * If an agent instance already exists for the user, it returns the existing one.
 *
 * @function createAgent
 * @param {string} userId - The ID of the user to create or retrieve an agent for
 * @returns {Promise<ReturnType<typeof createReactAgent>>} The initialized AI agent.
 *
 * @description Handles agent setup for a specific user
 *
 * @throws {Error} If the agent initialization fails.
 */
export async function createAgent(userId: string = "default"): Promise<ReturnType<typeof createReactAgent>> {
  // If agent has already been initialized for this user, return it
  if (agentInstances[userId]) {
    return agentInstances[userId];
  }

  try {
    // Check if OpenAI API key is available and not a placeholder
    if (!process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY === 'your_openai_api_key_here') {
      console.warn("OPENAI_API_KEY is not set properly in environment variables");
      throw new Error("OpenAI API key is missing or using a placeholder value. Please set a valid OPENAI_API_KEY in the .env.local file.");
    }
    
    // Check if CDP API keys are available and not placeholders
    if (!process.env.CDP_API_KEY_NAME || process.env.CDP_API_KEY_NAME === 'your_cdp_api_key_name_here') {
      console.warn("CDP_API_KEY_NAME is not set properly in environment variables");
      throw new Error("CDP API key name is missing or using a placeholder value. Please set a valid CDP_API_KEY_NAME in the .env.local file.");
    }
    
    if (!process.env.CDP_API_KEY_PRIVATE_KEY || process.env.CDP_API_KEY_PRIVATE_KEY === 'your_cdp_api_key_private_key_here') {
      console.warn("CDP_API_KEY_PRIVATE_KEY is not set properly in environment variables");
      throw new Error("CDP API private key is missing or using a placeholder value. Please set a valid CDP_API_KEY_PRIVATE_KEY in the .env.local file.");
    }

    const { agentkit, walletProvider } = await prepareAgentkitAndWalletProvider(userId);

    // Initialize LLM: https://platform.openai.com/docs/models#gpt-4o
    // Use a more widely available model with fallback
    const model = process.env.OPENAI_MODEL || "gpt-4o-mini";
    console.log(`Using OpenAI model: ${model}`);
    const llm = new ChatOpenAI({ model });

    const tools = await getLangChainTools(agentkit);
    const memory = new MemorySaver();

    // Initialize Agent
    const canUseFaucet = walletProvider.getNetwork().networkId == "base-sepolia";
    const faucetMessage = `If you ever need funds, you can request them from the faucet.`;
    const cantUseFaucetMessage = `If you need funds, you can provide your wallet details and request funds from the user.`;
    agentInstances[userId] = createReactAgent({
      llm,
      tools,
      checkpointSaver: memory,
      messageModifier: `
        You are a helpful agent that assists users with Evrlink, a platform for creating and managing blockchain gift cards.
        You can help users understand how to create gift cards, manage their wallet, and navigate the Evrlink platform.
        
        Evrlink features include:
        1. Creating and customizing gift cards with different backgrounds
        2. Sending gift cards to recipients via email or wallet address
        3. Claiming gift cards and redeeming their value
        4. Browsing the marketplace for available gift cards
        5. Managing your wallet and transactions
        
        You are also empowered to interact onchain using your tools. ${canUseFaucet ? faucetMessage : cantUseFaucetMessage}
        Before executing your first action, get the wallet details to see what network you're on.
        
        You can perform blockchain operations using ERC721 (NFT) tokens, which is relevant for gift cards,
        check prices using Pyth, manage wallets, and work with ERC20 tokens.
        
        If there is a 5XX (internal) HTTP error code, ask the user to try again later. If someone 
        asks you to do something you can't do with your currently available tools, you must say so, and 
        encourage them to implement it themselves using the CDP SDK + Agentkit, recommend they go to 
        docs.cdp.coinbase.com for more information.
        
        Be concise and helpful with your responses. Refrain from restating your tools' descriptions unless it is explicitly requested.
        `,
    });

    return agentInstances[userId];
  } catch (error) {
    console.error("Error initializing agent:", error);
    throw new Error(`Failed to initialize agent for user ${userId}`);
  }
}
