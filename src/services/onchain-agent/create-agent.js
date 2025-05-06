/**
 * Onchain Agent Implementation for Evrlink
 * 
 * This file handles the creation and configuration of the onchain agent.
 */

const { getLangChainTools } = require("@coinbase/agentkit-langchain");
const { MemorySaver } = require("@langchain/langgraph");
const { createReactAgent } = require("@langchain/langgraph/prebuilt");
const { ChatOpenAI } = require("@langchain/openai");
const { prepareAgentkitAndWalletProvider } = require("./prepare-agentkit");

// The agent instance
let agent;

/**
 * Initializes and returns an instance of the AI agent.
 * If an agent instance already exists, it returns the existing one.
 *
 * @function createOnchainAgent
 * @returns {Promise<ReturnType<typeof createReactAgent>>} The initialized AI agent.
 *
 * @description Handles agent setup
 *
 * @throws {Error} If the agent initialization fails.
 */
async function createOnchainAgent() {
  // If agent has already been initialized, return it
  if (agent) {
    return agent;
  }

  try {
    const { agentkit, walletProvider } = await prepareAgentkitAndWalletProvider();

    // Initialize LLM
    const llm = new ChatOpenAI({ 
      model: "gpt-4o-mini",
      apiKey: process.env.OPENAI_API_KEY
    });

    const tools = await getLangChainTools(agentkit);
    const memory = new MemorySaver();

    // Initialize Agent
    const canUseFaucet = walletProvider.getNetwork().networkId == "base-sepolia";
    const faucetMessage = `If you ever need funds, you can request them from the faucet.`;
    const cantUseFaucetMessage = `If you need funds, you can provide your wallet details and request funds from the user.`;
    
    agent = createReactAgent({
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
        
        You are also empowered to interact onchain using your tools. ${canUseFaucet ? faucetMessage : cantUseFaucetMessage}.
        Before executing your first action, get the wallet details to see what network you're on.
        
        Be concise and helpful with your responses. If you don't know the answer to a specific question,
        suggest that the user check the documentation or contact support.
      `,
    });

    return agent;
  } catch (error) {
    console.error("Error initializing onchain agent:", error);
    throw new Error("Failed to initialize onchain agent");
  }
}

module.exports = {
  createOnchainAgent
};
