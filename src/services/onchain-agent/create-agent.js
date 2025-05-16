/**
 * Onchain Agent Implementation for Evrlink
 * 
 * This file handles the creation and configuration of the onchain agent.
 */

const { getLangChainTools } = require("@coinbase/agentkit-langchain");
const { ChatOpenAI } = require("@langchain/openai");
const { AgentExecutor, initializeAgentExecutorWithOptions } = require("langchain/agents");
const { ConversationChain } = require("langchain/chains");
const { prepareAgentkitAndWalletProvider } = require('./prepare-agentkit.js');

// Store agents by userId
const agentInstances = {};

/**
 * Creates an onchain agent with AgentKit integration.
 *
 * @function createOnchainAgent
 * @param {string} [userId="default"] - The user ID for the agent.
 * @returns {Promise<AgentExecutor>} The initialized AI agent.
 *
 * @description Handles agent creation and caching
 *
 * @throws {Error} If the agent initialization fails.
 */
async function createOnchainAgent(userId = "default") {
  try {
    // Check if we have a cached instance
    if (agentInstances[userId]) {
      console.log(`Using cached agent for user ${userId}`);
      return agentInstances[userId];
    }

    // Initialize AgentKit and WalletProvider
    const { agentkit, walletProvider } = await prepareAgentkitAndWalletProvider(userId);

    // Get the LangChain tools from AgentKit
    const tools = await getLangChainTools(agentkit);

    // Initialize OpenAI model
    const model = process.env.OPENAI_MODEL || "gpt-4-turbo-preview";
    console.log(`Using OpenAI model: ${model}`);
    const llm = new ChatOpenAI({
      modelName: model,
      temperature: 0,
    });

    // Initialize the agent executor
    const agent = await initializeAgentExecutorWithOptions(tools, llm, {
      agentType: "openai-functions",
      verbose: true,
      returnIntermediateSteps: true,
      handleParsingErrors: true,
      agentArgs: {
        prefix: `You are an AI assistant specializing in blockchain operations and NFT gift cards. You have access to tools for creating, managing, and transferring NFTs on the blockchain.

Key capabilities:
- Create and mint NFT gift cards
- Transfer NFTs between wallets
- Check NFT balances and ownership
- Get token details and transaction history

When helping users, always:
1. Explain the process clearly
2. Mention any required information or prerequisites
3. Handle errors gracefully and suggest solutions
4. Confirm successful operations

Your goal is to make blockchain interactions simple and user-friendly.

If you encounter a 5XX (internal) HTTP error code, ask the user to try again later. If someone asks you to do something you can't do with your currently available tools, you must say so, and encourage them to implement it themselves using the CDP SDK + Agentkit.

Be concise and helpful with your responses. Refrain from restating your tools' descriptions unless it is explicitly requested.`
      }
    });

    return agent;
  } catch (error) {
    console.error('Error creating onchain agent:', error);
    throw error;
  }
}

module.exports = {
  createOnchainAgent
};