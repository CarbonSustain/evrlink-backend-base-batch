import { getLangChainTools } from "@coinbase/agentkit-langchain";
import { ChatOpenAI } from "@langchain/openai";
import { prepareAgentkitAndWalletProvider } from "./prepare-agentkit";

// Define a simpler AgentExecutor type for compatibility
interface SimpleAgentExecutor {
  run: (input: string) => Promise<string>;
  stream: (input: any, options: any) => Promise<AsyncGenerator<any, void, unknown>>;
  call: (params: { input: string }) => Promise<{ output: string }>;
}

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
const agentInstances: Record<string, SimpleAgentExecutor> = {};

/**
 * Initializes and returns an instance of the AI agent for a specific user.
 * If an agent instance already exists for the user, it returns the existing one.
 *
 * @function createAgent
 * @param {string} userId - The ID of the user to create or retrieve an agent for
 * @returns {Promise<SimpleAgentExecutor>} The initialized AI agent.
 *
 * @description Handles agent setup for a specific user
 *
 * @throws {Error} If the agent initialization fails.
 */
export async function createAgent(userId: string = "default"): Promise<SimpleAgentExecutor> {
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
    const modelName = process.env.OPENAI_MODEL || "gpt-4o-mini";
    console.log(`Using OpenAI model: ${modelName}`);
    const llm = new ChatOpenAI({
      openAIApiKey: process.env.OPENAI_API_KEY,
      modelName: modelName,
      temperature: 0.1
    });

    const tools = await getLangChainTools(agentkit);

    // Initialize Agent
    const canUseFaucet = walletProvider.getNetwork().networkId == "base-sepolia";
    const faucetMessage = `If you ever need funds, you can request them from the faucet.`;
    const cantUseFaucetMessage = `If you need funds, you can provide your wallet details and request funds from the user.`;
    // Create a simpler agent approach for compatibility
    const systemPrompt = `You are a helpful agent that assists users with Evrlink, a platform for creating and managing blockchain gift cards.
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
    docs.cdp.coinbase.com for more information.`;
    
    // Create a simplified agent to handle the requests
    // This is a workaround to avoid complex compatibility issues with various LangChain versions
    const executor: SimpleAgentExecutor = {
      run: async (input: string) => {
        console.log(`[Agent] Processing request for user ${userId}: ${input}`);
        try {
          // Create a system message with our context
          const systemMessage = `You are a helpful agent that assists users with Evrlink. ${canUseFaucet ? faucetMessage : cantUseFaucetMessage}\n` +
            "You can help with gift cards, wallet management, and navigating the Evrlink platform.";
          
          // Use the LLM directly for simplicity
          const response = await llm.predict(systemMessage + "\n\nUser: " + input + "\n\nAssistant:");
          console.log(`[Agent] Generated response for user ${userId}`);
          return response;
        } catch (error) {
          console.error(`[Agent] Error processing request for user ${userId}:`, error);
          return "I'm sorry, I encountered an error processing your request. Please try again or contact support if the issue persists.";
        }
      },
      
      // Add call method to support server.js direct calls
      call: async (params: { input: string }) => {
        console.log(`[Agent] Call request for user ${userId}: ${params.input}`);
        try {
          // Create a system message with our context
          const systemMessage = `You are a helpful agent that assists users with Evrlink. ${canUseFaucet ? faucetMessage : cantUseFaucetMessage}\n` +
            "You can help with gift cards, wallet management, and navigating the Evrlink platform.";
          
          // Use the LLM directly for simplicity
          const response = await llm.predict(systemMessage + "\n\nUser: " + params.input + "\n\nAssistant:");
          console.log(`[Agent] Generated call response for user ${userId}`);
          return { output: response };
        } catch (error) {
          console.error(`[Agent] Error processing call request for user ${userId}:`, error);
          return { output: "I'm sorry, I encountered an error processing your request. Please try again or contact support if the issue persists." };
        }
      },
      
      // Add stream method to support the agent routes
      stream: async (input: any, options: any) => {
        console.log(`[Agent] Streaming request for user ${userId || 'default'}:`, input.messages[0].content);
        try {
          // Create a system message with our context
          const systemMessage = `You are a helpful agent that assists users with Evrlink. ${canUseFaucet ? faucetMessage : cantUseFaucetMessage}\n` +
            "You can help with gift cards, wallet management, and navigating the Evrlink platform.";
          
          // Use the LLM directly for simplicity
          const userMessage = input.messages[0].content;
          const response = await llm.predict(systemMessage + "\n\nUser: " + userMessage + "\n\nAssistant:");
          console.log(`[Agent] Generated streaming response for user ${userId || 'default'}`);
          
          // Return an async generator that yields the response
          return (async function* () {
            yield {
              agent: {
                messages: [
                  { content: response, role: 'assistant' }
                ]
              }
            };
          })();
        } catch (error) {
          console.error(`[Agent] Error processing streaming request for user ${userId || 'default'}:`, error);
          return (async function* () {
            yield {
              agent: {
                messages: [
                  { content: "I'm sorry, I encountered an error processing your request. Please try again or contact support if the issue persists.", role: 'assistant' }
                ]
              }
            };
          })();
        }
      }
    };
    
    // Store the agent instance for this user
    agentInstances[userId] = executor;

    return agentInstances[userId];
  } catch (error) {
    console.error("Error initializing agent:", error);
    throw new Error(`Failed to initialize agent for user ${userId}`);
  }
}

/**
 * Export the createAgent function as createOnchainAgent for compatibility
 * with the agent.service.js file which is looking for this export name
 */
export const createOnchainAgent = createAgent;