/**
 * Agent Service for Evrlink
 * 
 * This service integrates both onchain and mock agent implementations.
 * It will attempt to use the onchain agent first and fall back to the mock agent if needed.
 */
const fs = require('fs');
const path = require('path');

// Import the onchain agent implementation
let createOnchainAgent;
try {
  // Try to load the compiled JS version from the dist directory first
  try {
    createOnchainAgent = require('../../dist/services/onchain-agent/create-agent').createAgent;
    console.log('Onchain agent module loaded successfully from dist directory');
  } catch (distError) {
    // If the dist version fails, try to load from the original directory
    createOnchainAgent = require('./onchain-agent/create-agent').createAgent;
    console.log('Onchain agent module loaded successfully from source directory');
  }
} catch (error) {
  console.warn('Onchain agent module not available:', error.message);
  createOnchainAgent = null;
}

// The agent instance
let agent;

/**
 * Initializes and returns an instance of the AI agent.
 * If an agent instance already exists, it returns the existing one.
 * This function will attempt to use the onchain agent first and fall back to the mock agent if needed.
 *
 * @function createAgent
 * @returns {Promise<any>} The initialized agent (onchain or mock).
 */
async function createAgent() {
  // If agent has already been initialized, return it
  if (agent) {
    return agent;
  }

  // Try to create an onchain agent first if the module is available
  if (createOnchainAgent) {
    try {
      console.log('Attempting to create onchain agent...');
      agent = await createOnchainAgent();
      console.log('Onchain agent created successfully');
      return agent;
    } catch (error) {
      console.error('Error creating onchain agent:', error);
      console.log('Falling back to mock agent...');
    }
  } else {
    console.log('Onchain agent module not available, using mock agent');
  }

  // Fall back to mock agent
  try {
    agent = new MockAgent();
    console.log('Mock agent created successfully');
    return agent;
  } catch (error) {
    console.error('Error initializing mock agent:', error);
    throw new Error('Failed to initialize agent');
  }
}



/**
 * A simplified mock agent that doesn't rely on external libraries
 * This will be used as a fallback if the onchain agent fails
 */
class MockAgent {
  constructor() {
    this.id = 'mock-agent-' + Date.now();
  }

  /**
   * Simulates streaming a response from the agent
   */
  async *stream(input, options) {
    // Simulate processing delay
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Generate a response based on the input
    const userMessage = input.messages[0].content;
    const response = this._generateResponse(userMessage);
    
    // Yield the response in the expected format
    yield {
      agent: {
        messages: [
          { content: response, role: 'assistant' }
        ]
      }
    };
  }

  /**
   * Non-streaming response for compatibility
   */
  async generateResponse(message) {
    return this._generateResponse(message);
  }

  /**
   * Internal method to generate a response based on the user's message
   */
  _generateResponse(message) {
    const lowerMessage = message.toLowerCase();
    
    // Simple pattern matching for common questions
    if (lowerMessage.includes('gift card') || lowerMessage.includes('create')) {
      return "To create a gift card in Evrlink, go to the 'Create' page, select a background, enter the recipient details, and specify the amount. You can then mint the gift card as an NFT.";
    } 
    else if (lowerMessage.includes('blockchain') || lowerMessage.includes('network')) {
      return "Evrlink currently supports Ethereum, Polygon, and Base networks. You can select your preferred network when connecting your wallet.";
    }
    else if (lowerMessage.includes('wallet') || lowerMessage.includes('connect')) {
      return "To connect your wallet, click on the 'Connect Wallet' button in the top right corner. Evrlink supports MetaMask, WalletConnect, and Coinbase Wallet.";
    }
    else if (lowerMessage.includes('background') || lowerMessage.includes('image')) {
      return "NFT backgrounds in Evrlink are customizable images that appear behind your gift cards. You can select from pre-made backgrounds or create your own in the 'Create Background' section.";
    }
    else {
      return "I'm here to help with Evrlink, a platform for creating and managing blockchain gift cards. You can ask me about creating gift cards, managing your wallet, or navigating the platform. How can I assist you today?";
    }
  }
}

module.exports = {
  createAgent
};