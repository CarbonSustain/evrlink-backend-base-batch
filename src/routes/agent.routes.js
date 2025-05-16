const express = require('express');
const router = express.Router();
const { createAgent } = require('../services/onchain-agent/create-agent');

/**
 * @route POST /api/agent
 * @desc Process a message from the user and get a response from the agent
 * @access Public
 */
router.post('/', async (req, res) => {
  try {
    // Handle both message formats
    const { message, userMessage: directMessage, userId = 'default', context = {} } = req.body;
    const finalMessage = directMessage || message;
    
    if (!finalMessage) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    console.log('Processing message:', {
      message: finalMessage,
      userId,
      context
    });

    // Get the agent instance for this user
    const agent = await createAgent(userId);
    
    // Stream the agent's response
    const stream = await agent.stream(
      { 
        messages: [{ content: finalMessage, role: "user" }],
        context: {
          ...context,
          platform: "Evrlink",
          features: ["gift_cards", "nft_backgrounds", "wallet_management"],
          userId
        }
      },
      { configurable: { thread_id: `Evrlink-${userId}` } },
    );
    
    // Process the streamed response chunks into a single message
    let agentResponse = "";
    for await (const chunk of stream) {
      if ("agent" in chunk) {
        agentResponse += chunk.agent.messages[0].content;
      }
    }
    
    console.log('Agent response:', agentResponse);
    
    // Return the final response
    return res.json({ response: agentResponse });
  } catch (error) {
    console.error('Error processing agent request:', error);
    return res.status(500).json({ error: 'Failed to process message' });
  }
});

module.exports = router;