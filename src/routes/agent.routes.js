const express = require('express');
const router = express.Router();
const { createAgent } = require('../services/agent.service');

/**
 * @route POST /api/agent
 * @desc Process a message from the user and get a response from the agent
 * @access Public
 */
router.post('/', async (req, res) => {
  try {
    const { message } = req.body;
    const userMessage = message; // For backward compatibility
    
    if (!userMessage) {
      return res.status(400).json({ error: 'User message is required' });
    }
    
    // Get the agent instance
    const agent = await createAgent();
    
    // Stream the agent's response
    const stream = await agent.stream(
      { messages: [{ content: userMessage, role: "user" }] },
      { configurable: { thread_id: "Evrlink Discussion" } },
    );
    
    // Process the streamed response chunks into a single message
    let agentResponse = "";
    for await (const chunk of stream) {
      if ("agent" in chunk) {
        agentResponse += chunk.agent.messages[0].content;
      }
    }
    
    // Return the final response
    return res.json({ response: agentResponse });
  } catch (error) {
    console.error('Error processing agent request:', error);
    return res.status(500).json({ error: 'Failed to process message' });
  }
});

module.exports = router;