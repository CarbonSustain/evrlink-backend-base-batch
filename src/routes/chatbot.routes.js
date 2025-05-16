const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/auth');
const User = require('../models/User');

/**
 * @route GET /api/chatbot/mode
 * @desc Get chatbot mode based on user's role_id
 * @access Private (requires authentication)
 */
router.get('/mode', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    console.log(`Getting chatbot mode for user: ${userId}`);
    
    // Use raw SQL to query the user's role_id directly
    const sequelize = User.sequelize;
    const result = await sequelize.query(
      `SELECT id, role_id FROM users WHERE id = $1`,
      { 
        bind: [userId],
        type: sequelize.QueryTypes.SELECT
      }
    );
    
    // Check if user exists and has a role
    if (!result || result.length === 0) {
      return res.status(404).json({ 
        error: 'User not found',
        mode: 'offline' // Default to offline chatbot if user not found
      });
    }
    
    const user = result[0];
    const roleId = user.role_id || 1; // Default to role_id 1 if not set
    
    // Determine chatbot mode based on role_id
    const chatbotMode = roleId === 1 ? 'offline' : 'online';
    
    console.log(`User ${userId} has role_id ${roleId}, chatbot mode: ${chatbotMode}`);
    
    res.json({
      userId,
      roleId,
      mode: chatbotMode,
    });
  } catch (error) {
    console.error('Error getting chatbot mode:', error);
    res.status(500).json({ 
      error: 'Failed to determine chatbot mode',
      mode: 'offline' // Default to offline in case of errors
    });
  }
});

module.exports = router;
