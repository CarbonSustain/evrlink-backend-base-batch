const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/auth');
const User = require('../models/User');

// In-memory cache for chatbot mode to prevent constant DB queries
// Format: { userId: { roleId, mode, timestamp } }
const modeCache = new Map();

// Cache expiration time in milliseconds (1 minute)
const CACHE_EXPIRATION = 60 * 1000;

/**
 * @route GET /api/chatbot/mode
 * @desc Get chatbot mode based on user's role_id
 * @access Private (requires authentication)
 */
router.get('/mode', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Check cache first
    if (modeCache.has(userId)) {
      const cachedData = modeCache.get(userId);
      const now = Date.now();

      // If cache is still valid (less than 5 minutes old)
      if (now - cachedData.timestamp < CACHE_EXPIRATION) {
        console.log(`Using cached chatbot mode for user ${userId}: ${cachedData.mode}`);

        // Return cached result
        return res.json({
          userId,
          roleId: cachedData.roleId,
          mode: cachedData.mode,
          cached: true
        });
      } else {
        // Cache expired, remove it
        modeCache.delete(userId);
      }
    }

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

    // Cache the result
    modeCache.set(userId, {
      roleId,
      mode: chatbotMode,
      timestamp: Date.now()
    });

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

// Add route to clear cache (for testing/admin purposes)
router.post('/clear-cache', verifyToken, (req, res) => {
  try {
    // Check if admin or just clear specific user's cache
    const userId = req.body.userId || req.user.userId;

    if (userId === 'all') {
      // Clear entire cache
      modeCache.clear();
      console.log('Cleared entire chatbot mode cache');
    } else {
      // Clear specific user's cache
      modeCache.delete(userId);
      console.log(`Cleared chatbot mode cache for user: ${userId}`);
    }

    res.json({ success: true, message: 'Cache cleared successfully' });
  } catch (error) {
    console.error('Error clearing cache:', error);
    res.status(500).json({ error: 'Failed to clear cache' });
  }
});

module.exports = router;
