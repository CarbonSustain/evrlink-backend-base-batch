const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { verifyToken } = require('../middleware/auth');
const { Op } = require('sequelize');

// Create or update user profile
router.post('/', verifyToken, async (req, res) => {
  try {
    const { walletAddress, username, email, bio, profileImageUrl } = req.body;
    
    if (!walletAddress) {
      return res.status(400).json({ error: 'Wallet address is required' });
    }
    
    // Find or create user
    const [user, created] = await User.findOrCreate({
      where: { walletAddress },
      defaults: {
        username,
        email,
        bio,
        profileImageUrl,
        role_id: 1 // Default role_id is 1
      }
    });
    
    // If user exists, update their profile
    if (!created) {
      user.username = username || user.username;
      user.email = email || user.email;
      user.bio = bio || user.bio;
      user.profileImageUrl = profileImageUrl || user.profileImageUrl;
      await user.save();
    }
    
    res.json(user);
  } catch (error) {
    console.error('Create/update user error:', error);
    res.status(500).json({ error: 'Failed to create/update user' });
  }
});

// Get user profile
router.get('/:address', async (req, res) => {
  try {
    const user = await User.findOne({ where: { walletAddress: req.params.address } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Get all users with pagination and sorting
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, sortBy = 'totalGiftCardsCreated', sortOrder = 'DESC' } = req.query;
    const offset = (page - 1) * limit;
    
    const users = await User.findAndCountAll({
      limit: parseInt(limit),
      offset: parseInt(offset),
      order: [[sortBy, sortOrder]]
    });
    
    res.json({
      users: users.rows,
      total: users.count,
      page: parseInt(page),
      totalPages: Math.ceil(users.count / limit)
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Get top users
router.get('/top', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const users = await User.findAll({
      order: [['totalGiftCardsCreated', 'DESC']],
      limit: parseInt(limit)
    });
    res.json(users);
  } catch (error) {
    console.error('Get top users error:', error);
    res.status(500).json({ error: 'Failed to get top users' });
  }
});

// Search users
router.get('/search', async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.status(400).json({ error: 'Search query is required' });
    }
    
    const users = await User.findAll({
      where: {
        [Op.or]: [
          { username: { [Op.iLike]: `%${query}%` } },
          { walletAddress: { [Op.iLike]: `%${query}%` } }
        ]
      },
      limit: 10
    });
    
    res.json(users);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Get user activity
router.get('/:address/activity', async (req, res) => {
  try {
    const user = await User.findOne({ where: { walletAddress: req.params.address } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user's recent activity (transactions, gift cards, etc.)
    // This is a placeholder - implement actual activity tracking
    const activity = [];
    
    res.json(activity);
  } catch (error) {
    console.error('Get user activity error:', error);
    res.status(500).json({ error: 'Failed to get user activity' });
  }
});

module.exports = router;
