const express = require('express');
const router = express.Router();
const { verifySignature } = require('../utils/crypto');
const User = require('../models/User');

// Check wallet connection status
router.get('/status', async (req, res) => {
  try {
    const { address } = req.query;
    if (!address) {
      return res.status(400).json({ error: 'Address is required' });
    }

    const user = await User.findOne({ where: { walletAddress: address } });
    res.json({
      isConnected: !!user,
      user: user ? {
        id: user.id,
        walletAddress: user.walletAddress,
        username: user.username,
        profileImageUrl: user.profileImageUrl
      } : null
    });
  } catch (error) {
    console.error('Wallet status error:', error);
    res.status(500).json({ error: 'Failed to check wallet status' });
  }
});

// Sign message for authentication
router.post('/sign', async (req, res) => {
  try {
    const { address, message } = req.body;
    
    if (!address || !message) {
      return res.status(400).json({ error: 'Address and message are required' });
    }

    // Get or create user
    let user = await User.findOne({ where: { walletAddress: address } });
    if (!user) {
      user = await User.create({ walletAddress: address });
    }

    // Generate random nonce
    const nonce = Math.random().toString(36).substring(2);

    res.json({
      nonce,
      message: `Sign this message to verify your wallet ownership: ${nonce}`
    });
  } catch (error) {
    console.error('Sign message error:', error);
    res.status(500).json({ error: 'Failed to generate sign message' });
  }
});

module.exports = router;
