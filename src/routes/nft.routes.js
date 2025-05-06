const express = require('express');
const router = express.Router();
const { ethers } = require('ethers');
const { Pool } = require('pg');
const { verifyToken } = require('../middleware/auth');

// Database configuration
const pool = new Pool({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
  port: process.env.DATABASE_PORT,
});

// Contract ABI and address
const NFT_CONTRACT_ABI = require('../contracts/GiftCard.json').abi;
const NFT_CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;

// Initialize provider
const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const contract = new ethers.Contract(NFT_CONTRACT_ADDRESS, NFT_CONTRACT_ABI, provider);

// Get backgrounds created by a user
router.get('/owned/:address', async (req, res) => {
  try {
    const { address } = req.params;
    
    // Get NFT balance from smart contract
    const balance = await contract.balanceOf(address);
    
    if (balance.toString() === '0') {
      return res.json({
        success: true,
        nfts: []
      });
    }
    
    // Get all token IDs owned by the address
    const ownedTokens = [];
    for (let i = 0; i < balance; i++) {
      const tokenId = await contract.tokenOfOwnerByIndex(address, i);
      const background = await contract.backgrounds(tokenId);
      
      // Get metadata from database
      const query = `
        SELECT * FROM backgrounds 
        WHERE blockchain_id = $1
      `;
      
      const result = await pool.query(query, [tokenId.toString()]);
      const dbBackground = result.rows[0];
      
      if (dbBackground) {
        ownedTokens.push({
          id: dbBackground.id,
          tokenId: tokenId.toString(),
          name: `${dbBackground.category} #${tokenId}`,
          description: `Created by ${dbBackground.artist_address}`,
          imageUrl: dbBackground.image_uri,
          category: dbBackground.category,
          price: dbBackground.price,
          usageCount: dbBackground.usage_count,
          isMinted: true,
          createdAt: dbBackground.created_at,
          contractAddress: NFT_CONTRACT_ADDRESS,
          tokenURI: `${process.env.BASE_URL}/api/nfts/token/${tokenId}/metadata`
        });
      }
    }
    
    res.json({
      success: true,
      nfts: ownedTokens
    });
  } catch (error) {
    console.error('Error fetching owned NFTs:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch owned NFTs'
    });
  }
});

// Get metadata for a specific token (used by wallets)
router.get('/token/:tokenId/metadata', async (req, res) => {
  try {
    const { tokenId } = req.params;
    
    // Query to get background details
    const query = `
      SELECT * FROM backgrounds 
      WHERE blockchain_id = $1
    `;
    
    const result = await pool.query(query, [tokenId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Background not found'
      });
    }

    const background = result.rows[0];
    
    // Format metadata according to OpenSea standard
    const metadata = {
      name: `${background.category} #${background.blockchain_id}`,
      description: `Created by ${background.artist_address}`,
      image: background.image_uri,
      external_url: `${process.env.FRONTEND_URL}/background/${background.id}`,
      attributes: [
        {
          trait_type: "Category",
          value: background.category
        },
        {
          trait_type: "Artist",
          value: background.artist_address
        },
        {
          trait_type: "Usage Count",
          value: background.usage_count
        },
        {
          trait_type: "Price",
          value: background.price
        }
      ]
    };

    res.json(metadata);
  } catch (error) {
    console.error('Error fetching background metadata:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch background metadata'
    });
  }
});

// Mint a background as NFT
router.post('/mint/:backgroundId', verifyToken, async (req, res) => {
  try {
    const { backgroundId } = req.params;
    const { address } = req.user; // From auth middleware
    
    // Get background details
    const bgQuery = `
      SELECT * FROM backgrounds 
      WHERE id = $1 AND artist_address = $2
    `;
    
    const bgResult = await pool.query(bgQuery, [backgroundId, address.toLowerCase()]);
    
    if (bgResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Background not found or not owned by user'
      });
    }
    
    const background = bgResult.rows[0];
    
    // Check if already minted
    if (background.blockchain_id) {
      return res.status(400).json({
        success: false,
        error: 'Background already minted as NFT'
      });
    }
    
    // Create a signer for the transaction
    const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    const contractWithSigner = contract.connect(signer);
    
    // Mint the NFT
    const tx = await contractWithSigner.mintBackground(
      background.category,
      background.image_uri,
      background.price,
      address
    );
    
    const receipt = await tx.wait();
    
    // Get the token ID from the event
    const event = receipt.logs.find(log => log.topics[0] === contract.interface.getEventTopic('BackgroundMinted'));
    const tokenId = event ? parseInt(event.topics[1]) : null;
    
    if (!tokenId) {
      throw new Error('Failed to get token ID from mint transaction');
    }
    
    // Update the background with blockchain ID
    const updateQuery = `
      UPDATE backgrounds 
      SET blockchain_id = $1, blockchain_tx_hash = $2
      WHERE id = $3
      RETURNING *
    `;
    
    const updateResult = await pool.query(updateQuery, [
      tokenId.toString(),
      receipt.hash,
      backgroundId
    ]);
    
    res.json({
      success: true,
      background: updateResult.rows[0],
      transactionHash: receipt.hash
    });
  } catch (error) {
    console.error('Error minting background:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to mint background'
    });
  }
});

module.exports = router; 