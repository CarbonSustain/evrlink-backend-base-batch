const express = require('express');
const router = express.Router();
const Background = require('../models/Background');
const { upload } = require('../middleware/multer');
const { verifyToken } = require('../middleware/auth');
const ethers = require('ethers');
const path = require('path');
const { updateBackgroundAfterMint, updateUserMintingStats } = require('../utils/blockchain-updates');
const { Op } = require('sequelize');
const fs = require('fs');

// Helper function for ethers version compatibility
function parseLog(log, contract) {
  try {
    // For ethers v6
    if (log.fragment && log.fragment.name) {
      return {
        name: log.fragment.name,
        args: log.args
      };
    }
    
    // For ethers v5
    if (contract && contract.interface) {
      const parsedLog = contract.interface.parseLog(log);
      if (parsedLog) {
        return {
          name: parsedLog.name,
          args: parsedLog.args
        };
      }
    }
    
    return null;
  } catch (err) {
    console.error('Error parsing log:', err);
    return null;
  }
}

// Helper function to check if an image file exists
function imageExists(imageUrl) {
  if (!imageUrl) return false;
  
  let filename;
  try {
    // Extract filename from URL
    const url = new URL(imageUrl);
    filename = path.basename(url.pathname);
  } catch (err) {
    // If not a valid URL, try to extract the filename directly
    filename = path.basename(imageUrl);
  }
  
  // Check if the file exists in the uploads directory
  const filePath = path.join(__dirname, '../../uploads', filename);
  return fs.existsSync(filePath);
}

// Get all backgrounds with filtering
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, category } = req.query;
    const offset = (page - 1) * limit;
    
    const where = {};
    if (category) {
      where.category = category;
    }
    
    const backgrounds = await Background.findAndCountAll({
      where,
      limit: parseInt(limit),
      offset: parseInt(offset),
      order: [['createdAt', 'DESC']]
    });
    
    res.json({
      backgrounds: backgrounds.rows,
      total: backgrounds.count,
      page: parseInt(page),
      totalPages: Math.ceil(backgrounds.count / limit)
    });
  } catch (error) {
    console.error('Get backgrounds error:', error);
    res.status(500).json({ error: 'Failed to get backgrounds' });
  }
});

// Get popular backgrounds
router.get('/popular', async (req, res) => {
  try {
    const backgrounds = await Background.findAll({
      order: [['usageCount', 'DESC']],
      limit: 10
    });
    res.json(backgrounds);
  } catch (error) {
    console.error('Get popular backgrounds error:', error);
    res.status(500).json({ error: 'Failed to get popular backgrounds' });
  }
});

// Get all categories
router.get('/categories', async (req, res) => {
  try {
    const categories = await Background.findAll({
      attributes: ['category'],
      group: ['category']
    });
    res.json(categories.map(cat => cat.category));
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Failed to get categories' });
  }
});

// Get background by ID
router.get('/:id', async (req, res) => {
  try {
    const background = await Background.findByPk(req.params.id);
    if (!background) {
      return res.status(404).json({ error: 'Background not found' });
    }
    
    // Check if the image file exists
    if (!imageExists(background.imageURI)) {
      console.log(`Warning: Image not found for background ID ${req.params.id}: ${background.imageURI}`);
      return res.status(404).json({ 
        error: 'Background image not found',
        message: 'The image file for this background does not exist'
      });
    }
    
    res.json(background);
  } catch (error) {
    console.error('Get background error:', error);
    res.status(500).json({ error: 'Failed to get background' });
  }
});

// Create new background
router.post('/', verifyToken, upload.single('image'), async (req, res) => {
  try {
    const { category, price } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'Image file is required' });
    }
    
    // Generate URL based on server configuration
    const protocol = req.secure ? 'https' : 'http';
    const host = req.get('host');
    const imageUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
    
    console.log('Creating background with:', { 
      imageUrl, 
      category, 
      price, 
      user: req.user 
    });

    if (!category || !price) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Create background with auto-incrementing ID
    const background = await Background.create({
      artistAddress: req.user ? req.user.userId : req.body.artistAddress,
      imageURI: imageUrl,
      category,
      price,
      usageCount: 0
    });

    console.log('Background created:', background);

    res.status(201).json({
      id: background.id,
      artistAddress: background.artistAddress,
      imageURI: background.imageURI,
      category: background.category,
      price: background.price,
      usageCount: background.usageCount
    });
  } catch (error) {
    console.error('Create background error:', error);
    res.status(500).json({ error: 'Failed to create background: ' + error.message });
  }
});

// Mint background NFT
router.post('/mint', verifyToken, upload.single('image'), async (req, res) => {
  try {
    const { category, price } = req.body;
    const imageFile = req.file;
    
    if (!imageFile) {
      return res.status(400).json({ error: 'Image file is required' });
    }
    
    // Generate URL based on server configuration
    const protocol = req.secure ? 'https' : 'http';
    const host = req.get('host');
    const imageUrl = `${protocol}://${host}/uploads/${imageFile.filename}`;
    
    // Debug user info from token
    console.log('User info from token:', req.user);
    
    // Get the actual wallet address from request body or token
    // Always prefer the actual wallet address over user ID
    const walletAddress = req.body.artistAddress || (req.user ? req.user.walletAddress : null);
    
    console.log('Minting background NFT with:', { 
      imageUrl, 
      category, 
      price, 
      artistAddress: walletAddress 
    });
    
    if (!category || !price) {
      return res.status(400).json({ error: 'Category and price are required' });
    }
    
    if (!walletAddress) {
      return res.status(400).json({ error: 'Artist wallet address is required' });
    }

    // Create a database record first
    const localBackground = await Background.create({
      artistAddress: walletAddress, // Store the wallet address instead of user ID
      imageURI: imageUrl,
      category,
      price,
      usageCount: 0
    });
    
    console.log('Background record created in database:', localBackground);
    
    // Get contract and wallet from app
    const app = req.app;
    
    // Check if blockchain is enabled and contract is available
    const blockchainEnabled = app.blockchainEnabled === true && app.contract && app.wallet;
    
    if (!blockchainEnabled) {
      console.warn('Blockchain connection not available - creating database record only');
      return res.status(201).json({ 
        success: true,
        warning: 'Blockchain connection not available - NFT minting skipped',
        background: {
          id: localBackground.id,
          artistAddress: localBackground.artistAddress,
          imageURI: localBackground.imageURI,
          category: localBackground.category,
          price: localBackground.price,
          usageCount: localBackground.usageCount
        }
      });
    }
    
    // Create full URI for the image - ensure it's accessible from the internet
    // In production, this should be an IPFS or permanent storage URL
    let fullImageURI;
    try {
      // Ensure base URL is properly configured
      const baseUrl = process.env.BASE_URL || 
                     (process.env.NODE_ENV === 'production' 
                       ? 'https://yourdomain.com' 
                       : `${req.protocol}://${req.get('host')}`);
      
      // Use the already constructed imageUrl which is complete
      fullImageURI = imageUrl;
      
      console.log(`Using image URI: ${fullImageURI}`);
    } catch (urlError) {
      console.error('Error constructing image URI:', urlError);
      fullImageURI = imageUrl; // Fallback to the original URL
    }
    
    console.log(`Server wallet address: ${app.wallet.address}`);
    console.log(`Artist address: ${walletAddress}`);
    console.log(`Minting with image URI: ${fullImageURI}`);
    console.log(`Category: ${category}`);
    
    // The server wallet will mint the background NFT on behalf of the user
    try {
      const tx = await app.contract.mintBackground(fullImageURI, category);
      
      console.log('Transaction hash:', tx.hash);
      console.log('Transaction sent to blockchain - Etherscan URL:', 
        `https://sepolia.etherscan.io/tx/${tx.hash}`);
      
      // Update the database with the transaction hash
      try {
        await updateBackgroundAfterMint(localBackground, tx.hash);
      } catch (updateError) {
        console.error('Error updating background after mint:', updateError);
        // Continue anyway - the transaction was sent
      }
      
      // Wait for the transaction to be mined with a timeout
      try {
        const receipt = await Promise.race([
          tx.wait(),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Transaction timeout')), 120000)) // 2 minute timeout
        ]);
        
        console.log('Transaction mined! Receipt:', receipt);
        
        // Extract the backgroundId from the event
        const event = receipt.logs.find(log => {
          try {
            // For ethers v6
            if (log.fragment && log.fragment.name === "BackgroundMinted") {
              return true;
            }
            
            // For ethers v5
            if (app.contract && app.contract.interface) {
              try {
                const parsedLog = app.contract.interface.parseLog(log);
                return parsedLog && parsedLog.name === "BackgroundMinted";
              } catch (parseErr) {
                return false;
              }
            }
            
            return false;
          } catch (err) {
            console.log('Error checking log fragment:', err);
            return false;
          }
        });
        
        if (event) {
          let backgroundId;
          
          // Extract background ID based on ethers version
          if (event.args && event.args.backgroundId) {
            // ethers v6
            backgroundId = event.args.backgroundId.toString();
          } else if (app.contract && app.contract.interface) {
            // ethers v5
            try {
              const parsedLog = app.contract.interface.parseLog(event);
              backgroundId = parsedLog.args.backgroundId.toString();
            } catch (err) {
              console.error('Error parsing log for backgroundId:', err);
            }
          }
          
          if (!backgroundId) {
            console.error('Could not extract backgroundId from event');
            backgroundId = 'unknown';
          }
          
          console.log('Background minted with blockchain ID:', backgroundId);
          
          // Update the database record with the blockchain ID
          try {
            await updateBackgroundAfterMint(localBackground, tx.hash, backgroundId);
          } catch (updateError) {
            console.error('Error updating background with blockchain ID:', updateError);
            // Continue anyway - we'll still return success
          }
          
          return res.status(201).json({
            success: true,
            background: {
              id: localBackground.id,
              artistAddress: localBackground.artistAddress,
              imageURI: localBackground.imageURI,
              category: localBackground.category,
              price: localBackground.price,
              blockchainTxHash: localBackground.blockchainTxHash,
              blockchainId: backgroundId,
              transactionHash: localBackground.blockchainTxHash,
              etherscanUrl: `https://sepolia.etherscan.io/tx/${localBackground.blockchainTxHash}`
            }
          });
        }
        console.log('No BackgroundMinted event found in receipt');
        console.log('All logs:', receipt.logs);
        
        return res.status(201).json({
          success: true,
          warning: 'Transaction completed but no BackgroundMinted event found',
          background: {
            id: localBackground.id,
            artistAddress: localBackground.artistAddress,
            imageURI: localBackground.imageURI,
            category: localBackground.category,
            price: localBackground.price,
            blockchainTxHash: localBackground.blockchainTxHash,
            transactionHash: localBackground.blockchainTxHash,
            etherscanUrl: `https://sepolia.etherscan.io/tx/${localBackground.blockchainTxHash}`
          }
        });
      } catch (miningError) {
        console.error('Error waiting for transaction to be mined:', miningError);
        
        // Transaction was sent but failed to mine or get receipt in time
        return res.status(201).json({
          success: true,
          warning: 'Transaction sent but confirmation status unknown',
          error: miningError.message,
          background: {
            id: localBackground.id,
            artistAddress: localBackground.artistAddress,
            imageURI: localBackground.imageURI,
            category: localBackground.category,
            price: localBackground.price,
            blockchainTxHash: localBackground.blockchainTxHash,
            transactionHash: localBackground.blockchainTxHash,
            etherscanUrl: `https://sepolia.etherscan.io/tx/${localBackground.blockchainTxHash}`
          }
        });
      }
    } catch (contractError) {
      console.error('Error calling blockchain contract:', contractError);
      
      // We still created the background in the database, so return success with warning
      return res.status(201).json({
        success: true,
        warning: 'Background created in database but blockchain minting failed',
        error: contractError.message,
        background: {
          id: localBackground.id,
          artistAddress: localBackground.artistAddress,
          imageURI: localBackground.imageURI,
          category: localBackground.category,
          price: localBackground.price
        }
      });
    }
  } catch (error) {
    console.error('Mint background error:', error);
    res.status(500).json({ error: 'Failed to mint background' });
  }
});

// Verify background status
router.get('/verify/:id', verifyToken, async (req, res) => {
  try {
    const background = await Background.findByPk(req.params.id);
    if (!background) {
      return res.status(404).json({ error: 'Background not found' });
    }
    
    // If there's no blockchain transaction hash, it's not yet minted
    if (!background.blockchainTxHash) {
      return res.status(200).json({
        success: true,
        status: 'pending',
        message: 'Background not yet submitted to blockchain',
        background: {
          id: background.id,
          artistAddress: background.artistAddress,
          imageURI: background.imageURI,
          category: background.category,
          price: background.price
        }
      });
    }
    
    // If we already have a blockchain ID, it's confirmed
    if (background.blockchainId) {
      return res.status(200).json({
        success: true,
        status: 'confirmed',
        message: 'Background successfully minted on blockchain',
        background: {
          id: background.id,
          artistAddress: background.artistAddress,
          imageURI: background.imageURI,
          category: background.category,
          price: background.price,
          blockchainTxHash: background.blockchainTxHash,
          blockchainId: background.blockchainId,
          transactionHash: background.blockchainTxHash,
          etherscanUrl: `https://sepolia.etherscan.io/tx/${background.blockchainTxHash}`
        }
      });
    }
    
    // If we have a transaction hash but no blockchain ID, check the transaction status
    const app = req.app;
    if (!app.contract || !app.wallet) {
      return res.status(200).json({
        success: true,
        status: 'unknown',
        message: 'Blockchain connection not available to verify transaction',
        background: {
          id: background.id,
          artistAddress: background.artistAddress,
          imageURI: background.imageURI,
          category: background.category,
          price: background.price,
          blockchainTxHash: background.blockchainTxHash,
          transactionHash: background.blockchainTxHash,
          etherscanUrl: `https://sepolia.etherscan.io/tx/${background.blockchainTxHash}`
        }
      });
    }
    
    // Verify the transaction status using the provider
    const { verifyTransaction } = require('../utils/blockchain-updates');
    const receipt = await verifyTransaction(background.blockchainTxHash, app.wallet.provider);
    
    if (!receipt) {
      return res.status(200).json({
        success: true,
        status: 'pending',
        message: 'Transaction is still pending or not found',
        background: {
          id: background.id,
          artistAddress: background.artistAddress,
          imageURI: background.imageURI,
          category: background.category,
          price: background.price,
          blockchainTxHash: background.blockchainTxHash,
          transactionHash: background.blockchainTxHash,
          etherscanUrl: `https://sepolia.etherscan.io/tx/${background.blockchainTxHash}`
        }
      });
    }
    
    // Check if the transaction was successful
    if (receipt.status === 1) {
      // Try to extract the event data
      const logs = receipt.logs;
      const event = logs.find(log => {
        try {
          // For ethers v6
          if (log.fragment && log.fragment.name === "BackgroundMinted") {
            return true;
          }
          
          // For ethers v5
          if (app.contract && app.contract.interface) {
            try {
              const parsedLog = app.contract.interface.parseLog(log);
              return parsedLog && parsedLog.name === "BackgroundMinted";
            } catch (parseErr) {
              return false;
            }
          }
          
          return false;
        } catch (err) {
          console.error('Error checking log fragment:', err);
          return false;
        }
      });
      
      if (event) {
        let blockchainId;
        
        // Extract background ID based on ethers version
        if (event.args && event.args.backgroundId) {
          // ethers v6
          blockchainId = event.args.backgroundId.toString();
        } else if (app.contract && app.contract.interface) {
          // ethers v5
          try {
            const parsedLog = app.contract.interface.parseLog(event);
            blockchainId = parsedLog.args.backgroundId.toString();
          } catch (err) {
            console.error('Error parsing log for backgroundId:', err);
          }
        }
        
        if (!blockchainId) {
          console.error('Could not extract backgroundId from event');
          blockchainId = 'unknown';
        }
        
        // Update the database with the blockchain ID
        await updateBackgroundAfterMint(background, background.blockchainTxHash, blockchainId);
        
        return res.status(200).json({
          success: true,
          status: 'confirmed',
          message: 'Background successfully minted on blockchain',
          background: {
            id: background.id,
            artistAddress: background.artistAddress,
            imageURI: background.imageURI,
            category: background.category,
            price: background.price,
            blockchainTxHash: background.blockchainTxHash,
            blockchainId,
            transactionHash: background.blockchainTxHash,
            etherscanUrl: `https://sepolia.etherscan.io/tx/${background.blockchainTxHash}`
          }
        });
      }
      
      // Transaction successful but event not found
      return res.status(200).json({
        success: true,
        status: 'confirmed_no_event',
        message: 'Transaction confirmed but BackgroundMinted event not found',
        background: {
          id: background.id,
          artistAddress: background.artistAddress,
          imageURI: background.imageURI,
          category: background.category,
          price: background.price,
          blockchainTxHash: background.blockchainTxHash,
          transactionHash: background.blockchainTxHash,
          etherscanUrl: `https://sepolia.etherscan.io/tx/${background.blockchainTxHash}`
        }
      });
    } else {
      // Transaction failed
      return res.status(200).json({
        success: true,
        status: 'failed',
        message: 'Transaction failed on the blockchain',
        background: {
          id: background.id,
          artistAddress: background.artistAddress,
          imageURI: background.imageURI,
          category: background.category,
          price: background.price,
          blockchainTxHash: background.blockchainTxHash,
          transactionHash: background.blockchainTxHash,
          etherscanUrl: `https://sepolia.etherscan.io/tx/${background.blockchainTxHash}`
        }
      });
    }
  } catch (error) {
    console.error('Verify background error:', error);
    res.status(500).json({ error: 'Failed to verify background' });
  }
});

// Get Backgrounds by Category
router.get('/category/:category', async (req, res) => {
  try {
    const backgrounds = await Background.findAll({
      where: { category: req.params.category }
    });
    
    // Filter out backgrounds with missing images
    const validBackgrounds = backgrounds.filter(background => 
      imageExists(background.imageURI)
    );
    
    console.log(`Found ${validBackgrounds.length} valid backgrounds with images in category ${req.params.category} (filtered from ${backgrounds.length} total)`);
    
    res.json({ 
      success: true, 
      backgrounds: validBackgrounds 
    });
  } catch (error) {
    console.error('Get backgrounds by category error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get backgrounds' 
    });
  }
});

module.exports = router;
