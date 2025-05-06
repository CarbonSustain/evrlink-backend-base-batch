const Background = require('../models/Background');
const User = require('../models/User');
const { Op } = require('sequelize');

/**
 * Update database records after minting a background NFT
 * @param {Object} localBackground - The database background record
 * @param {String} blockchainTxHash - The blockchain transaction hash
 * @param {String|null} blockchainId - The blockchain token ID (optional)
 */
async function updateBackgroundAfterMint(localBackground, blockchainTxHash, blockchainId = null) {
  console.log('Updating database with blockchain information:', {
    backgroundId: localBackground.id,
    blockchainTxHash,
    blockchainId
  });
  
  const updateData = { blockchainTxHash };
  if (blockchainId) {
    updateData.blockchainId = blockchainId;
  }
  
  try {
    await localBackground.update(updateData);
    console.log('Background record updated successfully');
    
    // If a blockchain ID was provided, update user stats
    if (blockchainId && localBackground.artistAddress) {
      await updateUserMintingStats(localBackground.artistAddress);
    }
    
    return true;
  } catch (error) {
    console.error('Error updating background record:', error);
    throw error;
  }
}

/**
 * Update user statistics after minting a background
 * @param {String} walletAddress - The wallet address of the artist
 */
async function updateUserMintingStats(walletAddress) {
  try {
    console.log(`Updating statistics for user with wallet address: ${walletAddress}`);
    
    // Find the user
    const user = await User.findOne({ where: { walletAddress } });
    if (!user) {
      console.log(`No user found with wallet address: ${walletAddress}`);
      
      // Try with a direct SQL query to handle potential table name discrepancies
      const sequelize = User.sequelize;
      try {
        const UserTable = User.getTableName();
        console.log(`Trying direct SQL with table: ${UserTable}`);
        
        // Count the total number of backgrounds minted by this user
        const mintedCount = await Background.count({ 
          where: { 
            artistAddress: walletAddress,
            blockchainId: { [Op.ne]: null } // Only count backgrounds that have been successfully minted
          } 
        });
        
        // Try to update the user with a raw SQL query
        await sequelize.query(
          `UPDATE ${UserTable} 
           SET total_backgrounds_minted = :mintedCount, 
               last_login_at = NOW() 
           WHERE wallet_address = :walletAddress`,
          { 
            replacements: { 
              mintedCount, 
              walletAddress 
            },
            type: sequelize.QueryTypes.UPDATE
          }
        );
        
        console.log(`User statistics updated via direct SQL: Total backgrounds minted = ${mintedCount}`);
        return true;
      } catch (sqlError) {
        console.error('Error updating user with direct SQL:', sqlError);
        // Don't throw error, just log it and return false
        return false;
      }
    }
    
    // Count the total number of backgrounds minted by this user
    const mintedCount = await Background.count({ 
      where: { 
        artistAddress: walletAddress,
        blockchainId: { [Op.ne]: null } // Only count backgrounds that have been successfully minted
      } 
    });
    
    // Update the user record
    await user.update({
      totalBackgroundsMinted: mintedCount,
      lastLoginAt: new Date()
    });
    
    console.log(`User statistics updated: Total backgrounds minted = ${mintedCount}`);
    return true;
  } catch (error) {
    console.error('Error updating user statistics:', error);
    // Don't fail the entire operation, just log the error
    return false;
  }
}

/**
 * Verify blockchain transaction status
 * @param {String} txHash - Transaction hash to verify
 * @param {Object} provider - Ethers.js provider
 * @returns {Promise<Object>} Transaction receipt or null
 */
async function verifyTransaction(txHash, provider) {
  try {
    const receipt = await provider.getTransactionReceipt(txHash);
    return receipt;
  } catch (error) {
    console.error('Error verifying transaction:', error);
    return null;
  }
}

/**
 * Check and fix artist address if it's a user ID instead of a wallet address
 * @param {Number} backgroundId - The background ID to check
 */
async function checkAndFixArtistAddress(backgroundId) {
  try {
    const background = await Background.findByPk(backgroundId);
    if (!background) {
      console.log(`No background found with ID: ${backgroundId}`);
      return false;
    }
    
    // Check if the artistAddress looks like a numeric ID
    const artistAddress = background.artistAddress;
    const isNumericId = /^\d+$/.test(artistAddress) && artistAddress.length < 10;
    
    if (isNumericId) {
      console.log(`Found numeric ID as artistAddress: ${artistAddress}`);
      
      // Look up the user to get the actual wallet address
      const user = await User.findByPk(parseInt(artistAddress));
      if (user && user.walletAddress) {
        console.log(`Fixing artistAddress from ${artistAddress} to ${user.walletAddress}`);
        
        // Update the background with the correct wallet address
        await background.update({
          artistAddress: user.walletAddress
        });
        
        console.log(`Updated background #${backgroundId} with wallet address ${user.walletAddress}`);
        return true;
      } else {
        console.log(`Could not find user with ID ${artistAddress}`);
        return false;
      }
    } else {
      console.log(`ArtistAddress already appears to be a wallet address: ${artistAddress}`);
      return true;
    }
  } catch (error) {
    console.error(`Error checking/fixing artist address: ${error}`);
    return false;
  }
}

module.exports = {
  updateBackgroundAfterMint,
  updateUserMintingStats,
  verifyTransaction,
  checkAndFixArtistAddress
}; 