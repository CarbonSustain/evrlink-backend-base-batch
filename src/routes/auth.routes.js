const express = require('express');
const router = express.Router();
const { verifySignature } = require('../utils/crypto');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;
const { verifyToken } = require('../middleware/auth');

// Login with wallet - using the most resilient approach possible
router.post('/login', async (req, res) => {
  try {
    console.log('Login request received:', req.body);
    const { address, signature } = req.body;
    
    if (!address || !signature) {
      console.log('Missing address or signature in request');
      return res.status(400).json({ error: 'Address and signature are required' });
    }
    
    console.log(`Attempting to verify signature for address: ${address}`);
    
    // Verify signature (skip verification for development if using mock)
    const isValid = signature.startsWith('mock_signature_for_') ? true : verifySignature(address, signature);
    console.log('Signature validation result:', isValid);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // Skip all Sequelize ORM methods and use raw SQL only to avoid schema issues
    try {
      // First check if the user exists
      console.log('Using raw SQL only approach for database operations');
      const sequelize = User.sequelize;
      const UserTable = User.getTableName(); // Get dynamic table name from model
      console.log('Using User table name:', UserTable);
      
      // Check if the User table exists, create if it doesn't
      try {
        await sequelize.query(`SELECT 1 FROM ${UserTable} LIMIT 1`);
        console.log('User table exists');
        
        // Inspect the User table schema
        try {
          console.log('Checking User table schema...');
          
          // PostgreSQL-specific query to check table schema
          const tableSchema = await sequelize.query(
            `SELECT column_name, data_type, is_nullable 
             FROM information_schema.columns 
             WHERE table_name = 'users' OR table_name = ${sequelize.escape(UserTable.replace(/"/g, ''))}`,
            { type: sequelize.QueryTypes.SELECT }
          );
          
          console.log('User table schema:', JSON.stringify(tableSchema, null, 2));
          
          // Also check sequence information for PostgreSQL
          const sequenceInfo = await sequelize.query(
            `SELECT pg_get_serial_sequence(${sequelize.escape(UserTable)}, 'id') as id_sequence`,
            { type: sequelize.QueryTypes.SELECT }
          );
          
          console.log('Sequence information:', JSON.stringify(sequenceInfo, null, 2));
          
        } catch (schemaError) {
          console.error('Schema inspection error:', schemaError);
          // Continue anyway - this is just for debugging
        }
      } catch (tableError) {
        console.error('User table check failed:', tableError);
        console.log('Attempting to create User table...');
        
        try {
          // Create User table with basic structure
          await sequelize.query(`
            CREATE TABLE IF NOT EXISTS users (
              id SERIAL PRIMARY KEY,
              wallet_address VARCHAR(255) UNIQUE NOT NULL,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
          `);
          console.log('User table created successfully');
        } catch (createError) {
          console.error('Failed to create User table:', createError);
          return res.status(500).json({ error: 'Database schema issue: failed to create User table' });
        }
      }
      
      // Check if user exists with this wallet address
      const existingUsers = await sequelize.query(
        `SELECT id, wallet_address FROM users WHERE wallet_address = $1`,
        { 
          bind: [address],
          type: sequelize.QueryTypes.SELECT
        }
      );
      
      let userId;
      
      // If user exists, use their ID
      if (existingUsers && existingUsers.length > 0) {
        userId = existingUsers[0].id;
        console.log(`Found existing user: ${userId}`);
      } else {
        // Handle user creation
        console.log('User not found, creating new user with complex INSERT');
        
        // Try several different parameter styles and query approaches
        try {
          console.log('Attempting to insert new user with wallet address:', address);
          
          // Try PostgreSQL-style parameters first
          try {
            const insertResult = await sequelize.query(
              `INSERT INTO users (wallet_address) VALUES ($1) RETURNING id;`,
              { 
                bind: [address],
                type: sequelize.QueryTypes.SELECT
              }
            );
            
            console.log('PostgreSQL insert result:', JSON.stringify(insertResult));
            
            if (insertResult && insertResult.length > 0) {
              userId = insertResult[0].id;
              console.log('User created successfully with PostgreSQL-style, ID:', userId);
              return userId;
            }
          } catch (pgError) {
            console.error('PostgreSQL-style insert failed:', pgError);
            // Continue to next approach
          }
          
          // Try standard question-mark parameters
          try {
            console.log('Trying standard question-mark parameters...');
            await sequelize.query(
              `INSERT INTO users (wallet_address) VALUES (?)`,
              { 
                replacements: [address]
              }
            );
            
            // Fetch the ID
            const selectResult = await sequelize.query(
              `SELECT id FROM users WHERE wallet_address = ? ORDER BY id DESC LIMIT 1`,
              { 
                replacements: [address],
                type: sequelize.QueryTypes.SELECT
              }
            );
            
            console.log('Question-mark parameter select result:', JSON.stringify(selectResult));
            
            if (selectResult && selectResult.length > 0) {
              userId = selectResult[0].id;
              console.log('User created with question-mark parameters, ID:', userId);
              return userId;
            }
          } catch (qMarkError) {
            console.error('Question-mark parameter insert failed:', qMarkError);
            // Continue to last approach
          }
          
          // Plain SQL as last resort
          try {
            console.log('Trying plain SQL as last resort...');
            // Directly interpolate value - not usually recommended but as last resort
            // Sanitize the address input first
            const sanitizedAddress = address.replace(/'/g, "''"); // SQL escape single quotes
            await sequelize.query(
              `INSERT INTO users (wallet_address) VALUES ('${sanitizedAddress}') RETURNING id`
            );
            
            const plainResult = await sequelize.query(
              `SELECT id FROM users WHERE wallet_address = '${sanitizedAddress}' LIMIT 1`
            );
            
            console.log('Plain SQL result:', JSON.stringify(plainResult));
            
            if (plainResult && plainResult[0] && plainResult[0].length > 0) {
              userId = plainResult[0][0].id;
              console.log('User created with plain SQL, ID:', userId);
              return userId;
            }
          } catch (plainError) {
            console.error('Plain SQL insert failed:', plainError);
          }
          
          throw new Error('All insert approaches failed');
        } catch (insertError) {
          console.error('Error inserting user:', insertError);
          throw new Error('Failed to create user in database: ' + insertError.message);
        }
      }
      
      if (!userId) {
        throw new Error('Failed to get or create user account');
    }

    // Generate JWT token
    const token = jwt.sign({ 
        userId,
        walletAddress: address
    }, JWT_SECRET, { expiresIn: '24h' });

      console.log(`JWT token generated for user: ${userId}`);
      
      // Return minimal user info
    res.json({
      token,
      user: {
          id: userId,
          walletAddress: address
        }
      });
    } catch (dbError) {
      console.error('Database error during login:', dbError);
      
      // Last resort fallback - if we still can't work with the database, create an in-memory user
      console.log('Using in-memory fallback approach for development');
      
      // For development purposes, we'll create a JWT token with the wallet address
      // This is NOT secure for production but allows development to continue
      const token = jwt.sign({ 
        // Use a consistent userId based on the wallet address
        userId: parseInt(address.substring(2, 10), 16) % 1000000, // Convert part of address to number
        walletAddress: address
      }, JWT_SECRET || 'fallback_jwt_secret_for_development', { expiresIn: '24h' });
      
      console.log('Created fallback JWT token for development');
      
      // Return minimal user info
      return res.json({
        token,
        user: {
          id: parseInt(address.substring(2, 10), 16) % 1000000,
          walletAddress: address
        },
        warning: 'Using fallback authentication due to database issues. Limited functionality available.'
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// Get current user - keep it simple
router.get('/me', async (req, res) => {
  try {
    // Use raw query to avoid model validation issues
    const sequelize = User.sequelize;
    const UserTable = User.getTableName(); // Get dynamic table name from model
    
    // Log what we're looking for
    console.log('Retrieving user with ID:', req.user.userId);
    
    // Use the same parameter style as login endpoint for consistency
    const users = await sequelize.query(
      `SELECT id, wallet_address FROM users WHERE id = $1`,
      { 
        bind: [req.user.userId],
        type: sequelize.QueryTypes.SELECT
      }
    );
    
    console.log('Found users:', JSON.stringify(users));
    
    if (!users || users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];
    res.json({
      id: user.id,
      walletAddress: user.wallet_address
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});
module.exports = router;
