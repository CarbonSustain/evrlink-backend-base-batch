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
            // Include default role_id of 1 for new users
            const insertResult = await sequelize.query(
              `INSERT INTO users (wallet_address, role_id) VALUES ($1, $2) RETURNING id`,
              { 
                bind: [address, 1], // Default role_id is 1
                type: sequelize.QueryTypes.SELECT
              }
            );
            
            if (insertResult && insertResult.length > 0) {
              userId = insertResult[0].id;
              console.log(`Created new user with ID: ${userId} and default role_id: 1`);
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
              `INSERT INTO users (wallet_address, role_id) VALUES (?, ?)`,
              { 
                replacements: [address, 1] // Default role_id is 1
              }
            );
            
            // Get the ID of the inserted user
            const newUser = await sequelize.query(
              `SELECT id FROM users WHERE wallet_address = ?`,
              { 
                replacements: [address],
                type: sequelize.QueryTypes.SELECT
              }
            );
            
            if (newUser && newUser.length > 0) {
              userId = newUser[0].id;
              console.log(`Created new user with ID: ${userId} and default role_id: 1`);
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
            const sanitizedAddress = address.replace(/'/g, "''");
            
            await sequelize.query(
              `INSERT INTO users (wallet_address, role_id) VALUES ('${sanitizedAddress}', 1)`
            );
            
            // Get the ID of the inserted user
            const newUser = await sequelize.query(
              `SELECT id FROM users WHERE wallet_address = '${sanitizedAddress}'`,
              { type: sequelize.QueryTypes.SELECT }
            );
            
            if (newUser && newUser.length > 0) {
              userId = newUser[0].id;
              console.log(`Created new user with ID: ${userId} and default role_id: 1`);
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

// Associate email with wallet address
router.post('/email-wallet', async (req, res) => {
  try {
    console.log('Email-wallet association request received:', req.body);
    const { email, walletAddress } = req.body;
    
    if (!email || !walletAddress) {
      console.log('Missing email or walletAddress in request');
      return res.status(400).json({ error: 'Email and wallet address are required' });
    }
    
    // Use raw SQL instead of Sequelize ORM to avoid schema issues
    const sequelize = User.sequelize;
    
    // First, check if the email_wallets table exists
    try {
      console.log('Checking if email_wallets table exists...');
      await sequelize.query('SELECT 1 FROM email_wallets LIMIT 1');
      console.log('email_wallets table exists');
    } catch (tableError) {
      console.log('email_wallets table does not exist, creating it...');
      try {
        // Create the email_wallets table
        await sequelize.query(`
          CREATE TABLE IF NOT EXISTS email_wallets (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            wallet_address VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);
        console.log('email_wallets table created successfully');
      } catch (createError) {
        console.error('Failed to create email_wallets table:', createError);
        return res.status(500).json({ error: 'Database schema issue: failed to create email_wallets table' });
      }
    }
    
    // Check if user exists in the users table
    console.log('Checking if user exists for wallet address:', walletAddress);
    const users = await sequelize.query(
      `SELECT id FROM users WHERE wallet_address = $1`,
      { 
        bind: [walletAddress],
        type: sequelize.QueryTypes.SELECT
      }
    );
    
    // Create user if it doesn't exist
    if (!users || users.length === 0) {
      console.log('User not found, creating new user with wallet address:', walletAddress);
      try {
        await sequelize.query(
          `INSERT INTO users (wallet_address) VALUES ($1)`,
          { 
            bind: [walletAddress]
          }
        );
        console.log('User created successfully');
      } catch (userError) {
        console.error('Error creating user:', userError);
        // Continue anyway, the association is the important part
      }
    } else {
      console.log('User exists with ID:', users[0].id);
    }
    
    // Check if email is already associated with a wallet
    console.log('Checking if email is already associated with a wallet:', email);
    const emailWallets = await sequelize.query(
      `SELECT id, wallet_address FROM email_wallets WHERE email = $1`,
      { 
        bind: [email],
        type: sequelize.QueryTypes.SELECT
      }
    );
    
    if (emailWallets && emailWallets.length > 0) {
      // Update the existing association
      console.log('Email already associated with wallet, updating to:', walletAddress);
      await sequelize.query(
        `UPDATE email_wallets SET wallet_address = $1 WHERE email = $2`,
        { 
          bind: [walletAddress, email]
        }
      );
      console.log('Updated email-wallet association');
    } else {
      // Create a new association
      console.log('Creating new email-wallet association');
      try {
        await sequelize.query(
          `INSERT INTO email_wallets (email, wallet_address) VALUES ($1, $2)`,
          { 
            bind: [email, walletAddress]
          }
        );
        console.log('Created new email-wallet association');
      } catch (insertError) {
        console.error('Error creating email-wallet association:', insertError);
        
        // Try another approach with plain SQL if the parameterized query fails
        try {
          const sanitizedEmail = email.replace(/'/g, "''");
          const sanitizedWalletAddress = walletAddress.replace(/'/g, "''");
          
          await sequelize.query(
            `INSERT INTO email_wallets (email, wallet_address) VALUES ('${sanitizedEmail}', '${sanitizedWalletAddress}')`
          );
          console.log('Created email-wallet association with plain SQL');
        } catch (plainError) {
          console.error('Error with plain SQL insert:', plainError);
          throw new Error('All insert approaches failed');
        }
      }
    }
    
    res.json({
      success: true,
      data: {
        email,
        walletAddress
      }
    });
  } catch (error) {
    console.error('Email-wallet association error:', error);
    res.status(500).json({ error: 'Failed to associate email with wallet: ' + error.message });
  }
});

// Get wallet address by email
router.get('/email-wallet', async (req, res) => {
  try {
    console.log('Get wallet by email request received:', req.query);
    const { email } = req.query;
    
    if (!email) {
      console.log('Missing email in request');
      return res.status(400).json({ error: 'Email is required' });
    }
    
    // Use raw SQL instead of Sequelize ORM
    const sequelize = User.sequelize;
    
    // Check if the email_wallets table exists
    try {
      await sequelize.query('SELECT 1 FROM email_wallets LIMIT 1');
    } catch (tableError) {
      console.log('email_wallets table does not exist');
      return res.status(404).json({ 
        success: false,
        error: 'No wallet found for this email'
      });
    }
    
    // Find email-wallet association
    const emailWallets = await sequelize.query(
      `SELECT wallet_address FROM email_wallets WHERE email = $1`,
      { 
        bind: [email],
        type: sequelize.QueryTypes.SELECT
      }
    );
    
    if (!emailWallets || emailWallets.length === 0) {
      console.log('No wallet found for email:', email);
      return res.status(404).json({ 
        success: false,
        error: 'No wallet found for this email'
      });
    }
    
    const walletAddress = emailWallets[0].wallet_address;
    console.log('Found wallet for email:', email, walletAddress);
    
    res.json({
      success: true,
      email,
      walletAddress
    });
  } catch (error) {
    console.error('Get wallet by email error:', error);
    res.status(500).json({ error: 'Failed to get wallet for email: ' + error.message });
  }
});

// Login with email
router.post('/login-email', async (req, res) => {
  try {
    console.log('Login with email request received:', req.body);
    const { email } = req.body;
    
    if (!email) {
      console.log('Missing email in request');
      return res.status(400).json({ error: 'Email is required' });
    }
    
    // Use raw SQL instead of Sequelize ORM
    const sequelize = User.sequelize;
    
    // Check if the email is associated with a wallet
    try {
      // Check if the email_wallets table exists
      try {
        await sequelize.query('SELECT 1 FROM email_wallets LIMIT 1');
      } catch (tableError) {
        console.log('email_wallets table does not exist, creating it...');
        await sequelize.query(`
          CREATE TABLE IF NOT EXISTS email_wallets (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            wallet_address VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);
      }
      
      // Find email-wallet association
      const emailWallets = await sequelize.query(
        `SELECT wallet_address FROM email_wallets WHERE email = $1`,
        { 
          bind: [email],
          type: sequelize.QueryTypes.SELECT
        }
      );
      
      if (!emailWallets || emailWallets.length === 0) {
        console.log('No wallet found for email:', email);
        return res.status(404).json({ 
          success: false,
          error: 'No wallet found for this email'
        });
      }
      
      const walletAddress = emailWallets[0].wallet_address;
      console.log('Found wallet for email:', email, walletAddress);
      
      // Now login with the wallet address (create a mock signature)
      const signature = `mock_signature_for_${walletAddress}`;
      
      // Check if user exists with this wallet address
      const existingUsers = await sequelize.query(
        `SELECT id FROM users WHERE wallet_address = $1`,
        { 
          bind: [walletAddress],
          type: sequelize.QueryTypes.SELECT
        }
      );
      
      let userId;
      
      // If user exists, use their ID
      if (existingUsers && existingUsers.length > 0) {
        userId = existingUsers[0].id;
        console.log(`Found existing user: ${userId}`);
      } else {
        // Create a new user with this wallet address and default role_id of 1
        console.log('User not found, creating new user with wallet address:', walletAddress);
        
        try {
          const insertResult = await sequelize.query(
            `INSERT INTO users (wallet_address, role_id, email) VALUES ($1, $2, $3) RETURNING id`,
            { 
              bind: [walletAddress, 1, email], // Default role_id is 1
              type: sequelize.QueryTypes.SELECT
            }
          );
          
          if (insertResult && insertResult.length > 0) {
            userId = insertResult[0].id;
            console.log(`Created new user with ID: ${userId} and default role_id: 1`);
          } else {
            throw new Error('Failed to create user');
          }
        } catch (insertError) {
          console.error('Error inserting user:', insertError);
          throw new Error('Failed to create user in database: ' + insertError.message);
        }
      }
      
      // Generate JWT token
      const token = jwt.sign({ 
        userId,
        walletAddress
      }, JWT_SECRET, { expiresIn: '24h' });
      
      console.log(`JWT token generated for user: ${userId}`);
      
      // Return user info with token
      res.json({
        token,
        user: {
          id: userId,
          walletAddress,
          email
        }
      });
      
    } catch (error) {
      console.error('Email login error:', error);
      res.status(500).json({ error: 'Login failed: ' + error.message });
    }
  } catch (error) {
    console.error('Login with email error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

module.exports = router;
