const express = require('express');
const cors = require('cors');
const path = require('path');
const sequelize = require('../db/db_config');
const routes = require('./routes');
const { verifyToken } = require('./middleware/auth');
const blockchainService = require('./services/blockchain');
const { BLOCKCHAIN_ENABLED } = require('./config');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api', routes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    details: err.message 
  });
});

// 404 handler for non-existent routes
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Initialize blockchain service if enabled
if (BLOCKCHAIN_ENABLED) {
  blockchainService.initialize()
    .then(() => {
      app.contract = blockchainService.contract;
      console.log('✅ Blockchain integration ready');
    })
    .catch(error => {
      console.error('❌ Failed to initialize blockchain:', error);
    });
}

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});