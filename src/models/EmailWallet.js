const { DataTypes } = require('sequelize');
const sequelize = require('../../db/db_config');

// Define the EmailWallet model to associate emails with wallet addresses
const EmailWallet = sequelize.define('EmailWallet', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
    field: 'id'
  },
  email: {
    type: DataTypes.STRING,
    field: 'email',
    allowNull: false,
    unique: true
  },
  walletAddress: {
    type: DataTypes.STRING,
    field: 'wallet_address',
    allowNull: false
  },
  createdAt: {
    type: DataTypes.DATE,
    field: 'created_at',
    defaultValue: sequelize.literal('CURRENT_TIMESTAMP')
  }
}, {
  tableName: 'email_wallets',
  timestamps: false,
  createdAt: 'created_at',
  updatedAt: false,
  validate: false // Disable validation to avoid schema conflicts
});

// Automatically create the table if it doesn't exist
sequelize.sync({ alter: true })
  .then(() => {
    console.log('EmailWallet model synced with database');
  })
  .catch(error => {
    console.error('Error syncing EmailWallet model:', error);
  });

console.log('EmailWallet model initialized');
console.log('EmailWallet model table name:', EmailWallet.getTableName());

module.exports = EmailWallet; 