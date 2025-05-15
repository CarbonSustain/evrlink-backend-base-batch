const { DataTypes } = require('sequelize');
const sequelize = require('../../db/db_config');

// Define the User model with absolute minimum fields
// Only include fields we know exist in the database
const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true, // This should use the database's SERIAL type
    field: 'id'
  },
  walletAddress: {
    type: DataTypes.STRING,
    field: 'wallet_address',
    allowNull: false,
    unique: true
  },
  email: {
    type: DataTypes.STRING,
    field: 'email',
    allowNull: true
  },
  // Only include created_at field since update_at seems to be missing
  createdAt: {
    type: DataTypes.DATE,
    field: 'created_at',
    defaultValue: sequelize.literal('CURRENT_TIMESTAMP')
  }
}, {
  tableName: 'users',
  timestamps: false, // Disable timestamps since updated_at doesn't exist
  createdAt: 'created_at',
  updatedAt: false, // Explicitly disable updatedAt
  validate: false // Disable validation to avoid schema conflicts
});

// Disable all model validation to avoid database schema conflicts
User.beforeValidate((user, options) => {
  // Skip validation completely
  return true;
});

// Log success
console.log('User model initialized with minimum fields (id, wallet_address, email, created_at)');
console.log('User model table name:', User.getTableName());

module.exports = User;