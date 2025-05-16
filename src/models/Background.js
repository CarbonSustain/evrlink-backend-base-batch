const { DataTypes } = require('sequelize');
const sequelize = require('../../db/db_config');
const User = require('./User.js');

const Background = sequelize.define('Background', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  blockchainId: {
    type: DataTypes.STRING,
    field: 'blockchain_id',
    allowNull: true
  },
  blockchainTxHash: {
    type: DataTypes.STRING,
    field: 'blockchain_tx_hash',
    allowNull: true
  },
  artistAddress: {
    type: DataTypes.STRING,
    field: 'artist_address',
    allowNull: true,
    references: {
      model: User,
      key: 'wallet_address'
    }
  },
  imageURI: {
    type: DataTypes.TEXT,
    field: 'image_uri',
    allowNull: false
  },
  usageCount: {
    type: DataTypes.INTEGER,
    field: 'usage_count',
    defaultValue: 0
  },
  category: {
    type: DataTypes.STRING,
    field: 'category',
    allowNull: true
  },
  price: {
    type: DataTypes.STRING,
    field: 'price',
    allowNull: true
  },
  createdAt: {
    type: DataTypes.DATE,
    field: 'created_at'
  },
  updatedAt: {
    type: DataTypes.DATE,
    field: 'updated_at'
  }
}, {
  tableName: 'backgrounds',
  timestamps: true,
  underscored: true
});

module.exports = Background;