const { DataTypes } = require('sequelize');
const sequelize = require('../../db/db_config');
const Background = require('./Background');

const GiftCard = sequelize.define('GiftCard', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: false
  },
  creatorAddress: {
    type: DataTypes.STRING,
    field: 'creator_address',
    allowNull: false
  },
  currentOwner: {
    type: DataTypes.STRING,
    field: 'current_owner',
    allowNull: false
  },
  price: {
    type: DataTypes.DECIMAL(10, 4),
    allowNull: false
  },
  message: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  secretHash: {
    type: DataTypes.STRING,
    field: 'secret_hash',
    allowNull: true
  },
  backgroundId: {
    type: DataTypes.INTEGER,
    field: 'background_id',
    allowNull: false,
    references: {
      model: Background,
      key: 'id'
    }
  },
  isClaimable: {
    type: DataTypes.BOOLEAN,
    field: 'is_claimable',
    defaultValue: false
  },
  createdAt: {
    type: DataTypes.DATE,
    field: 'created_at',
    defaultValue: DataTypes.NOW
  },
  updatedAt: {
    type: DataTypes.DATE,
    field: 'updated_at',
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'gift_cards',
  timestamps: true,
  updatedAt: 'updated_at',
  createdAt: 'created_at'
});

GiftCard.belongsTo(Background, { foreignKey: 'background_id' });
Background.hasMany(GiftCard, { foreignKey: 'background_id' });

module.exports = GiftCard;