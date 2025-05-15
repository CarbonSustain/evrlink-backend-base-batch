const { DataTypes } = require('sequelize');
const sequelize = require('../../db/db_config');
const GiftCard = require('./GiftCard');
const User = require("./User");

const Transaction = sequelize.define('Transaction', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  giftCardId: {
    type: DataTypes.INTEGER,
    field: 'gift_card_id',
    allowNull: false,
    references: {
      model: GiftCard,
      key: 'id'
    }
  },
  fromAddress: {
    type: DataTypes.STRING,
    field: 'from_address',
    allowNull: false,
    references: {
      model: User,
      key: 'wallet_address'
    }
  },
  toAddress: {
    type: DataTypes.STRING,
    field: 'to_address',
    allowNull: false
  },
  transactionType: {
    type: DataTypes.STRING,
    field: 'transaction_type',
    allowNull: false
  },
  amount: {
    type: DataTypes.DECIMAL(10, 4),
    field: 'amount',
    allowNull: false
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
  tableName: 'transactions',
  timestamps: true,
  underscored: true
});

Transaction.belongsTo(GiftCard, { foreignKey: 'gift_card_id' });

module.exports = Transaction;