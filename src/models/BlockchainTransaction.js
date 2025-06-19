const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");
const GiftCardSettlement = require("./GiftCardSettlement");
const BlockchainTransactionCategory = require("./BlockchainTransactionCategory");
const User = require("./User");

const BlockchainTransaction = sequelize.define(
  "BlockchainTransaction",
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      references: {
        model: "blockchain_transactions_gift_card",
        key: "blockchain_transaction_id",
      },
    },
    tx_hash: { type: DataTypes.STRING, unique: true, field: "tx_hash" },

    blockchain_tx_id: {
      type: DataTypes.INTEGER,
      field: "blockchain_tx_id",
      references: { model: "blockchain_transaction_categories", key: "id" },
    },
    gas_fee: { type: DataTypes.INTEGER, field: "gas_fee" },
    from_addr: {
      type: DataTypes.STRING,
      field: "from_addr",
      references: { model: "users", key: "wallet_address" },
    },
    to_addr: { type: DataTypes.STRING, field: "to_addr" },
    tx_timestamp: { type: DataTypes.DATE, field: "tx_timestamp" },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "blockchain_transactions",
    timestamps: true,
    createdAt: "created_at",
    updatedAt: "updated_at",
  }
);

// BlockchainTransaction.belongsTo(GiftCardSettlement, {
//   foreignKey: "gift_card_settlement_id",
// });
BlockchainTransaction.belongsTo(BlockchainTransactionCategory, {
  foreignKey: "blockchain_tx_id",
});
BlockchainTransaction.belongsTo(User, {
  foreignKey: "from_addr",
  targetKey: "wallet_address",
  as: "fromUser",
});

module.exports = BlockchainTransaction;
