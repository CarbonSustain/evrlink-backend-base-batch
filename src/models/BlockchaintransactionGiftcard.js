const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");

const BlockchainTransactionGiftCard = sequelize.define(
  "BlockchainTransactionGiftCard",
  {
    blockchain_transaction_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: { model: "blockchain_transactions", key: "id" },
      primaryKey: true,
    },
    gift_card_settlement_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: { model: "gift_card_settlement", key: "id" },
      primaryKey: true,
    },
    created_at: { type: DataTypes.DATE },
    updated_at: { type: DataTypes.DATE },
  },
  {
    tableName: "blockchain_transaction_gift_card",
    timestamps: true,
    createdAt: "created_at",
    updatedAt: "updated_at",
    indexes: [
      {
        unique: true,
        fields: ["blockchain_transaction_id", "gift_card_settlement_id"],
      },
    ],
    id: false,
  }
);

module.exports = BlockchainTransactionGiftCard;
