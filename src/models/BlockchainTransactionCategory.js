const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");

const BlockchainTransactionCategory = sequelize.define(
  "BlockchainTransactionCategory",
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING, unique: true },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "blockchain_transaction_categories",
    timestamps: true,
    createdAt: "created_at",
    updatedAt: "updated_at",
  }
);

module.exports = BlockchainTransactionCategory;
