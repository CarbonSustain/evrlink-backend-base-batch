const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");
const GiftCard = require("./GiftCard");
const User = require("./User");

const GiftCardSettlement = sequelize.define(
  "gift_card_settlement",
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      references: {
        model: "blockchain_transactions_gift_card",
        key: "gift_card_settlement_id",
      },
    },
    gift_card_id: {
      type: DataTypes.INTEGER,
      field: "gift_card_id",
      unique: true,
      references: { model: "gift_card", key: "id" },
    },
    from_addr: {
      type: DataTypes.STRING,
      field: "from_addr",
      references: { model: "users", key: "wallet_address" },
    },
    to_addr: { type: DataTypes.STRING, field: "to_addr" },
    tax_fee: { type: DataTypes.FLOAT, field: "tax_fee" },
    evrlink_fee: { type: DataTypes.FLOAT, field: "evrlink_fee" },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "gift_card_settlement",
    timestamps: true,
    created_at: "created_at",
    updated_at: "updated_at",
  }
);

GiftCardSettlement.belongsTo(GiftCard, { foreignKey: "gift_card_id" });
GiftCardSettlement.belongsTo(User, {
  foreignKey: "from_addr",
  targetKey: "wallet_address",
  as: "fromUser",
});

module.exports = GiftCardSettlement;
