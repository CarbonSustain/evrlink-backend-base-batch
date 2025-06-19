const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");
const GiftCardCategory = require("./GiftCardCategory");
const User = require("./User");

const GiftCard = sequelize.define(
  "gift_cards",
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    creator_address: {
      type: DataTypes.STRING,
      field: "creator_address",
      references: { model: "users", key: "wallet_address" },
    },
    issuer_address: {
      type: DataTypes.STRING,
      field: "issuer_address",
      references: { model: "users", key: "wallet_address" },
    },
    price: { type: DataTypes.DECIMAL },
    message: { type: DataTypes.TEXT },
    gift_card_category_id: {
      type: DataTypes.INTEGER,
      field: "gift_card_category_id",
      references: { model: "gift_card_categories", key: "id" },
    },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "gift_cards",
    timestamps: true,
    created_at: "created_at",
    updated_at: "updated_at",
  }
);

GiftCard.belongsTo(GiftCardCategory, { foreignKey: "gift_card_category_id" });
GiftCard.belongsTo(User, {
  foreignKey: "creator_address",
  targetKey: "wallet_address",
  as: "creator",
});
GiftCard.belongsTo(User, {
  foreignKey: "issuer_address",
  targetKey: "wallet_address",
  as: "issuer",
});

module.exports = GiftCard;
