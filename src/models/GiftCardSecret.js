const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");
const GiftCard = require("./GiftCard");

const GiftCardSecret = sequelize.define(
  "gift_card_secrets",
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    gift_card_id: {
      type: DataTypes.INTEGER,
      field: "gift_card_id",
      references: { model: "gift_card", key: "id" },
    },
    secret_hash: { type: DataTypes.STRING, unique: true, field: "secret_hash" },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "gift_card_secrets",
    timestamps: true,
    created_at: "created_at",
    updated_at: "updated_at",
  }
);

GiftCardSecret.belongsTo(GiftCard, { foreignKey: "gift_card_id" });

module.exports = GiftCardSecret;
