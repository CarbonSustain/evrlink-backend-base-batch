const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");

const GiftCardCategory = sequelize.define(
  "gift_card_categories",
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "gift_card_categories",
    timestamps: true,
    created_at: "created_at",
    updated_at: "updated_at",
  }
);

module.exports = GiftCardCategory;
