const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");
const User = require("./User");
const GiftCardCategory = require("./GiftCardCategory");
const { blob } = require("stream/consumers");

const ArtNft = sequelize.define(
  "ArtNft",
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    artist_address: {
      type: DataTypes.STRING,
      field: "artist_address",
      references: { model: "users", key: "wallet_address" },
    },
    image_uri: { type: DataTypes.TEXT, unique: true, field: "image_uri" },
    price: { type: DataTypes.DECIMAL },
    gift_card_category_id: {
      type: DataTypes.INTEGER,
      field: "gift_card_category_id",
      references: { model: "gift_card_categories", key: "id" },
    },
    blockchain_transaction_id: {
      type: DataTypes.INTEGER,
      field: "blockchain_transaction_id",
      allowNull: true,
      unique: true,
      references: { model: "blockchain_transactions", key: "id" },
    },
    createdAt: { type: DataTypes.DATE, field: "created_at" },
    updatedAt: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "art_nft",
    timestamps: true,
    createdAt: "created_at",
    updatedAt: "updated_at",
  }
);

ArtNft.belongsTo(User, {
  foreignKey: "artist_address",
  targetKey: "wallet_address",
  as: "artist",
});
ArtNft.belongsTo(GiftCardCategory, {
  foreignKey: "gift_card_category_id",
  as: "category",
});

module.exports = ArtNft;
