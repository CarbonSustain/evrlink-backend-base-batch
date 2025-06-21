const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");
const GiftCard = require("./GiftCard");
const ArtNft = require("./ArtNft");

const GiftCardArtNft = sequelize.define(
  "gift_card_art_nft",
  {
    gift_card_id: {
      type: DataTypes.INTEGER,
      field: "gift_card_id",
      references: { model: "gift_card", key: "id" },
      primaryKey: true,
    },
    art_nft_id: {
      type: DataTypes.INTEGER,
      field: "art_nft_id",
      references: { model: "art_nft", key: "id" },
      primaryKey: true,
    },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "gift_card_art_nft",
    timestamps: true,
    created_at: "created_at",
    updated_at: "updated_at",
  }
);

GiftCardArtNft.belongsTo(GiftCard, { foreignKey: "gift_card_id" });
GiftCardArtNft.belongsTo(ArtNft, { foreignKey: "art_nft_id" });
GiftCard.hasMany(GiftCardArtNft, { foreignKey: "gift_card_id" });
ArtNft.hasMany(GiftCardArtNft, { foreignKey: "art_nft_id" });

module.exports = GiftCardArtNft;
