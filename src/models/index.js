// Centralized model loader for new schema
const UserRole = require("./UserRole");
const User = require("./User");
const GiftCardCategory = require("./GiftCardCategory");
const GiftCard = require("./GiftCard");
const GiftCardSecret = require("./GiftCardSecret");
const ArtNft = require("./ArtNft");
const GiftCardArtNft = require("./GiftCardArtNft");
const GiftCardSettlement = require("./GiftCardSettlement");
const BlockchainTransactionCategory = require("./BlockchainTransactionCategory");
const BlockchainTransaction = require("./BlockchainTransaction");

module.exports = {
  UserRole,
  User,
  GiftCardCategory,
  GiftCard,
  GiftCardSecret,
  ArtNft,
  GiftCardArtNft,
  GiftCardSettlement,
  BlockchainTransactionCategory,
  BlockchainTransaction,
};
