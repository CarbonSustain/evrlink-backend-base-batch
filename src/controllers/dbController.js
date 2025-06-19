const Background = require('../models/ArtNft');
const GiftCard = require('../models/GiftCard');
const Transaction = require('../models/Transaction');
const User = require('../models/User');
const GiftCardCategory = require('../models/GiftCardCategory'); // Add this import

// Function to create a new background
exports.createBackground = async (artistAddress, imageURI, categoryName) => {
  // Look up or create the category and use its ID as FK
  let category = await GiftCardCategory.findOne({ where: { name: categoryName } });
  if (!category) {
    category = await GiftCardCategory.create({ name: categoryName });
  }
  const background = await Background.create({
    artistAddress,
    imageUri: imageURI, // Use correct field name
    giftCardCategoryId: category.id // Use FK
  });
  return background.id;
};

// Function to get all backgrounds
exports.getAllBackgrounds = async () => {
  return await Background.findAll();
};

// Function to create a new gift card
exports.createGiftCard = async (creatorAddress, currentOwner, price, message, backgroundId) => {
  const giftCard = await GiftCard.create({
    creatorAddress,
    currentOwner,
    price,
    message,
    backgroundId
  });
  return giftCard.id;
};

// Function to get all gift cards
exports.getAllGiftCards = async () => {
  return await GiftCard.findAll();
};

// Function to create a new transaction
exports.createTransaction = async (giftCardId, fromAddress, toAddress, transactionType, amount) => {
  const transaction = await Transaction.create({
    giftCardId,
    fromAddress,
    toAddress,
    transactionType,
    amount
  });
  return transaction.id;
};

// Function to get all transactions
exports.getAllTransactions = async () => {
  return await Transaction.findAll();
};

// Function to create a new user
exports.createUser = async (walletAddress, username, email) => {
  const user = await User.create({
    walletAddress,
    username,
    email
  });
  return user.id;
};

// Function to get all users
exports.getAllUsers = async () => {
  return await User.findAll();
};