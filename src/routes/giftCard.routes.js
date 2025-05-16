const express = require("express");
const router = express.Router();
const GiftCard = require("../models/GiftCard");
const Background = require("../models/Background");
const { verifyToken } = require("../middleware/auth");
const { hashSecret, verifySecret } = require("../utils/crypto");
const rateLimit = require("express-rate-limit");
const { ethers } = require("ethers");
const { BLOCKCHAIN_ENABLED } = require("../config");
const { Op } = require("sequelize");

// Rate limiting middleware
const createLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
});

// Input validation middleware
const validateGiftCardInput = (req, res, next) => {
  const { backgroundId, price, message, giftCardId, recipientAddress } =
    req.body;

  const errors = {};

  // For create route
  if (req.path === "/create") {
    if (!backgroundId) {
      errors.backgroundId = "Background ID is required";
    }

    if (!price) {
      errors.price = "Price is required";
    } else if (isNaN(parseFloat(price)) || parseFloat(price) <= 0) {
      errors.price = "Price must be a positive number";
    }
  }

  // For transfer route
  if (req.path === "/transfer") {
    if (!giftCardId) {
      errors.giftCardId = "Gift card ID is required";
    }

    if (!recipientAddress) {
      errors.recipientAddress = "Recipient address is required";
    } else if (!ethers.isAddress(recipientAddress)) {
      errors.recipientAddress = "Invalid Ethereum address format";
    }
  }

  if (Object.keys(errors).length > 0) {
    return res
      .status(400)
      .json({ error: "Validation failed", details: errors });
  }

  next();
};

// Create new gift card
router.post(
  "/create",
  verifyToken,
  createLimiter,
  validateGiftCardInput,
  async (req, res) => {
    const { backgroundId, price, message } = req.body;
    const sequelize = GiftCard.sequelize;

    // Start a transaction
    const transaction = await sequelize.transaction();

    try {
      console.log("Creating gift card with data:", {
        backgroundId,
        price,
        message,
        userWalletAddress: req.user.walletAddress,
      });

      if (!req.user.walletAddress) {
        throw new Error(
          "User wallet address is required but not found in token"
        );
      }

      // Check if background exists - within transaction
      const background = await Background.findByPk(backgroundId, {
        transaction,
      });
      if (!background) {
        await transaction.rollback();
        console.error(`Background not found with ID: ${backgroundId}`);
        return res.status(404).json({
          success: false,
          error: "Background not found",
        });
      }

      console.log("Found background:", background.id);

      let transactionHash = null;
      let blockchainError = null;

      // Handle blockchain transaction if enabled
      if (BLOCKCHAIN_ENABLED && req.app.contract) {
        try {
          console.log("Creating gift card on blockchain...");
          // Calculate total required ETH as per contract
          const backgroundPrice = ethers.parseEther(
            background.price.toString()
          );
          const PLATFORM_FEE_IN_WEI = BigInt("611111111111111");
          const taxFee = (backgroundPrice * 4n) / 100n;
          const climateFee = backgroundPrice / 100n;
          const totalRequired =
            backgroundPrice + PLATFORM_FEE_IN_WEI + taxFee + climateFee;

          const tx = await req.app.contract.createGiftCard(
            backgroundId,
            message || "",
            { value: totalRequired }
          );
          const receipt = await tx.wait();
          transactionHash = receipt.transactionHash || tx.hash;
          console.log("Blockchain transaction successful:", transactionHash);
        } catch (error) {
          // Enhanced error handling for blockchain failures
          let debugMsg = "Blockchain error: ";
          if (
            error.code === "INSUFFICIENT_FUNDS" ||
            (error.reason && error.reason.includes("insufficient funds"))
          ) {
            debugMsg +=
              "Insufficient ETH sent. Please ensure the totalRequired amount is sent.";
          } else if (
            error.code === "CALL_EXCEPTION" ||
            (error.reason && error.reason.includes("revert"))
          ) {
            debugMsg +=
              "Smart contract reverted. Check if backgroundId exists and all require() conditions are met.";
          } else if (
            error.code === "UNPREDICTABLE_GAS_LIMIT" ||
            (error.message && error.message.includes("out of gas"))
          ) {
            debugMsg +=
              "Transaction ran out of gas. Try increasing the gas limit.";
          } else if (
            error.code === "NETWORK_ERROR" ||
            (error.message && error.message.includes("network"))
          ) {
            debugMsg +=
              "Network/provider error. Check your RPC provider (e.g., Alchemy/Infura) and network status.";
          } else if (
            error.code === "INVALID_ARGUMENT" ||
            (error.message && error.message.includes("invalid argument"))
          ) {
            debugMsg +=
              "Invalid argument sent to contract. Check contract ABI and input types.";
          } else if (
            error.code === "NONCE_EXPIRED" ||
            (error.message && error.message.includes("nonce"))
          ) {
            debugMsg += "Nonce issue. Try resetting the backend wallet nonce.";
          } else if (
            error.code === "ACTION_REJECTED" ||
            (error.message && error.message.includes("rejected"))
          ) {
            debugMsg += "Transaction was rejected by the wallet or network.";
          } else if (
            error.code === "SERVER_ERROR" ||
            (error.message && error.message.includes("server error"))
          ) {
            debugMsg += "Server error from RPC provider.";
          } else if (
            error.message &&
            error.message.includes("event not found")
          ) {
            debugMsg +=
              "Event not found in transaction receipt. Check contract ABI and event emission.";
          } else if (error.message && error.message.includes("private key")) {
            debugMsg +=
              "Wallet/private key error. Check backend wallet configuration and funding.";
          } else {
            debugMsg += error.message || "Unknown blockchain error.";
          }
          console.error(debugMsg, error);
          blockchainError = new Error(debugMsg);
          // Continue with database creation even if blockchain fails
        }
      } else {
        console.log("Blockchain functionality is disabled or not available");
      }

      console.log("Creating gift card in database...");

      // Only proceed if blockchain did NOT fail
      if (blockchainError) {
        await transaction.rollback();
        console.error(
          "Blockchain transaction failed, rolling back DB transaction."
        );
        return res.status(500).json({
          success: false,
          error: "Blockchain operation failed, gift card was not created.",
        });
      }

      // Get the next available ID
      const lastGiftCard = await GiftCard.findOne({
        order: [["id", "DESC"]],
        transaction,
      });
      const nextId = lastGiftCard ? parseInt(lastGiftCard.id) + 1 : 1;

      // Create gift card with proper error handling - within transaction
      const giftCard = await GiftCard.create(
        {
          id: nextId,
          backgroundId,
          price: parseFloat(price), // Convert price to float
          message: message || "", // Handle optional message
          creatorAddress: req.user.walletAddress,
          currentOwner: req.user.walletAddress,
          transactionHash,
          isClaimable: false,
        },
        { transaction }
      );

      // If we get here, commit the transaction
      await transaction.commit();

      console.log("Gift card created successfully:", giftCard.id);

      // If there was a blockchain error but database succeeded, include warning
      if (blockchainError) {
        return res.status(201).json({
          success: true,
          data: giftCard.toJSON(),
          warning:
            "Gift card created in database but blockchain operation failed",
        });
      }

      res.status(201).json({
        success: true,
        data: giftCard.toJSON(),
      });
    } catch (error) {
      // Rollback transaction on error
      await transaction.rollback();

      console.error("Create gift card error:", error);
      console.error("Error stack:", error.stack);

      // Handle specific error cases
      if (error.message.includes("wallet address is required")) {
        return res.status(401).json({
          success: false,
          error: "Authentication error",
          details:
            "User wallet address is required. Please reconnect your wallet.",
        });
      }

      res.status(500).json({
        success: false,
        error: "Failed to create gift card",
        details:
          process.env.NODE_ENV === "development"
            ? {
                message: error.message,
                stack: error.stack,
              }
            : undefined,
      });
    }
  }
);

// Get all gift cards with filtering
router.get("/", async (req, res) => {
  try {
    const { priceRange, category, sortBy } = req.query;
    const where = {};

    if (priceRange) {
      const [min, max] = priceRange.split(",").map(Number);
      where.price = { [Op.between]: [min, max] };
    }

    if (category) {
      where.background = {
        category,
      };
    }

    const order =
      sortBy === "price" ? [["price", "ASC"]] : [["createdAt", "DESC"]];

    const giftCards = await GiftCard.findAll({
      where,
      include: [{ model: Background, as: "background" }],
      order,
    });

    res.json(giftCards);
  } catch (error) {
    console.error("Search gift cards error:", error);
    res.status(500).json({ error: "Failed to search gift cards" });
  }
});

// Transfer gift card
router.post(
  "/transfer",
  verifyToken,
  validateGiftCardInput,
  async (req, res) => {
    const { giftCardId, recipientAddress } = req.body;

    try {
      // Find gift card and check ownership
      const giftCard = await GiftCard.findByPk(giftCardId);
      if (!giftCard) {
        return res.status(404).json({ error: "Gift card not found" });
      }

      if (giftCard.creatorAddress !== req.user.walletAddress) {
        return res
          .status(403)
          .json({ error: "Not authorized to transfer this gift card" });
      }

      if (giftCard.currentOwner !== req.user.walletAddress) {
        return res
          .status(403)
          .json({ error: "Not authorized to transfer this gift card" });
      }

      let transactionHash = null;

      // Handle blockchain transaction if enabled
      if (BLOCKCHAIN_ENABLED) {
        try {
          const tx = await req.app.contract.transferGiftCard(
            giftCardId,
            recipientAddress
          );
          const receipt = await tx.wait();
          transactionHash = receipt.transactionHash || tx.hash;
        } catch (blockchainError) {
          console.error("Blockchain error:", blockchainError);
          return res.status(500).json({
            error: "Blockchain transaction failed",
            details:
              process.env.NODE_ENV === "development"
                ? blockchainError.message
                : undefined,
          });
        }
      }

      // Update gift card with proper error handling
      await giftCard.update({
        currentOwner: recipientAddress,
        transactionHash,
        transferredAt: new Date(),
      });

      res.json({
        success: true,
        data: giftCard.toJSON(),
      });
    } catch (error) {
      console.error("Transfer gift card error:", error);
      res.status(500).json({
        error: "Failed to transfer gift card",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      });
    }
  }
);

// Set secret key for gift card
router.post("/:id/set-secret", verifyToken, async (req, res) => {
  try {
    const giftCardId = req.params.id;
    const { secret } = req.body;

    // Check if gift card exists
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (!giftCard) {
      return res.status(404).json({
        success: false,
        error: "Gift card not found",
      });
    }

    if (giftCard.currentOwner !== req.user.walletAddress) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - only the owner can set the secret key",
      });
    }

    // Hash the secret for database storage
    const secretHash = hashSecret(secret);

    // Update database
    giftCard.secretHash = secretHash;
    giftCard.isClaimable = true;
    await giftCard.save();

    return res.json({
      success: true,
      data: {
        id: giftCard.id,
        isClaimable: giftCard.isClaimable,
      },
    });
  } catch (error) {
    console.error("Set gift card secret error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to set gift card secret",
    });
  }
});

// Legacy route for backward compatibility
router.post("/set-secret", verifyToken, async (req, res) => {
  try {
    const { giftCardId, secret } = req.body;

    // Check if gift card exists
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (!giftCard) {
      return res.status(404).json({
        success: false,
        error: "Gift card not found",
      });
    }

    if (giftCard.currentOwner !== req.user.walletAddress) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - only the owner can set the secret key",
      });
    }

    // Hash the secret for database storage
    const secretHash = hashSecret(secret);

    // Update database
    giftCard.secretHash = secretHash;
    giftCard.isClaimable = true;
    await giftCard.save();

    return res.json({
      success: true,
      data: {
        id: giftCard.id,
        isClaimable: giftCard.isClaimable,
      },
    });
  } catch (error) {
    console.error("Set gift card secret error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to set gift card secret",
    });
  }
});

// Claim gift card
router.post("/claim", verifyToken, async (req, res) => {
  try {
    const { giftCardId, secret } = req.body;

    // Check if gift card exists
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (!giftCard) {
      return res.status(404).json({
        success: false,
        error: "Gift card not found",
      });
    }
    if (!giftCard.isClaimable) {
      return res.status(400).json({
        success: false,
        error: "Gift card is not claimable",
      });
    }

    // Blockchain claim
    let transactionHash = null;
    let blockchainError = null;
    if (BLOCKCHAIN_ENABLED && req.app.contract) {
      try {
        const tx = await req.app.contract.claimGiftCard(giftCardId, secret);
        const receipt = await tx.wait();
        transactionHash = receipt.transactionHash;
      } catch (error) {
        blockchainError = error;
      }
    }

    // Update database records
    giftCard.currentOwner = req.user.walletAddress;
    giftCard.secretHash = null;
    giftCard.isClaimable = false;
    await giftCard.save();

    return res.json({
      success: true,
      data: {
        id: giftCard.id,
        currentOwner: giftCard.currentOwner,
        isClaimable: giftCard.isClaimable,
        transactionHash,
      },
      blockchainError: blockchainError ? blockchainError.message : undefined,
    });
  } catch (error) {
    console.error("Claim gift card error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to claim gift card",
    });
  }
});

// Buy gift card
router.post("/buy", verifyToken, async (req, res) => {
  try {
    const { giftCardId, message, price } = req.body;

    // Check if gift card exists
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (!giftCard) {
      return res.status(404).json({
        success: false,
        error: "Gift card not found",
      });
    }

    // Handle blockchain purchase if enabled
    let transactionHash = null;
    let blockchainPurchased = false;

    if (BLOCKCHAIN_ENABLED && req.app.contract) {
      console.log(
        `🔹 Buying gift card ${giftCardId} on blockchain for ${req.user.walletAddress}`
      );
      try {
        // Create transaction with payment
        const tx = await req.app.contract.buyGiftCard(giftCardId, {
          value: price,
        });
        const receipt = await tx.wait();
        console.log("🔍 Blockchain Transaction Receipt:", receipt);
        transactionHash = receipt.transactionHash || tx.hash;
        blockchainPurchased = true;
      } catch (blockchainError) {
        console.error("Blockchain error buying gift card:", blockchainError);
        // Continue with database update even if blockchain fails
        console.log("Continuing with database update despite blockchain error");
      }
    } else {
      console.log(
        "Blockchain functionality not available or not enabled, proceeding with database update only"
      );
      blockchainPurchased = true; // Allow database update to proceed
    }

    // Update database records
    giftCard.currentOwner = req.user.walletAddress;
    giftCard.message = message || giftCard.message;
    giftCard.price = price || giftCard.price;
    await giftCard.save();

    return res.json({
      success: true,
      data: {
        id: giftCard.id,
        currentOwner: giftCard.currentOwner,
        message: giftCard.message,
        price: giftCard.price,
        transactionHash,
      },
    });
  } catch (error) {
    console.error("Buy gift card error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to buy gift card",
    });
  }
});

module.exports = router;
