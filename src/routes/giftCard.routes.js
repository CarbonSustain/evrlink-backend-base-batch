const express = require("express");
const router = express.Router();
const GiftCard = require("../models/GiftCard");
const Background = require("../models/ArtNft");
const GiftCardSecret = require("../models/GiftCardSecret");
const GiftCardArtNft = require("../models/GiftCardArtNft");
const BlockchainTransaction = require("../models/BlockchainTransaction");
const BlockchainTransactionCategory = require("../models/BlockchainTransactionCategory");
const EvrlinkConstant = require("../models/EvrlinkConstant");
const BlockchainTransactionGiftCard = require("../models/BlockchaintransactionGiftcard");
const { verifyToken } = require("../middleware/auth");
const { hashSecret, verifySecret } = require("../utils/crypto");
const rateLimit = require("express-rate-limit");
const { ethers } = require("ethers");
const { BLOCKCHAIN_ENABLED } = require("../config");
const { Op } = require("sequelize");
const { GiftCardSettlement } = require("../models");
const { User } = require("../models");
const { set } = require("zod");
const axios = require("axios"); // (keep if used elsewhere)
// const Coinbase = require("coinbase").Client; // Add this line

// Rate limiting middleware
const createLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
});

// Input validation middleware
const validateGiftCardInput = (req, res, next) => {
  const {
    backgroundIds,
    message,
    giftCardId,
    recipientAddress,
    paymentMethod,
    artNftPricesUSDC,
    transferMethod, // new field
  } = req.body;
  const errors = {};

  if (req.path === "/create") {
    if (!Array.isArray(backgroundIds) || backgroundIds.length === 0) {
      errors.backgroundIds = "backgroundIds (array) is required";
    }
    if (!paymentMethod || !["eth", "usdc"].includes(paymentMethod)) {
      errors.paymentMethod = "paymentMethod must be 'eth' or 'usdc'";
    }
    if (paymentMethod === "usdc" || paymentMethod === "eth") {
      if (
        !Array.isArray(artNftPricesUSDC) ||
        artNftPricesUSDC.length !== backgroundIds.length ||
        artNftPricesUSDC.some((v) => isNaN(Number(v)) || Number(v) <= 0)
      ) {
        errors.artNftPricesUSDC =
          "artNftPricesUSDC (array of positive numbers, same length as backgroundIds) is required";
      }
    }
    // Optionally validate transferMethod if present
    if (
      transferMethod &&
      !["setSecretKey", "transfer", "transferByBaseUsername"].includes(
        transferMethod
      )
    ) {
      errors.transferMethod = "Invalid transferMethod";
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
    let {
      backgroundIds,
      message,
      secret,
      recipientAddress,
      paymentMethod,
      artNftPricesUSDC,
      transferMethod, // new field
      baseUsername, // for transferByBaseUsername
    } = req.body;

    // Only accept the relevant field(s) based on transferMethod
    if (transferMethod === "setSecretKey") {
      recipientAddress = undefined;
      baseUsername = undefined;
    } else if (transferMethod === "transfer") {
      secret = undefined;
      baseUsername = undefined;
    } else if (transferMethod === "transferByBaseUsername") {
      secret = undefined;
      recipientAddress = undefined;
    } else {
      // If no transferMethod, allow all fields (legacy/fallback)
      // Optionally, you could clear all but the first present
    }

    const sequelize = GiftCard.sequelize;
    const transaction = await sequelize.transaction();

    try {
      console.log("Creating gift card with data:", {
        backgroundIds,
        message,
        userWalletAddress: req.user.walletAddress,
      });

      if (!req.user.walletAddress) {
        throw new Error(
          "User wallet address is required but not found in token"
        );
      }

      // Check if backgrounds exist - within transaction
      const backgrounds = await Background.findAll({
        where: {
          id: backgroundIds,
        },
        transaction,
      });
      if (!backgrounds || backgrounds.length === 0) {
        await transaction.rollback();
        console.error(`No backgrounds found with IDs: ${backgroundIds}`);
        return res.status(404).json({
          success: false,
          error: "No backgrounds found",
        });
      }

      console.log(
        "Found backgrounds:",
        backgrounds.map((b) => b.id)
      );

      // Fetch rates from evrlink_constants table (use latest row)
      const constants = await EvrlinkConstant.findOne({
        order: [["created_at", "DESC"]],
        transaction,
      });
      const taxRate = constants?.tax_rate;
      const platformFee = constants?.evrlink_platform_fee;
      const climateRate = constants?.climate_rate;
      console.log("artNftPricesUSDC:", artNftPricesUSDC); // Calculate USDC fees
      // artNftPricesUSDC = artNftPricesUSDC * 1e6; // Convert to smallest unit (6 decimals)
      // Convert all artNftPricesUSDC to smallest unit (6 decimals) if not already
      const artNftPricesUSDCInSmallest = Array.isArray(artNftPricesUSDC)
        ? artNftPricesUSDC.map((v) => BigInt(Math.floor(Number(v) * 1e6)))
        : [];
      const backgroundTotalPriceUSDC =
        artNftPricesUSDCInSmallest.length > 0
          ? artNftPricesUSDCInSmallest.reduce((acc, v) => acc + v, BigInt(0))
          : BigInt(0);
      const platformFeeUSDC = BigInt(Math.round(platformFee * 1e6));
      const taxFeeUSDC =
        (BigInt(Math.floor(Number(taxRate) * 1e6)) * backgroundTotalPriceUSDC) /
        BigInt(1e6);
      const climateFeeUSDC =
        (BigInt(Math.floor(Number(climateRate) * 1e6)) *
          backgroundTotalPriceUSDC) /
        BigInt(1e6);
      console.log(
        "Background total price (USDC):",
        backgroundTotalPriceUSDC.toString()
      );

      const totalPriceUSDC =
        backgroundTotalPriceUSDC +
        taxFeeUSDC +
        climateFeeUSDC +
        platformFeeUSDC;
      console.log("Platform fee (USDC):", platformFeeUSDC.toString());
      console.log("Tax fee (USDC):", taxFeeUSDC.toString());
      console.log("Climate fee (USDC):", climateFeeUSDC.toString());
      let transactionHash = null;
      let blockchainError = null;
      let receipt = null;

      // Helper to convert USDC (6 decimals) to ETH (wei) using Coinbase SDK
      // async function usdcToEth(usdcAmount) {
      //   // usdcAmount: string or BigInt, in USDC smallest unit (6 decimals)
      //   const usdcDecimals = 6;
      //   const ethDecimals = 18;
      //   const client = new Coinbase({
      //     apiKey: process.env.COIN_BASE_API_KEY,
      //     apiSecret: process.env.COIN_BASE_API_SECRET,
      //   });

      //   // Get ETH-USD spot price from Coinbase
      //   const ethSpot = await new Promise((resolve, reject) => {
      //     client.getSpotPrice(
      //       { currencyPair: "ETH-USD" },
      //       function (err, price) {
      //         if (err) return reject(err);
      //         resolve(price);
      //       }
      //     );
      //   });

      //   const ethPriceUSD = parseFloat(ethSpot.amount); // ETH price in USD

      //   // 1 USDC = 1 USD, so usdcAmount in USD:
      //   const amountUSD = Number(usdcAmount) / 10 ** usdcDecimals;
      //   // Convert USD to ETH
      //   const amountETH = amountUSD / ethPriceUSD;
      //   // Convert to wei
      //   return BigInt(Math.floor(amountETH * 10 ** ethDecimals)).toString();
      // }

      // Handle blockchain transaction if enabled
      if (BLOCKCHAIN_ENABLED && req.app.contract) {
        try {
          console.log("Creating gift card on blockchain...");
          if (paymentMethod === "usdc") {
            // USDC: check allowance before calling createGiftCardWithUSDC
            const usdcAddress = process.env.USDC_TOKEN_ADDRESS;
            const usdcAbi = [
              "function allowance(address owner, address spender) view returns (uint256)",
              "function approve(address spender, uint256 amount) returns (bool)",
              "function balanceOf(address account) view returns (uint256)",
            ];
            const userAddress = req.user.walletAddress;
            console.log("User address:", userAddress);
            const contractAddress = await req.app.contract.getAddress();
            console.log("Contract address:", contractAddress);
            const usdc = new ethers.Contract(
              usdcAddress,
              usdcAbi,
              req.app.wallet.provider
            );
            console.log("USDC contract initialized:", usdcAddress);
            const totalUSDC =
              backgroundTotalPriceUSDC +
              taxFeeUSDC +
              climateFeeUSDC +
              platformFeeUSDC;
            console.log("Total USDC:", totalUSDC.toString());
            const allowance = await usdc.allowance(
              userAddress,
              contractAddress
            );
            console.log("USDC allowance:", allowance.toString());
            // Fix: Show allowance in human-readable USDC (6 decimals)
            if (BigInt(allowance) < BigInt(totalUSDC)) {
              return res.status(400).json({
                success: false,
                error: `Insufficient USDC allowance. Your wallet allowance for the contract is ${(
                  Number(allowance) / 1e6
                ).toFixed(6)} USDC, but ${(Number(totalUSDC) / 1e6).toFixed(
                  6
                )} USDC is required. Please approve at least this amount for the contract before creating a gift card.`,
                details: {
                  required: (Number(totalUSDC) / 1e6).toFixed(6),
                  currentAllowance: (Number(allowance) / 1e6).toFixed(6),
                },
              });
            }
            // USDC: call createGiftCardWithUSDC
            const tx = await req.app.contract.createGiftCardWithUSDC(
              backgroundIds,
              message || "",
              backgroundTotalPriceUSDC.toString(),
              taxFeeUSDC.toString(),
              climateFeeUSDC.toString(),
              platformFeeUSDC.toString()
            );
            receipt = await tx.wait();
            transactionHash = receipt.transactionHash || tx.hash;
            console.log(
              "Blockchain transaction (USDC) successful:",
              transactionHash
            );
          } else {
            // ETH: convert all USDC values to wei directly using the rate 1 USDC = 4e14 wei
            function usdcToWei(usdcAmount) {
              // usdcAmount is in USDC smallest unit (6 decimals)
              return (BigInt(usdcAmount) * BigInt(4e14)) / BigInt(1e6);
            }
            const artNftPricesETH = artNftPricesUSDC.map((price) =>
              usdcToWei(BigInt(Math.floor(Number(price) * 1e6)))
            );
            const backgroundTotalPriceWei = usdcToWei(backgroundTotalPriceUSDC);
            const taxFeeWei = usdcToWei(taxFeeUSDC);
            const climateFeeWei = usdcToWei(climateFeeUSDC);
            const platformFeeWei = usdcToWei(platformFeeUSDC);

            const totalRequired =
              backgroundTotalPriceWei +
              taxFeeWei +
              climateFeeWei +
              platformFeeWei;

            console.log(
              "Background total price (wei):",
              backgroundTotalPriceWei
            );
            console.log("Tax fee (wei):", taxFeeWei);
            console.log("Climate fee (wei):", climateFeeWei);
            console.log("Platform fee (wei):", platformFeeWei);
            console.log("Total required (wei):", totalRequired);
            console.log("backgroundIds", backgroundIds);
            console.log(
              "artNftPricesETH",
              artNftPricesETH.map((p) => p.toString())
            );

            const tx = await req.app.contract.createGiftCardWithETH(
              backgroundIds,
              artNftPricesETH,
              message || "",
              backgroundTotalPriceWei,
              taxFeeWei,
              climateFeeWei,
              platformFeeWei,
              {
                value: totalRequired, // send total in wei
              }
            );
            receipt = await tx.wait();
            transactionHash = receipt.transactionHash || tx.hash;
            console.log(
              "Blockchain transaction (ETH) successful:",
              transactionHash
            );
          }
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
          creator_address: req.user.walletAddress,
          issuer_address: req.user.walletAddress,
          price: Number(totalPriceUSDC) / 1e6, // Only store price for ETH
          message: message || "",
          gift_card_category_id: backgrounds[0].gift_card_category_id || null,
          created_at: new Date(),
          updated_at: new Date(),
        },
        { transaction }
      );
      await GiftCardArtNft.create(
        {
          gift_card_id: giftCard.id,
          art_nft_id: backgrounds[0].id,
          created_at: new Date(),
          updated_at: new Date(),
        },
        { transaction }
      );
      await GiftCardSettlement.create(
        {
          gift_card_id: giftCard.id,
          from_addr: req.user.walletAddress,
          to_addr: recipientAddress || null,
          evrlink_fee: Number(platformFeeUSDC) / 1e6, // Only store fee for ETH, not wei, or it will overflow bigintplatformFeeUSDC,
          tax_fee: Number(taxFeeUSDC) / 1e6,
          // climate_fee: parseFloat(climateFeeWei.toString()),
          created_at: new Date(),
          updated_at: new Date(),
        },
        { transaction }
      );

      // --- BlockchainTransaction for MINT_GIFT_CARD ---
      const createTxCategory = await BlockchainTransactionCategory.findOne({
        where: { name: "MINT_GIFT_CARD" },
        transaction,
      });
      if (!createTxCategory) {
        throw new Error(
          "BlockchainTransactionCategory 'MINT_GIFT_CARD' not found. Please check your database seed."
        );
      }

      const giftcardse = await GiftCardSettlement.findOne({
        where: { gift_card_id: giftCard.id },
        transaction,
      });
      if (!giftcardse) {
        throw new Error(
          "GiftCardSettlement not found for created gift card. Please check your database seed."
        );
      }
      await BlockchainTransaction.create(
        {
          tx_hash: transactionHash,
          blockchain_tx_id: createTxCategory.id,
          from_addr: req.user.walletAddress,
          to_addr: null,
          gift_card_settlement_id: giftcardse.id,
          gas_fee:
            receipt &&
            receipt.gasUsed !== undefined &&
            (receipt.effectiveGasPrice !== undefined ||
              receipt.gasPrice !== undefined)
              ? parseFloat(
                  ethers.formatEther(
                    receipt.gasUsed *
                      (receipt.effectiveGasPrice !== undefined
                        ? receipt.effectiveGasPrice
                        : receipt.gasPrice)
                  )
                )
              : 0,
          tx_timestamp: new Date(),
          created_at: new Date(),
          updated_at: new Date(),
        },
        { transaction }
      );

      const bt_id = await BlockchainTransaction.findOne({
        where: { tx_hash: transactionHash },
        transaction,
      });
      const g_id = await GiftCardSettlement.findOne({
        where: { gift_card_id: giftCard.id },
        transaction,
      });

      await BlockchainTransactionGiftCard.create(
        {
          blockchain_transaction_id: bt_id.id,
          gift_card_settlement_id: g_id.id,
          created_at: new Date(),
          updated_at: new Date(),
        },
        { transaction }
      );

      // Workflow: If secret is provided, set secret key on-chain and update DB
      if (secret) {
        // Save secret hash in DB
        const secretHash = hashSecret(secret);
        await GiftCardSecret.create(
          {
            gift_card_id: giftCard.id,
            secret_hash: secretHash,
            created_at: new Date(),
            updated_at: new Date(),
          },
          { transaction }
        );
        // Record blockchain transaction for setting secret
        let txCategory = await BlockchainTransactionCategory.findOne({
          where: { name: "SET_GIFT_CARD_SECRET" },
        });
        if (!txCategory) {
          txCategory = await BlockchainTransactionCategory.create(
            { name: "SET_GIFT_CARD_SECRET" },
            { transaction }
          );
        }
        // await BlockchainTransaction.create(
        //   {
        //     tx_hash: tx,
        //     blockchain_tx_Id: txCategory.id,
        //     from_addr: req.user.walletAddress,
        //     to_addr: null,
        //     amount: 0,
        //     tx_timestamp: new Date(),
        //     created_at: new Date(),
        //     updated_at: new Date(),
        //   },
        //   { transaction }
        // );

        // Set secret key on-chain (call set-secret API internally)
        try {
          req.params.id = giftCard.id;
          req.body.secret = secret;
          await router.handle(req, res, () => {});
          return;
        } catch (err) {
          console.error(
            "Error calling set-secret API after gift card creation:",
            err
          );
        }
      }

      // Workflow: If recipientAddress is provided (direct transfer), transfer after creation
      if (!secret && recipientAddress) {
        try {
          req.body.giftCardId = giftCard.id;
          req.body.recipientAddress = recipientAddress;
          await router.handle(
            {
              ...req,
              method: "POST",
              url: "/transfer",
              body: { giftCardId: giftCard.id, recipientAddress },
              user: req.user,
              app: req.app,
            },
            res,
            () => {}
          );
          return;
        } catch (err) {
          console.error(
            "Error calling transfer API after gift card creation:",
            err
          );
        }
      }

      // If we get here, commit the transaction
      await transaction.commit();

      console.log("Gift card created successfully:", giftCard.id);

      // --- Workflow branching based on transferMethod ---
      // Remove callInternalApi and use direct router.handle as above

      if (transferMethod === "setSecretKey" && secret) {
        try {
          req.params.id = giftCard.id;
          req.body.secret = secret;
          await router.handle(req, res, () => {});
          return;
        } catch (err) {
          console.error(
            "Error calling set-secret API after gift card creation:",
            err
          );
        }
      } else if (transferMethod === "transfer" && recipientAddress) {
        try {
          await router.handle(
            {
              ...req,
              method: "POST",
              url: "/transfer",
              body: { giftCardId: giftCard.id, recipientAddress },
              user: req.user,
              app: req.app,
            },
            res,
            () => {}
          );
          return;
        } catch (err) {
          console.error(
            "Error calling transfer API after gift card creation:",
            err
          );
        }
      } else if (transferMethod === "transferByBaseUsername" && baseUsername) {
        try {
          await router.handle(
            {
              ...req,
              method: "POST",
              url: "/transfer-by-baseusername",
              body: { giftCardId: giftCard.id, baseUsername },
              user: req.user,
              app: req.app,
            },
            res,
            () => {}
          );
          return;
        } catch (err) {
          console.error(
            "Error calling transfer-by-baseusername API after gift card creation:",
            err
          );
        }
      }

      // Fallback to legacy logic if no transferMethod or not matched
      // If both secret and recipientAddress are provided, set secret then transfer
      if (secret && recipientAddress) {
        try {
          req.params.id = giftCard.id;
          req.body.secret = secret;
          await router.handle(req, res, () => {});
        } catch (err) {
          console.error(
            "Error calling set-secret API after gift card creation:",
            err
          );
        }
        try {
          await router.handle(
            {
              ...req,
              method: "POST",
              url: "/transfer",
              body: { giftCardId: giftCard.id, recipientAddress },
              user: req.user,
              app: req.app,
            },
            res,
            () => {}
          );
        } catch (err) {
          console.error(
            "Error calling transfer API after gift card creation:",
            err
          );
        }
        return;
      }
      // If only secret is provided, set secret
      if (secret) {
        try {
          req.params.id = giftCard.id;
          req.body.secret = secret;
          await router.handle(req, res, () => {});
          return;
        } catch (err) {
          console.error(
            "Error calling set-secret API after gift card creation:",
            err
          );
        }
      }
      // If only recipientAddress is provided, transfer
      if (recipientAddress) {
        try {
          await router.handle(
            {
              ...req,
              method: "POST",
              url: "/transfer",
              body: { giftCardId: giftCard.id, recipientAddress },
              user: req.user,
              app: req.app,
            },
            res,
            () => {}
          );
          return;
        } catch (err) {
          console.error(
            "Error calling transfer API after gift card creation:",
            err
          );
        }
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

      // Allow transfer if the user is either the creator or the issuer/current owner
      if (
        giftCard.creator_address !== req.user.walletAddress &&
        giftCard.issuer_address !== req.user.walletAddress
      ) {
        return res
          .status(403)
          .json({ error: "Not authorized to transfer this gift card" });
      }

      let transactionHash = null;
      let receipt = null;

      // --- On-chain owner check before transfer ---
      if (BLOCKCHAIN_ENABLED && req.app.contract) {
        try {
          const onChainGiftCard = await req.app.contract.giftCards(giftCardId);
          const onChainOwner =
            onChainGiftCard.currentOwner ||
            onChainGiftCard.current_owner ||
            onChainGiftCard.owner;
          // Compare on-chain owner with DB owner (issuer_address)
          if (
            !onChainOwner ||
            onChainOwner.toLowerCase() !== giftCard.issuer_address.toLowerCase()
          ) {
            return res.status(400).json({
              error:
                "Blockchain error: Only the on-chain owner can transfer this gift card. The DB owner does not match the on-chain owner.",
              details: {
                onChainOwner,
                dbOwner: giftCard.issuer_address,
              },
            });
          }
        } catch (err) {
          return res.status(500).json({
            error: "Failed to fetch on-chain gift card owner.",
            details: err.message,
          });
        }
      }

      // Handle blockchain transaction if enabled
      if (BLOCKCHAIN_ENABLED) {
        try {
          const tx = await req.app.contract.transferGiftCard(
            giftCardId,
            recipientAddress
          );
          receipt = await tx.wait();
          transactionHash = receipt.transactionHash || tx.hash;
        } catch (blockchainError) {
          // Improved error for "Only owner can transfer"
          if (
            blockchainError.reason &&
            blockchainError.reason.includes("Only owner can transfer")
          ) {
            return res.status(400).json({
              error:
                "Blockchain error: Only the on-chain owner can transfer this gift card. Please ensure the backend wallet is the current on-chain owner.",
              details: blockchainError.reason,
            });
          }
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
        issuer_address: recipientAddress, // update issuer_address to new owner
        updated_at: new Date(),
      });

      // Update settlement to_addr and updated_at
      await GiftCardSettlement.update(
        { to_addr: recipientAddress, updated_at: new Date() },
        { where: { gift_card_id: giftCard.id } }
      );

      // Record blockchain transaction for transfer
      const txCategory = await BlockchainTransactionCategory.findOne({
        where: { name: "TRANSFER_GIFT_CARD" },
      });
      if (!txCategory) {
        throw new Error(
          "BlockchainTransactionCategory 'TRANSFER_GIFT_CARD' not found. Please check your database seed."
        );
      }

      const giftcardse = await GiftCardSettlement.findOne({
        where: { gift_card_id: giftCard.id },
      });
      if (!giftcardse) {
        throw new Error(
          "GiftCardSettlement not found for transferred gift card. Please check your database seed."
        );
      }
      // Create blockchain transaction record
      await BlockchainTransaction.create({
        tx_hash: transactionHash,
        blockchain_tx_id: txCategory.id,
        from_addr: req.user.walletAddress,
        to_addr: recipientAddress,
        gift_card_settlement_id: giftcardse.id,
        gas_fee:
          receipt &&
          receipt.gasUsed !== undefined &&
          (receipt.effectiveGasPrice !== undefined ||
            receipt.gasPrice !== undefined)
            ? parseFloat(
                ethers.formatEther(
                  receipt.gasUsed *
                    (receipt.effectiveGasPrice !== undefined
                      ? receipt.effectiveGasPrice
                      : receipt.gasPrice)
                )
              )
            : 0,
        tx_timestamp: new Date(),
        created_at: new Date(),
        updated_at: new Date(),
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

    // Allow setting secret if the user is either the creator or the current owner
    if (
      giftCard.creator_address !== req.user.walletAddress &&
      giftCard.issuer_address !== req.user.walletAddress
    ) {
      return res.status(403).json({
        success: false,
        error:
          "Unauthorized - only the owner or creator can set the secret key",
      });
    }

    // --- Set secret on-chain ---
    let blockchainError = null;
    let transactionHash = null;
    let receipt = null;
    if (BLOCKCHAIN_ENABLED && req.app.contract) {
      try {
        const tx = await req.app.contract.setSecretKey(giftCardId, secret);
        receipt = await tx.wait();
        transactionHash = receipt.transactionHash || tx.hash;
        console.log("🔍 Set secret on-chain receipt:", receipt);
      } catch (error) {
        blockchainError = error;
        console.error("Blockchain set-secret error:", error);
        return res.status(500).json({
          success: false,
          error: "Failed to set secret on-chain: " + (error.message || error),
        });
      }
    }

    // Hash the secret for database storage
    const secretHash = hashSecret(secret);

    // Update database
    giftCard.secretHash = secretHash;
    await GiftCardSecret.create({
      gift_card_id: giftCard.id,
      secret_hash: secretHash,
      created_at: new Date(),
      updated_at: new Date(),
    });
    await giftCard.save();

    // Update settlement updated_at to now (secret set)
    await GiftCardSettlement.update(
      { updated_at: new Date() },
      { where: { gift_card_id: giftCard.id } }
    );

    // Record blockchain transaction for set-secret
    const setSecretTxCategory = await BlockchainTransactionCategory.findOne({
      where: { name: "SET_GIFT_CARD_SECRET" },
    });
    if (!setSecretTxCategory) {
      throw new Error(
        "BlockchainTransactionCategory 'SET_GIFT_CARD_SECRET' not found. Please check your database seed."
      );
    }

    const giftcardse = await GiftCardSettlement.findOne({
      where: { gift_card_id: giftCard.id },
    });
    if (!giftcardse) {
      throw new Error(
        "GiftCardSettlement not found for transferred gift card. Please check your database seed."
      );
    }

    await BlockchainTransaction.create({
      tx_hash: transactionHash,
      blockchain_tx_id: setSecretTxCategory.id,
      from_addr: req.user.walletAddress,
      to_addr: null,
      gift_card_settlement_id: giftcardse.id,
      gas_fee:
        receipt &&
        receipt.gasUsed !== undefined &&
        (receipt.effectiveGasPrice !== undefined ||
          receipt.gasPrice !== undefined)
          ? parseFloat(
              ethers.formatEther(
                receipt.gasUsed *
                  (receipt.effectiveGasPrice !== undefined
                    ? receipt.effectiveGasPrice
                    : receipt.gasPrice)
              )
            )
          : 0,
      tx_timestamp: new Date(),
      created_at: new Date(),
      updated_at: new Date(),
    });

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
    await GiftCardSecret.create({
      gift_card_id: giftCard.id,
      secret_hash: secretHash,
      created_at: new Date(),
      updated_at: new Date(),
    });

    await giftCard.save();

    // No blockchain transaction for legacy route

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
    console.log("Claiming gift card with data:", req.body);
    const { giftCardId, secret, claimerAddress } = req.body;

    // Check if gift card exists
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (!giftCard) {
      return res.status(404).json({
        success: false,
        error: "Gift card not found",
      });
    }

    // Blockchain claim
    let transactionHash = null;
    let blockchainError = null;
    let receipt = null;
    if (BLOCKCHAIN_ENABLED && req.app.contract) {
      try {
        const tx = await req.app.contract.claimGiftCard(giftCardId, secret);
        receipt = await tx.wait();
        console.log("🔍 Blockchain Transaction Receipt:", receipt);
        transactionHash = receipt.transactionHash;
      } catch (error) {
        blockchainError = error;
      }
    }

    // Update database records

    // Update settlement to_addr and updated_at
    await GiftCardSettlement.update(
      { to_addr: claimerAddress, updated_at: new Date() },
      { where: { gift_card_id: giftCard.id } }
    );

    // Record blockchain transaction
    const claimTxCategory = await BlockchainTransactionCategory.findOne({
      where: { name: "CLAIM_GIFT_CARD" },
    });
    if (!claimTxCategory) {
      throw new Error(
        "BlockchainTransactionCategory 'CLAIM_GIFT_CARD' not found. Please check your database seed."
      );
    }
    const giftcardse = await GiftCardSettlement.findOne({
      where: { gift_card_id: giftCard.id },
    });
    if (!giftcardse) {
      throw new Error(
        "GiftCardSettlement not found for transferred gift card. Please check your database seed."
      );
    }
    console.log(
      "Creating blockchain transaction for claim...",
      giftCard.issuer_address,
      claimerAddress
    );
    await BlockchainTransaction.create({
      tx_hash: transactionHash,
      blockchain_tx_id: claimTxCategory.id,
      from_addr: giftCard.issuer_address,
      to_addr: req.user.walletAddress,
      gift_card_settlement_id: giftcardse.id,
      gas_fee:
        receipt &&
        receipt.gasUsed !== undefined &&
        (receipt.effectiveGasPrice !== undefined ||
          receipt.gasPrice !== undefined)
          ? parseFloat(
              ethers.formatEther(
                receipt.gasUsed *
                  (receipt.effectiveGasPrice !== undefined
                    ? receipt.effectiveGasPrice
                    : receipt.gasPrice)
              )
            )
          : 0,
      tx_timestamp: receipt ? new Date(receipt.timestamp * 1000) : new Date(),
      created_at: new Date(),
      updated_at: new Date(),
    });

    await GiftCard.update(
      {
        issuer_address: claimerAddress,
        updated_at: new Date(),
      },
      { where: { id: giftCard.id } }
    );

    // Ensure User exists for claimer

    let user = await User.findOne({
      where: { wallet_address: req.user.walletAddress },
    });
    if (!user) {
      await User.create({ wallet_address: req.user.walletAddress });
    }

    return res.json({
      success: true,
      data: {
        id: giftCard.id,
        currentOwner: giftCard.current_owner,
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

// Add Alchemy Mainnet provider for .cb.id resolution
const cbidProvider = new ethers.JsonRpcProvider(
  "https://eth-mainnet.g.alchemy.com/v2/RmUuMM-w_jnGCiXht5C4thJN34MMDH5l"
);

// POST /resolve-cbid
router.post("/resolve-cbid", async (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Missing 'name' in request body" });
  }
  try {
    const address = await cbidProvider.resolveName(name); // e.g., "chandan.cb.id"
    if (address) {
      return res.json({ name, address });
    } else {
      return res
        .status(404)
        .json({ error: `${name} is not registered or not resolvable.` });
    }
  } catch (err) {
    console.error("Error resolving ENS name:", err);
    return res
      .status(500)
      .json({ error: "Error resolving ENS name", details: err.message });
  }
});

// Transfer gift card by base username
router.post("/transfer-by-baseusername", async (req, res) => {
  try {
    const { giftCardId, baseUsername } = req.body;
    if (!giftCardId || !baseUsername) {
      return res.status(400).json({
        success: false,
        error: "giftCardId and baseUsername are required.",
      });
    }

    // Resolve the base username to wallet address using the local /resolve-cbid endpoint
    let resolvedAddress;
    try {
      // Call the local resolve-cbid endpoint directly
      const cbidRes = await new Promise((resolve, reject) => {
        const mockReq = {
          ...req,
          method: "POST",
          url: "/resolve-cbid",
          body: { name: baseUsername },
        };
        const mockRes = {
          status: (code) => {
            mockRes.statusCode = code;
            return mockRes;
          },
          json: (data) => resolve(data),
          send: (data) => resolve(data),
          end: () => resolve(),
          setHeader: () => {},
        };
        router.handle(mockReq, mockRes, reject);
      });

      if (!cbidRes || !cbidRes.address) {
        return res.status(404).json({
          success: false,
          error: `Could not resolve wallet address for base username: ${baseUsername}`,
        });
      }
      resolvedAddress = cbidRes.address;
    } catch (err) {
      return res.status(500).json({
        success: false,
        error: "Failed to resolve base username",
        details: err.message,
      });
    }

    // Call the direct transfer API with the resolved address
    try {
      const transferRes = await new Promise((resolve, reject) => {
        const mockReq = {
          ...req,
          method: "POST",
          url: "/transfer",
          body: { giftCardId, recipientAddress: resolvedAddress },
        };
        const mockRes = {
          status: (code) => {
            mockRes.statusCode = code;
            return mockRes;
          },
          json: (data) => resolve(data),
          send: (data) => resolve(data),
          end: () => resolve(),
        };
        router.handle(mockReq, mockRes, reject);
      });
      return res.json(transferRes);
    } catch (err) {
      return res.status(500).json({
        success: false,
        error: "Failed to transfer gift card",
        details: err.message,
      });
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: "Unexpected error in transfer-by-baseusername",
      details: error.message,
    });
  }
});

//         // Create transaction with payment
//         const tx = await req.app.contract.buyGiftCard(giftCardId, {
//           value: price,
//         });
//         const receipt = await tx.wait();
//         console.log("🔍 Blockchain Transaction Receipt:", receipt);
//         transactionHash = receipt.transactionHash || tx.hash;
//         blockchainPurchased = true;
//       } catch (blockchainError) {
//         console.error("Blockchain error buying gift card:", blockchainError);
//         // Continue with database update even if blockchain fails
//         console.log("Continuing with database update despite blockchain error");
//       }
//     } else {
//       console.log(
//         "Blockchain functionality not available or not enabled, proceeding with database update only"
//       );
//       blockchainPurchased = true; // Allow database update to proceed
//     }

//     // Update database records
//     giftCard.currentOwner = req.user.walletAddress;
//     giftCard.message = message || giftCard.message;
//     giftCard.price = price || giftCard.price;
//     await giftCard.save();

//     return res.json({
//       success: true,
//       data: {
//         id: giftCard.id,
//         currentOwner: giftCard.currentOwner,
//         message: giftCard.message,
//         price: giftCard.price,
//         transactionHash,
//       },
//     });
//   } catch (error) {
//     console.error("Buy gift card error:", error);
//     res.status(500).json({
//       success: false,
//       error: "Failed to buy gift card",
//     });
//   }
// });
//   } catch (error) {
//     console.error("Buy gift card error:", error);
//     res.status(500).json({
//       success: false,
//       error: "Failed to buy gift card",
//     });
//   }
// });

module.exports = router;
