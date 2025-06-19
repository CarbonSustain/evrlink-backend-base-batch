const express = require("express");
const router = express.Router();
const Background = require("../models/ArtNft.js");
const BlockchainTransaction = require("../models/BlockchainTransaction.js");
const { upload } = require("../middleware/multer");
const { verifyToken } = require("../middleware/auth");
const ethers = require("ethers");
const path = require("path");
const {
  updateBackgroundAfterMint,
  updateUserMintingStats,
} = require("../utils/blockchain-updates");
const { Op } = require("sequelize");
const fs = require("fs");
let blochaininfo;

// Helper function for ethers version compatibility
function parseLog(log, contract) {
  try {
    // For ethers v6
    if (log.fragment && log.fragment.name) {
      return {
        name: log.fragment.name,
        args: log.args,
      };
    }

    // For ethers v5
    if (contract && contract.interface) {
      const parsedLog = contract.interface.parseLog(log);
      if (parsedLog) {
        return {
          name: parsedLog.name,
          args: parsedLog.args,
        };
      }
    }

    return null;
  } catch (err) {
    console.error("Error parsing log:", err);
    return null;
  }
}

// Helper function to check if an image file exists
function imageExists(imageUrl) {
  if (!imageUrl) return false;

  let filename;
  try {
    // Extract filename from URL
    const url = new URL(imageUrl);
    filename = path.basename(url.pathname);
  } catch (err) {
    // If not a valid URL, try to extract the filename directly
    filename = path.basename(imageUrl);
  }

  // Check if the file exists in the uploads directory
  const filePath = path.join(__dirname, "../../uploads", filename);
  return fs.existsSync(filePath);
}

// Get all backgrounds with filtering
router.get("/", async (req, res) => {
  try {
    const { page = 1, limit = 10, category } = req.query;
    const offset = (page - 1) * limit;

    const where = {};
    if (category) {
      where.category = category;
    }

    const backgrounds = await Background.findAndCountAll({
      where,
      limit: parseInt(limit),
      offset: parseInt(offset),
      order: [["createdAt", "DESC"]],
    });

    res.json({
      backgrounds: backgrounds.rows,
      total: backgrounds.count,
      page: parseInt(page),
      totalPages: Math.ceil(backgrounds.count / limit),
    });
  } catch (error) {
    console.error("Get backgrounds error:", error);
    res.status(500).json({ error: "Failed to get backgrounds" });
  }
});

// Get popular backgrounds
router.get("/popular", async (req, res) => {
  try {
    const backgrounds = await Background.findAll({
      order: [["usageCount", "DESC"]],
      limit: 10,
    });
    res.json(backgrounds);
  } catch (error) {
    console.error("Get popular backgrounds error:", error);
    res.status(500).json({ error: "Failed to get popular backgrounds" });
  }
});

// Get all categories
router.get("/categories", async (req, res) => {
  try {
    const categories = await Background.findAll({
      attributes: ["category"],
      group: ["category"],
    });
    res.json(categories.map((cat) => cat.category));
  } catch (error) {
    console.error("Get categories error:", error);
    res.status(500).json({ error: "Failed to get categories" });
  }
});

// Get background by ID
router.get("/:id", async (req, res) => {
  try {
    const background = await Background.findByPk(req.params.id);
    if (!background) {
      return res.status(404).json({ error: "Background not found" });
    }

    // Check if the image file exists
    if (!imageExists(background.image_uri)) {
      console.log(
        `Warning: Image not found for background ID ${req.params.id}: ${background.image_uri}`
      );
      return res.status(404).json({
        error: "Background image not found",
        message: "The image file for this background does not exist",
      });
    }

    res.json(background);
  } catch (error) {
    console.error("Get background error:", error);
    res.status(500).json({ error: "Failed to get background" });
  }
});

// Create new background
router.post("/", verifyToken, upload.single("image"), async (req, res) => {
  try {
    const { category, price } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "Image file is required" });
    }

    // Generate URL based on server configuration
    const imageUrl = `https://${process.env.S3_BUCKET_NAME}.s3.us-west-2.amazonaws.com/${req.fileName}`;

    if (!category || !price) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Validate price as a positive number
    if (isNaN(price) || Number(price) <= 0) {
      return res.status(400).json({ error: "Price must be a positive number" });
    }

    // Use correct model for gift_card_categories
    const GiftCardCategory = require("../models/GiftCardCategory");
    let giftCardCategoryId = null;
    if (category) {
      let cat = await GiftCardCategory.findOne({
        where: { name: category },
      });
      if (!cat) {
        cat = await GiftCardCategory.create({ name: category });
      }
      giftCardCategoryId = cat.id;
    }

    // Create background with auto-incrementing ID
    // const background = await Background.create({
    //   artist_address: req.user
    //     ? req.user.wallet_address
    //     : req.body.artistAddress,
    //   image_uri: imageUrl,
    //   gift_card_category_id: giftCardCategoryId,
    //   price: price,
    // });

    res.status(201).json({
      id: background.id,
      artist_address: background.artist_address,
      image_uri: background.image_uri,
      gift_card_category_id: background.gift_card_category_id,
      price: background.price,
    });
  } catch (error) {
    console.error("Create background error:", error);
    res
      .status(500)
      .json({ error: "Failed to create background: " + error.message });
  }
});

// Mint background NFT
router.post("/mint", verifyToken, upload.single("image"), async (req, res) => {
  try {
    const { category, price } = req.body;
    const imageFile = req.file;

    if (!imageFile) {
      return res.status(400).json({ error: "Image file is required" });
    }

    // Generate URL based on server configuration
    const imageUrl = `https://${process.env.S3_BUCKET_NAME}.s3.us-west-2.amazonaws.com/${req.fileName}`;

    // Get the actual wallet address from request body or token
    const walletAddress =
      req.body.artistAddress || (req.user ? req.user.wallet_address : null);

    if (!category || !price) {
      return res.status(400).json({ error: "Category and price are required" });
    }

    if (!walletAddress) {
      return res
        .status(400)
        .json({ error: "Artist wallet address is required" });
    }

    // Use correct model for gift_card_categories
    const GiftCardCategory = require("../models/GiftCardCategory");
    let giftCardCategoryId = null;
    if (category) {
      let cat = await GiftCardCategory.findOne({
        where: { name: category },
      });
      if (!cat) {
        cat = await GiftCardCategory.create({ name: category });
      }
      giftCardCategoryId = cat.id;
    }

    // Create a database record first
    const localBackground = await Background.create({
      artist_address: walletAddress,
      image_uri: imageUrl,
      gift_card_category_id: giftCardCategoryId,
      price: price,
    });

    // Get contract and wallet from app
    const app = req.app;

    // Check if blockchain is enabled and contract is available
    const blockchainEnabled =
      app.blockchainEnabled === true && app.contract && app.wallet;

    if (!blockchainEnabled) {
      console.warn(
        "Blockchain connection not available - creating database record only"
      );
      return res.status(201).json({
        success: true,
        warning: "Blockchain connection not available - NFT minting skipped",
        background: {
          id: localBackground.id,
          artist_address: localBackground.artist_address,
          image_uri: localBackground.image_uri,
          gift_card_category_id: localBackground.gift_card_category_id,
          price: localBackground.price,
        },
      });
    }

    // Create full URI for the image - ensure it's accessible from the internet
    // In production, this should be an IPFS or permanent storage URL
    let fullImageURI;
    try {
      // Ensure base URL is properly configured
      const baseUrl =
        process.env.BASE_URL ||
        (process.env.NODE_ENV === "production"
          ? "https://yourdomain.com"
          : `${req.protocol}://${req.get("host")}`);

      // Use the already constructed imageUrl which is complete
      fullImageURI = imageUrl;

      console.log(`Using image URI: ${fullImageURI}`);
    } catch (urlError) {
      console.error("Error constructing image URI:", urlError);
      fullImageURI = imageUrl; // Fallback to the original URL
    }

    console.log(`Server wallet address: ${app.wallet.address}`);
    console.log(`Artist address: ${walletAddress}`);
    console.log(`Minting with image URI: ${fullImageURI}`);
    console.log(`Category: ${category}`);

    // The server wallet will mint the background NFT on behalf of the user
    try {
      const tx = await app.contract.mintBackground(
        fullImageURI,
        category,
        ethers.parseEther(price.toString())
      );
      const txhash = tx.hash;

      console.log("Transaction hash:", tx.hash);
      console.log(
        "Transaction sent to blockchain - Etherscan URL:",
        `https://sepolia.etherscan.io/tx/${tx.hash}`
      );

      // Wait for the transaction to be mined with a timeout
      try {
        const receipt = await Promise.race([
          tx.wait(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Transaction timeout")), 120000)
          ),
          // 2 minute timeout
        ]);
        const gasfee = Number((receipt.gasPrice * receipt.gasUsed)) / 1e18;
        const fromaddr = String(receipt.from).toLowerCase();
        const toaddr = String(receipt.to).toLowerCase();

        // Update the database with the transaction hash
        await BlockchainTransaction.create({
          tx_hash: txhash,
          blockchain_tx_id: 1,
          gas_fee: gasfee,
          from_addr: fromaddr,
          to_addr: toaddr,
          tx_timestamp: new Date(),
          created_at: new Date(),
          updated_at: new Date(),
        });
        const transaction_id = await BlockchainTransaction.findOne({
          where: { tx_hash: txhash },
          attributes: ["id"],
        });
        await Background.update(
          {
            blockchain_transaction_id: transaction_id.id,
          },
          {
            where: { id: localBackground.id },
          }
        );

        console.log("Transaction mined! Receipt:", receipt);

        // Extract the backgroundId from the event
        const event = receipt.logs.find((log) => {
          try {
            // For ethers v6
            if (log.fragment && log.fragment.name === "BackgroundMinted") {
              return true;
            }

            // For ethers v5
            if (app.contract && app.contract.interface) {
              try {
                const parsedLog = app.contract.interface.parseLog(log);
                return parsedLog && parsedLog.name === "BackgroundMinted";
              } catch (parseErr) {
                return false;
              }
            }

            return false;
          } catch (err) {
            console.log("Error checking log fragment:", err);
            return false;
          }
        });

        if (event) {
          let backgroundId;

          // Extract background ID based on ethers version
          if (event.args && event.args.backgroundId) {
            // ethers v6
            backgroundId = event.args.backgroundId.toString();
          } else if (app.contract && app.contract.interface) {
            // ethers v5
            try {
              const parsedLog = app.contract.interface.parseLog(event);
              backgroundId = parsedLog.args.backgroundId.toString();
            } catch (err) {
              console.error("Error parsing log for backgroundId:", err);
            }
          }

          if (!backgroundId) {
            console.error("Could not extract backgroundId from event");
            backgroundId = "unknown";
          }

          console.log("Background minted with blockchain ID:", backgroundId);

          // Update the database record with the blockchain ID
          // try {
          //   await updateBackgroundAfterMint(
          //     localBackground,
          //     tx.hash,
          //     backgroundId
          //   );
          // } catch (updateError) {
          //   console.error(
          //     "Error updating background with blockchain ID:",
          //     updateError
          //   );
          //   // Continue anyway - we'll still return success
          // }

          return res.status(201).json({
            success: true,
            background: {
              id: localBackground.id,
              artist_address: localBackground.artist_address,
              image_uri: localBackground.image_uri,
              gift_card_category_id: localBackground.gift_card_category_id,
              price: localBackground.price,
              transactionHash: tx.hash,
              etherscanUrl: `https://sepolia.etherscan.io/tx/${tx.hash}`,
            },
          });
        }
        console.log("No BackgroundMinted event found in receipt");
        console.log("All logs:", receipt.logs);

        return res.status(201).json({
          success: true,
          warning: "Transaction completed but no BackgroundMinted event found",
          background: {
            id: localBackground.id,
            artist_address: localBackground.artist_address,
            image_uri: localBackground.image_uri,
            gift_card_category_id: localBackground.gift_card_category_id,
            price: localBackground.price,
            transactionHash: tx.hash,
            etherscanUrl: `https://sepolia.etherscan.io/tx/${tx.hash}`,
          },
        });
      } catch (miningError) {
        console.error(
          "Error waiting for transaction to be mined:",
          miningError
        );

        // Transaction was sent but failed to mine or get receipt in time
        return res.status(201).json({
          success: true,
          warning: "Transaction sent but confirmation status unknown",
          error: miningError.message,
          background: {
            id: localBackground.id,
            artist_address: localBackground.artist_address,
            image_uri: localBackground.image_uri,
            gift_card_category_id: localBackground.gift_card_category_id,
            price: localBackground.price,
            transactionHash: tx.hash,
            etherscanUrl: `https://sepolia.etherscan.io/tx/${tx.hash}`,
          },
        });
      }
    } catch (contractError) {
      console.error("Error calling blockchain contract:", contractError);

      // We still created the background in the database, so return success with warning
      return res.status(201).json({
        success: true,
        warning: "Background created in database but blockchain minting failed",
        error: contractError.message,
        background: {
          id: localBackground.id,
          artist_address: localBackground.artist_address,
          image_uri: localBackground.image_uri,
          gift_card_category_id: localBackground.gift_card_category_id,
          price: localBackground.price,
        },
      });
    }
  } catch (error) {
    console.error("Mint background error:", error);
    res.status(500).json({ error: "Failed to mint background" });
  }
});

// Verify background status
router.get("/verify/:id", verifyToken, async (req, res) => {
  try {
    const background = await Background.findByPk(req.params.id);
    if (!background) {
      return res.status(404).json({ error: "Background not found" });
    }

    // There is no blockchainTxHash or blockchainId on art_nft, so just return the background info
    return res.status(200).json({
      success: true,
      status: "not_tracked",
      message:
        "Blockchain transaction info is not tracked on backgrounds. See blockchain_transactions table.",
      background: {
        id: background.id,
        artist_address: background.artist_address,
        image_uri: background.image_uri,
        gift_card_category_id: background.gift_card_category_id,
        price: background.price,
      },
    });
  } catch (error) {
    console.error("Verify background error:", error);
    res.status(500).json({ error: "Failed to verify background" });
  }
});

// Get Backgrounds by Category
router.get("/category/:category", async (req, res) => {
  try {
    const backgrounds = await Background.findAll({
      where: { category: req.params.category },
    });

    // Filter out backgrounds with missing images
    const validBackgrounds = backgrounds.filter((background) =>
      imageExists(background.image_uri)
    );

    console.log(
      `Found ${validBackgrounds.length} valid backgrounds with images in category ${req.params.category} (filtered from ${backgrounds.length} total)`
    );

    res.json({
      success: true,
      backgrounds: validBackgrounds,
    });
  } catch (error) {
    console.error("Get backgrounds by category error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get backgrounds",
    });
  }
});

function reciptretrival() {
  return blochaininfo;
}

module.exports = router; // Export the  router;
