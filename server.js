const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");
const { ethers } = require("ethers");
const path = require("path");
const fs = require("fs");
require("dotenv").config();
const { Sequelize, Op } = require("sequelize");
const multer = require("multer");
const jwt = require("jsonwebtoken");

// Import models
const Background = require("./src/models/Background");
const GiftCard = require("./src/models/GiftCard");
const Transaction = require("./src/models/Transaction");
const User = require("./src/models/User");

// Import API routes
const apiRoutes = require("./src/routes");
const chatbotRoutes = require("./src/routes/chatbot.routes");

const app = express();

// Security middleware
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: [
          "'self'",
          "data:",
          "https://api.evrlink.com",
          "https://evrlink.com",
          "*",
        ],
      },
    },
  })
);
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS), // 100 requests
  message: "Too many requests from this IP, please try again later.",
});

app.use(limiter);

// CORS configuration for production
const corsOptions = {
  origin: [
    "https://evrlink.com",
    "https://www.evrlink.com",
    "https://evrlink.io",
    "https://www.evrlink.io", // Allow requests from this domain
    "http://localhost:8001",
    "http://127.0.0.1:8080",
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["Cross-Origin-Resource-Policy"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

// Serve uploaded files statically with CORS headers
app.use(
  "/uploads",
  (req, res, next) => {
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    res.setHeader("Access-Control-Allow-Origin", "*");

    // Log the request for debugging
    console.log(`Image request: ${req.url}`);

    // Check if the file exists before serving
    const filePath = path.join(__dirname, "uploads", req.url);
    if (fs.existsSync(filePath)) {
      console.log(`Serving image: ${filePath}`);
      next();
    } else {
      console.log(`Warning: Image not found: ${filePath}`);

      // Create a simple SVG placeholder for missing images
      const createPlaceholder = process.env.AUTO_CREATE_PLACEHOLDERS === "true";

      if (createPlaceholder) {
        try {
          const filename = path.basename(req.url);
          const placeholderSVG = `<svg width="400" height="300" xmlns="http://www.w3.org/2000/svg">
          <rect width="400" height="300" fill="#f0f0f0"/>
          <text x="50%" y="50%" font-family="Arial" font-size="24" text-anchor="middle" fill="#888">
            Image Not Found
          </text>
          <text x="50%" y="65%" font-family="Arial" font-size="16" text-anchor="middle" fill="#888">
            (${filename})
          </text>
        </svg>`;

          // Create the placeholder file
          fs.writeFileSync(filePath, placeholderSVG);
          console.log(`Created placeholder image: ${filePath}`);
          next();
        } catch (error) {
          console.error(`Error creating placeholder: ${error.message}`);
          res
            .status(404)
            .send("Image not found and failed to create placeholder");
        }
      } else {
        // Return 404
        res.status(404).send("Image not found");
      }
    }
  },
  express.static(path.join(__dirname, "uploads"))
);

// Fallback route for image errors - this will only be reached if the static middleware doesn't handle it
app.use("/uploads/*", (req, res) => {
  console.log(`Fallback handler - Image not found: ${req.originalUrl}`);
  res.status(404).send("Image not found (fallback)");
});

// Agent endpoint
app.post("/api/agent", async (req, res) => {
  try {
    const { message: userMessage, userId = "default" } = req.body;

    if (!userMessage) {
      return res.status(400).json({ error: "No message found in request" });
    }

    console.log("Processing agent request:", { userMessage, userId });

    // Get the agent instance
    const agent = await createAgent(userId);

    try {
      // Stream the agent's response using the stream method
      console.log(`Streaming response for message: "${userMessage}"`);
      const stream = await agent.stream(
        { messages: [{ content: userMessage, role: "user" }] },
        { configurable: { thread_id: `Evrlink-${userId}` } }
      );

      // Process the streamed response chunks into a single message
      let response = "";
      console.log("Processing response stream...");
      for await (const chunk of stream) {
        if ("agent" in chunk) {
          response += chunk.agent.messages[0].content;
        }
      }

      console.log("Agent response:", response);

      if (!response) {
        console.error("No valid response from agent");
        return res.status(500).json({ error: "No valid response from agent" });
      }

      console.log("Sending response:", response);
      return res.json({ response });
    } catch (agentError) {
      console.error("Error calling agent:", agentError);
      throw agentError;
    }
  } catch (error) {
    console.error("Error in agent endpoint:", error);
    res.status(500).json({ error: error.message || "Internal server error" });
  }
});

// Mount API routes
app.use("/api", apiRoutes);
app.use("/api/chatbot", chatbotRoutes);
// Initialize blockchain connection
let contract = null;
let wallet = null;
let blockchainEnabled = false;

// Import agent service
const { createAgent } = require("./src/services/agent.service");

try {
  // Check if required environment variables are set
  // Remove Sepolia references and use Base Sepolia
  const requiredEnvVars = [
    "PRIVATE_KEY",
    "BASE_SEPOLIA_RPC_URL",
    "CONTRACT_ADDRESS",
  ];
  const missingVars = requiredEnvVars.filter(
    (varName) => !process.env[varName]
  );

  if (missingVars.length > 0) {
    console.warn(
      `Missing blockchain environment variables: ${missingVars.join(", ")}`
    );
    console.warn("Blockchain features will be disabled");
  } else {
    let provider;
    if (ethers.providers && ethers.providers.JsonRpcProvider) {
      // ethers v5
      provider = new ethers.providers.JsonRpcProvider(
        process.env.BASE_SEPOLIA_RPC_URL.trim()
      );
    } else {
      // ethers v6
      provider = new ethers.JsonRpcProvider(
        process.env.BASE_SEPOLIA_RPC_URL.trim()
      );
    }

    // Only use this for all blockchain actions
    const privateKey = process.env.PRIVATE_KEY.trim();
    wallet = new ethers.Wallet(privateKey, provider);

    // Try to find the correct contract artifact file
    let contractABI;
    try {
      // Try different possible locations for contract ABI
      const possiblePaths = [
        "./artifacts/contracts/BackgroundNFT.sol/BackgroundNFT.json",
        "./artifacts/contracts/GiftCard.sol/NFTGiftMarketplace.json",
        "./artifacts/contracts/NFTGiftMarketplace.sol/NFTGiftMarketplace.json",
      ];

      for (const path of possiblePaths) {
        try {
          const artifact = require(path);
          if (artifact && artifact.abi) {
            console.log(`Found contract ABI at ${path}`);
            contractABI = artifact.abi;
            break;
          }
        } catch (err) {
          // Continue to next path
        }
      }

      if (!contractABI) {
        throw new Error("Could not find contract ABI in any expected location");
      }
    } catch (err) {
      throw new Error(`ABI loading error: ${err.message}`);
    }

    // Create contract instance
    const contractAddress = process.env.CONTRACT_ADDRESS.trim();
    contract = new ethers.Contract(contractAddress, contractABI, wallet);

    console.log("Blockchain connection initialized successfully");
    console.log(`Connected to contract at ${contractAddress}`);
    console.log(`Server wallet address: ${wallet.address}`);
    blockchainEnabled = true;
  }
} catch (error) {
  console.error("Failed to initialize blockchain connection:");
  console.error(`Error: ${error.name} - ${error.message}`);
  console.warn("Blockchain features will be disabled");
}

// Add contract, wallet and blockchain status to app
app.contract = contract;
app.wallet = wallet;
app.blockchainEnabled = blockchainEnabled;

// Initialize agent
let agent = null;
createAgent()
  .then((a) => {
    agent = a;
    console.log("Agent initialized successfully");
  })
  .catch((error) => {
    console.error("Failed to initialize agent:", error);
  });

// Add updateUserStats to app if available
if (typeof updateUserStats === "function") {
  app.updateUserStats = updateUserStats;
}

const handleError = (error, res) => {
  console.error("❌ Error:", error);
  if (error.code === "INSUFFICIENT_FUNDS") {
    return res.status(400).json({
      success: false,
      error:
        "Insufficient funds. Please try with a smaller amount or get more Sepolia ETH.",
    });
  }
  if (error.code === "NETWORK_ERROR") {
    return res.status(503).json({
      success: false,
      error: "Network error. Please check your connection and try again.",
    });
  }
  return res.status(500).json({
    success: false,
    error: error.message || "An unexpected error occurred.",
  });
};

// Remove frontend serving configuration and replace with API status endpoint
app.get("/", (req, res) => {
  res.json({
    status: "success",
    message: "NFTGiftMarketplace API is running",
    network: "Sepolia Testnet",
  });
});

// Simple test endpoint for backgrounds API
app.get("/api/backgrounds/test", (req, res) => {
  res.json({
    status: "success",
    message: "Backgrounds API test endpoint is working",
  });
});

// Get all backgrounds
// Commenting out this version since we have a better implementation below with pagination
// app.get("/api/backgrounds", async (req, res) => {
//   try {
//     const backgrounds = await Background.findAll({
//       order: [['createdAt', 'DESC']]
//     });
//
//     res.json({
//       success: true,
//       count: backgrounds.length,
//       backgrounds: backgrounds.map(bg => ({
//         id: bg.id,
//         artistAddress: bg.artistAddress,
//         imageURI: bg.imageURI,
//         category: bg.category,
//         price: bg.price,
//         usageCount: bg.usageCount,
//         createdAt: bg.createdAt
//       }))
//     });
//   } catch (error) {
//     console.error('Error fetching backgrounds:', error);
//     res.status(500).json({
//       success: false,
//       error: error.message || 'Failed to fetch backgrounds'
//     });
//   }
// });

// Setup multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"));
    }
  },
});

const ARTIST_MESSAGE =
  "Background created successfully. Note: While the contract shows the server wallet as the minter for technical reasons, the database correctly attributes you as the artist.";

// Direct background creation endpoint
app.post("/api/backgrounds", upload.single("image"), async (req, res) => {
  try {
    const { category, price } = req.body;
    const imageFile = req.file;

    if (!imageFile) {
      return res.status(400).json({ error: "Image file is required" });
    }
    if (!category || !price) {
      return res.status(400).json({ error: "Category and price are required" });
    }
    if (isNaN(price) || Number(price) <= 0) {
      return res.status(400).json({ error: "Price must be a positive number" });
    }

    // Construct image URL (adjust as per your storage setup)
    const imageUrl = `https://${process.env.S3_BUCKET_NAME}.s3.us-west-2.amazonaws.com/${req.fileName}`;

    // Mint on blockchain with new contract logic
    let tx, receipt, event, backgroundId;
    try {
      tx = await contract.mintBackground(
        imageUrl,
        category,
        ethers.parseEther(price.toString())
      );
      receipt = await tx.wait();

      // Extract backgroundId from event logs (as before)
      event = receipt.logs.find((log) => {
        try {
          return log.fragment && log.fragment.name === "BackgroundMinted";
        } catch (err) {
          console.log("Error checking log fragment:", err);
          return false;
        }
      });

      if (!event) {
        return res.status(500).json({
          success: false,
          error: "BackgroundMinted event not found in transaction receipt.",
        });
      }
      backgroundId = event.args.backgroundId.toString();
    } catch (error) {
      console.error("Error minting background on-chain:", error);
      return res
        .status(500)
        .json({ error: "Failed to mint background on-chain" });
    }

    // Only create DB record if on-chain mint succeeded
    const localBackground = await Background.create({
      id: backgroundId, // Use blockchain ID
      artistAddress: req.body.artistAddress || null,
      imageURI: imageUrl,
      category,
      price,
      usageCount: 0,
      blockchainId: backgroundId,
      blockchainTxHash: tx.hash,
    });

    res.status(201).json({
      success: true,
      background: {
        id: localBackground.id,
        artistAddress: localBackground.artistAddress,
        imageURI: localBackground.imageURI,
        category: localBackground.category,
        price: localBackground.price,
        blockchainTxHash: localBackground.blockchainTxHash,
        blockchainId: localBackground.blockchainId,
        transactionHash: localBackground.blockchainTxHash,
        basescanUrl: localBackground.blockchainTxHash
          ? `https://sepolia.basescan.org/tx/${localBackground.blockchainTxHash}`
          : null,
      },
    });
  } catch (error) {
    console.error("Error creating background:", error);
    res.status(500).json({ error: "Failed to create background" });
  }
});

// Mint Background
app.post("/api/background/mint", async (req, res) => {
  try {
    const { imageURI, category, price } = req.body;
    if (!imageURI || !category || !price) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (isNaN(price) || Number(price) <= 0) {
      return res.status(400).json({ error: "Invalid price" });
    }

    console.log("🔹 Minting Background:", { imageURI, category, price });
    const tx = await contract.mintBackground(
      imageURI,
      category,
      ethers.parseEther(price.toString())
    );
    const receipt = await tx.wait();
    console.log("🔍 Transaction Receipt:", receipt);

    const event = receipt.logs.find(
      (log) => log.fragment && log.fragment.name === "BackgroundMinted"
    );
    if (!event) {
      return res.status(500).json({
        success: false,
        error: "BackgroundMinted event not found in transaction receipt.",
      });
    }
    const backgroundId = event.args.backgroundId.toString();

    // Save to database using the blockchain ID
    const background = await Background.create({
      id: backgroundId, // Use blockchain ID
      artistAddress: wallet.address,
      imageURI,
      category,
      price,
    });

    console.log(`✅ Background Minted and Saved to DB - ID: ${backgroundId}`);
    await updateUserStats(wallet.address);
    res.json({
      success: true,
      transactionHash: tx.hash,
      basescanUrl: `https://sepolia.basescan.org/tx/${transactionHash}`,
      giftCardId,
      giftCard,
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Calculate required ETH for minting a gift card
app.post("/api/giftcard/price", async (req, res) => {
  try {
    const { backgroundId, price } = req.body;
    if (!backgroundId || !price) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: backgroundId and price are required.",
      });
    }

    // Optionally verify background exists
    const background = await Background.findByPk(backgroundId);
    if (!background) {
      return res.status(404).json({
        success: false,
        error: "Background not found with the given ID.",
      });
    }

    const backgroundPrice = ethers.parseEther(price.toString());
    const PLATFORM_FEE_IN_WEI = BigInt("611111111111111");
    const taxFee = (backgroundPrice * 4n) / 100n;
    const climateFee = backgroundPrice / 100n;
    const totalRequired =
      backgroundPrice + PLATFORM_FEE_IN_WEI + taxFee + climateFee;

    res.json({
      success: true,
      backgroundId,
      price: price.toString(),
      breakdown: {
        backgroundPrice: backgroundPrice.toString(),
        platformFee: PLATFORM_FEE_IN_WEI.toString(),
        taxFee: taxFee.toString(),
        climateFee: climateFee.toString(),
      },
      totalRequired: totalRequired.toString(),
      totalRequiredEth: ethers.formatEther(totalRequired),
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Helper function for pagination
function getPaginationParams(req) {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  return { limit, offset, page };
}

// Get All Backgrounds with Pagination
// Commenting out as this is now handled by background.routes.js
// app.get("/api/backgrounds", async (req, res) => {
//   try {
//     const { limit, offset, page } = getPaginationParams(req);
//     const { category } = req.query;
//
//     const whereClause = category ? { category } : {};
//
//     const { count, rows: backgrounds } = await Background.findAndCountAll({
//       where: whereClause,
//       limit,
//       offset,
//       order: [['createdAt', 'DESC']]
//     });
//
//     const totalPages = Math.ceil(count / limit);
//
//     res.json({
//       success: true,
//       backgrounds,
//       pagination: {
//         currentPage: page,
//         totalPages,
//         totalItems: count,
//         itemsPerPage: limit,
//         hasNextPage: page < totalPages,
//         hasPrevPage: page > 1
//       }
//     });
//   } catch (error) {
//     handleError(error, res);
//   }
// });

// Get Background by ID
app.get("/api/background/:id", async (req, res) => {
  try {
    const background = await Background.findByPk(req.params.id);
    if (!background) {
      return res.status(404).json({
        success: false,
        error: "Background not found",
      });
    }
    res.json({ success: true, background });
  } catch (error) {
    handleError(error, res);
  }
});

app.post("/api/auth/email-wallet", async (req, res) => {
  const { walletAddress, email, user_name, role_id = 1 } = req.body;

  try {
    const updateData = {};
    if (walletAddress) updateData.walletAddress = walletAddress;
    if (email) updateData.email = email;
    if (user_name) updateData.user_name = user_name;
    updateData.role_id = role_id; // Ensure role_id is always set

    // Perform the upsert
    const [user, created] = await User.upsert(
      {
        ...updateData,
      },
      {
        where: {
          [Sequelize.Op.or]: [{ walletAddress }, { email }, { user_name }],
        },
        returning: true,
      }
    );

    if (created) {
      return res
        .status(201)
        .json({ message: "User created successfully", user });
    } else {
      return res
        .status(200)
        .json({ message: "User updated successfully", user });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "An error occurred", error });
  }
});

// Associate email with wallet address
app.post("/email-wallet", async (req, res) => {
  try {
    console.log("Email-wallet association request received:", req.body);
    const { email, walletAddress } = req.body;

    if (!email || !walletAddress) {
      console.log("Missing email or walletAddress in request");
      return res
        .status(400)
        .json({ error: "Email and wallet address are required" });
    }

    // Use raw SQL instead of Sequelize ORM to avoid schema issues
    const sequelize = User.sequelize;

    // First, check if the email_wallets table exists
    try {
      console.log("Checking if email_wallets table exists...");
      await sequelize.query("SELECT 1 FROM email_wallets LIMIT 1");
      console.log("email_wallets table exists");
    } catch (tableError) {
      console.log("email_wallets table does not exist, creating it...");
      try {
        // Create the email_wallets table
        await sequelize.query(`
          CREATE TABLE IF NOT EXISTS email_wallets (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            wallet_address VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);
        console.log("email_wallets table created successfully");
      } catch (createError) {
        console.error("Failed to create email_wallets table:", createError);
        return res.status(500).json({
          error: "Database schema issue: failed to create email_wallets table",
        });
      }
    }

    // Check if user exists in the users table
    console.log("Checking if user exists for wallet address:", walletAddress);
    const users = await sequelize.query(
      `SELECT id FROM users WHERE wallet_address = $1`,
      {
        bind: [walletAddress],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    // Create user if it doesn't exist
    if (!users || users.length === 0) {
      console.log(
        "User not found, creating new user with wallet address:",
        walletAddress
      );
      try {
        await sequelize.query(
          `INSERT INTO users (wallet_address) VALUES ($1)`,
          {
            bind: [walletAddress],
          }
        );
        console.log("User created successfully");
      } catch (userError) {
        console.error("Error creating user:", userError);
        // Continue anyway, the association is the important part
      }
    } else {
      console.log("User exists with ID:", users[0].id);
    }

    // Check if email is already associated with a wallet
    console.log(
      "Checking if email is already associated with a wallet:",
      email
    );
    const emailWallets = await sequelize.query(
      `SELECT id, wallet_address FROM email_wallets WHERE email = $1`,
      {
        bind: [email],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (emailWallets && emailWallets.length > 0) {
      // Update the existing association
      console.log(
        "Email already associated with wallet, updating to:",
        walletAddress
      );
      await sequelize.query(
        `UPDATE email_wallets SET wallet_address = $1 WHERE email = $2`,
        {
          bind: [walletAddress, email],
        }
      );
      console.log("Updated email-wallet association");
    } else {
      // Create a new association
      console.log("Creating new email-wallet association");
      try {
        await sequelize.query(
          `INSERT INTO email_wallets (email, wallet_address) VALUES ($1, $2)`,
          {
            bind: [email, walletAddress],
          }
        );
        console.log("Created new email-wallet association");
      } catch (insertError) {
        console.error("Error creating email-wallet association:", insertError);

        // Try another approach with plain SQL if the parameterized query fails
        try {
          const sanitizedEmail = email.replace(/'/g, "''");
          const sanitizedWalletAddress = walletAddress.replace(/'/g, "''");

          await sequelize.query(
            `INSERT INTO email_wallets (email, wallet_address) VALUES ('${sanitizedEmail}', '${sanitizedWalletAddress}')`
          );
          console.log("Created email-wallet association with plain SQL");
        } catch (plainError) {
          console.error("Error with plain SQL insert:", plainError);
          throw new Error("All insert approaches failed");
        }
      }
    }

    res.json({
      success: true,
      data: {
        email,
        walletAddress,
      },
    });
  } catch (error) {
    console.error("Email-wallet association error:", error);
    res.status(500).json({
      error: "Failed to associate email with wallet: " + error.message,
    });
  }
});

// Get wallet address by email
app.get("/email-wallet", async (req, res) => {
  try {
    console.log("Get wallet by email request received:", req.query);
    const { email } = req.query;

    if (!email) {
      console.log("Missing email in request");
      return res.status(400).json({ error: "Email is required" });
    }

    // Use raw SQL instead of Sequelize ORM
    const sequelize = User.sequelize;

    // Check if the email_wallets table exists
    try {
      await sequelize.query("SELECT 1 FROM email_wallets LIMIT 1");
    } catch (tableError) {
      console.log("email_wallets table does not exist");
      return res.status(404).json({
        success: false,
        error: "No wallet found for this email",
      });
    }

    // Find email-wallet association
    const emailWallets = await sequelize.query(
      `SELECT wallet_address FROM email_wallets WHERE email = $1`,
      {
        bind: [email],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!emailWallets || emailWallets.length === 0) {
      console.log("No wallet found for email:", email);
      return res.status(404).json({
        success: false,
        error: "No wallet found for this email",
      });
    }

    const walletAddress = emailWallets[0].wallet_address;
    console.log("Found wallet for email:", email, walletAddress);

    res.json({
      success: true,
      email,
      walletAddress,
    });
  } catch (error) {
    console.error("Get wallet by email error:", error);
    res
      .status(500)
      .json({ error: "Failed to get wallet for email: " + error.message });
  }
});

// Direct handler for GET email-wallet endpoint
app.get("/api/auth/email-wallet", async (req, res) => {
  console.log("Direct get wallet by email request received:", req.query);
  const { email } = req.query;

  if (!email) {
    console.log("Missing email in request");
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    // First try to find user by email in the User model
    const user = await User.findOne({ where: { email } });

    if (user) {
      console.log(
        "Found user with matching email in users table:",
        user.walletAddress
      );
      return res.json({
        success: true,
        email,
        walletAddress: user.walletAddress,
      });
    }

    // If not found in users table, check email_wallets table (legacy approach)
    console.log("User not found in users table, checking email_wallets table");
    const sequelize = require("./db/db_config");

    // Check if the email_wallets table exists
    try {
      await sequelize.query("SELECT 1 FROM email_wallets LIMIT 1");
    } catch (tableError) {
      console.log("email_wallets table does not exist");
      return res.status(404).json({
        success: false,
        error: "No wallet found for this email",
      });
    }

    // Find email-wallet association
    const emailWallets = await sequelize.query(
      `SELECT wallet_address FROM email_wallets WHERE email = $1`,
      {
        bind: [email],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!emailWallets || emailWallets.length === 0) {
      console.log("No wallet found for email:", email);
      return res.status(404).json({
        success: false,
        error: "No wallet found for this email",
      });
    }

    const walletAddress = emailWallets[0].wallet_address;
    console.log(
      "Found wallet for email in email_wallets table:",
      email,
      walletAddress
    );

    res.json({
      success: true,
      email,
      walletAddress,
    });
  } catch (error) {
    console.error("Get wallet by email error:", error);
    res
      .status(500)
      .json({ error: "Failed to get wallet for email: " + error.message });
  }
});

// Create Gift Card
app.post(
  ["/api/giftcard/create", "/api/gift-cards/create"],
  async (req, res) => {
    try {
      const { backgroundId, price, message } = req.body;
      if (!backgroundId || !price) {
        return res.status(400).json({
          success: false,
          error:
            "Missing required fields: backgroundId and price are required.",
        });
      }

      // First verify the background exists in database
      const background = await Background.findByPk(backgroundId);
      if (!background) {
        return res.status(404).json({
          success: false,
          error: "Background not found with the given ID.",
        });
      }

      // Require blockchain to be enabled for gift card creation
      if (!blockchainEnabled || !contract) {
        return res.status(503).json({
          success: false,
          error:
            "Blockchain is not enabled. Gift card creation requires blockchain connectivity.",
        });
      }

      let giftCardId;
      let transactionHash;

      // Calculate total required ETH as per contract logic
      const backgroundPrice = ethers.parseEther(price.toString());
      const PLATFORM_FEE_IN_WEI = BigInt("611111111111111");
      const taxFee = (backgroundPrice * 4n) / 100n;
      const climateFee = backgroundPrice / 100n;
      const totalRequired =
        backgroundPrice + PLATFORM_FEE_IN_WEI + taxFee + climateFee;

      // Create Gift Card on blockchain
      console.log("🔹 Creating Gift Card on blockchain:", {
        backgroundId,
        price,
        message,
      });
      let receipt;
      try {
        const tx = await contract.createGiftCard(backgroundId, message, {
          value: totalRequired,
        });
        receipt = await tx.wait();

        const event = receipt.logs.find(
          (log) => log.fragment && log.fragment.name === "GiftCardCreated"
        );
        if (!event) {
          const errMsg =
            "GiftCardCreated event not found in transaction receipt. Possible ABI mismatch or contract did not emit event.";
          console.error(errMsg);
          throw new Error(errMsg);
        }
        giftCardId = event.args.giftCardId.toString();
        transactionHash = receipt.hash;
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
        } else if (error.message && error.message.includes("event not found")) {
          debugMsg +=
            "Event not found in transaction receipt. Check contract ABI and event emission.";
        } else if (error.message && error.message.includes("private key")) {
          debugMsg +=
            "Wallet/private key error. Check backend wallet configuration and funding.";
        } else {
          debugMsg += error.message || "Unknown blockchain error.";
        }
        console.error(debugMsg, error);
        return res.status(500).json({
          success: false,
          error: debugMsg,
          details: error.stack || error,
        });
      }

      // Only save to DB if blockchain succeeded
      const giftCard = await GiftCard.create({
        id: giftCardId,
        backgroundId,
        price: totalRequired.toString(), // Store the actual ETH collected
        message,
        isClaimable: true,
        creatorAddress,
        currentOwner: creatorAddress,
        transactionHash,
      });

      // Increment background usage count
      await background.increment("usageCount");
      await background.save();

      res.json({
        success: true,
        transactionHash,
        basescanUrl: `https://sepolia.basescan.org/tx/${transactionHash}`,
        giftCardId,
        giftCard,
      });
    } catch (error) {
      console.error("Gift card creation error:", error);
      handleError(error, res);
    }
  }
);

// Get All Gift Cards with Pagination and Filters
app.get("/api/giftcards", async (req, res) => {
  try {
    const { limit, offset, page } = getPaginationParams(req);
    const { status, minPrice, maxPrice } = req.query;

    const whereClause = {};
    if (status) {
      whereClause.isClaimable = status === "available";
    }
    if (minPrice) {
      whereClause.price = {
        ...whereClause.price,
        [Op.gte]: parseFloat(minPrice),
      };
    }
    if (maxPrice) {
      whereClause.price = {
        ...whereClause.price,
        [Op.lte]: parseFloat(maxPrice),
      };
    }

    const { count, rows: giftCards } = await GiftCard.findAndCountAll({
      where: whereClause,
      include: [{ model: Background }],
      limit,
      offset,
      order: [["createdAt", "DESC"]],
    });

    const totalPages = Math.ceil(count / limit);

    res.json({
      success: true,
      giftCards,
      pagination: {
        currentPage: page,
        totalPages,
        totalItems: count,
        itemsPerPage: limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Get Gift Card by ID
app.get("/api/giftcard/:id", async (req, res) => {
  try {
    const giftCard = await GiftCard.findByPk(req.params.id, {
      include: [{ model: Background }],
    });
    if (!giftCard) {
      return res.status(404).json({
        success: false,
        error: "Gift Card not found",
      });
    }
    res.json({ success: true, giftCard });
  } catch (error) {
    handleError(error, res);
  }
});

// Get All Gift Cards by Owner
app.get("/api/giftcards/owner/:address", async (req, res) => {
  try {
    const giftCards = await GiftCard.findAll({
      where: { currentOwner: req.params.address },
      include: [{ model: Background }],
    });
    res.json({ success: true, giftCards });
  } catch (error) {
    handleError(error, res);
  }
});

// Get All Gift Cards by Creator
app.get("/api/giftcards/creator/:address", async (req, res) => {
  try {
    const giftCards = await GiftCard.findAll({
      where: { creatorAddress: req.params.address },
      include: [{ model: Background }],
    });
    res.json({ success: true, giftCards });
  } catch (error) {
    handleError(error, res);
  }
});

// Transfer Gift Card
app.post("/api/giftcard/transfer", async (req, res) => {
  try {
    const { giftCardId, recipient } = req.body;
    if (!giftCardId || !recipient) {
      return res.status(400).json({
        success: false,
        error:
          "Missing required fields: giftCardId and recipient are required.",
      });
    }

    // Call the smart contract to transfer the gift card on-chain
    const tx = await contract.transferGiftCard(giftCardId, recipient);
    const receipt = await tx.wait();

    // Find the GiftCardTransferred event in the logs (optional, if your contract emits it)
    const event = receipt.logs.find(
      (log) => log.fragment && log.fragment.name === "GiftCardTransferred"
    );
    if (!event) {
      // Optionally warn, but still proceed if the transaction succeeded
      console.warn(
        "GiftCardTransferred event not found in transaction receipt"
      );
    }

    // Update database only after successful on-chain transfer
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (giftCard) {
      await giftCard.update({ currentOwner: recipient });

      // Record transaction
      await Transaction.create({
        giftCardId,
        fromAddress: wallet.address,
        toAddress: recipient,
        transactionType: "TRANSFER",
        amount: 0,
        transactionHash: tx.hash,
      });
    }

    await Promise.all([
      updateUserStats(wallet.address),
      updateUserStats(recipient),
    ]);
    res.json({
      success: true,
      transactionHash: tx.hash,
      etherscanUrl: `https://sepolia.etherscan.io/tx/${tx.hash}`,
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Buy Gift Card
app.post("/api/giftcard/buy", async (req, res) => {
  try {
    const { giftCardId, message, price } = req.body;
    if (!giftCardId || !price) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: giftCardId and price are required.",
      });
    }

    const tx = await contract.buyGiftCard(giftCardId, message, {
      value: ethers.parseEther(price),
    });
    const receipt = await tx.wait();

    // Update database
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (giftCard) {
      await giftCard.update({
        currentOwner: wallet.address,
        message: message || giftCard.message,
      });

      // Record transaction
      await Transaction.create({
        giftCardId,
        fromAddress: giftCard.creatorAddress,
        toAddress: wallet.address,
        transactionType: "PURCHASE",
        amount: price,
      });
    }

    await Promise.all([
      updateUserStats(wallet.address),
      updateUserStats(giftCard.currentOwner),
    ]);
    res.json({ success: true, transactionHash: tx.hash });
  } catch (error) {
    handleError(error, res);
  }
});

// Get All Transactions for a Gift Card
app.get("/api/giftcard/:id/transactions", async (req, res) => {
  try {
    const transactions = await Transaction.findAll({
      where: { giftCardId: req.params.id },
      order: [["createdAt", "DESC"]],
    });
    res.json({ success: true, transactions });
  } catch (error) {
    handleError(error, res);
  }
});

// Claim Gift Card
app.post("/api/giftcard/claim", async (req, res) => {
  try {
    const { giftCardId, secret } = req.body;
    if (!giftCardId || !secret) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: giftCardId and secret are required.",
      });
    }

    console.log("🔹 Claiming Gift Card on blockchain:", { giftCardId });
    const tx = await contract.claimGiftCard(giftCardId, secret);
    const receipt = await tx.wait();
    console.log("🔍 Transaction Receipt:", receipt);

    // Find the GiftCardClaimed event
    const event = receipt.logs.find(
      (log) => log.fragment && log.fragment.name === "GiftCardClaimed"
    );
    if (!event) {
      return res.status(500).json({
        success: false,
        error: "GiftCardClaimed event not found in transaction receipt.",
      });
    }

    // Only update DB if on-chain claim succeeded
    const giftCard = await GiftCard.findByPk(giftCardId);
    if (giftCard) {
      await giftCard.update({
        currentOwner: wallet.address,
        isClaimable: false,
        secretHash: null,
      });

      // Record transaction
      await Transaction.create({
        giftCardId,
        fromAddress: giftCard.creatorAddress,
        toAddress: wallet.address,
        transactionType: "CLAIM",
        amount: 0,
        transactionHash: tx.hash,
      });
    }

    await Promise.all([
      updateUserStats(wallet.address),
      updateUserStats(giftCard.creatorAddress),
    ]);
    res.json({
      success: true,
      transactionHash: tx.hash,
      etherscanUrl: `https://sepolia.etherscan.io/tx/${tx.hash}`,
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Helper function to update user statistics
async function updateUserStats(walletAddress) {
  const user = await User.findOne({ where: { walletAddress } });
  if (!user) return;

  const [createdCount, sentCount, receivedCount, mintedCount] =
    await Promise.all([
      GiftCard.count({ where: { creatorAddress: walletAddress } }),
      Transaction.count({
        where: {
          fromAddress: walletAddress,
          transactionType: "TRANSFER",
        },
      }),
      Transaction.count({
        where: {
          toAddress: walletAddress,
          transactionType: "TRANSFER",
        },
      }),
      Background.count({ where: { artistAddress: walletAddress } }),
    ]);

  await user.update({
    totalGiftCardsCreated: createdCount,
    totalGiftCardsSent: sentCount,
    totalGiftCardsReceived: receivedCount,
    totalBackgroundsMinted: mintedCount,
    lastLoginAt: new Date(),
  });
}

// User Registration/Update
app.post("/api/user", async (req, res) => {
  try {
    const { walletAddress, username, email, bio, profileImageUrl } = req.body;
    if (!walletAddress) {
      return res.status(400).json({
        success: false,
        error: "Wallet address is required",
      });
    }

    // Try to find existing user
    let user = await User.findOne({ where: { walletAddress } });

    if (user) {
      // Update existing user
      await user.update({
        username: username || user.username,
        email: email || user.email,
        bio: bio || user.bio,
        profileImageUrl: profileImageUrl || user.profileImageUrl,
        lastLoginAt: new Date(),
      });
    } else {
      // Create new user
      user = await User.create({
        walletAddress,
        username,
        email,
        bio,
        profileImageUrl,
        lastLoginAt: new Date(),
      });
    }

    // Update user statistics
    await updateUserStats(walletAddress);

    // Get updated user data
    user = await User.findOne({ where: { walletAddress } });

    res.json({
      success: true,
      user,
      message: user ? "User updated successfully" : "User created successfully",
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Get User Profile with Detailed Statistics
app.get("/api/user/:walletAddress", async (req, res) => {
  try {
    const user = await User.findOne({
      where: { walletAddress: req.params.walletAddress },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Get all data in parallel
    const [
      createdGiftCards,
      ownedGiftCards,
      mintedBackgrounds,
      sentTransactions,
      receivedTransactions,
    ] = await Promise.all([
      // Gift cards created by user
      GiftCard.findAll({
        where: { creatorAddress: req.params.walletAddress },
        include: [{ model: Background }],
      }),
      // Gift cards currently owned by user
      GiftCard.findAll({
        where: { currentOwner: req.params.walletAddress },
        include: [{ model: Background }],
      }),
      // Backgrounds minted by user
      Background.findAll({
        where: { artistAddress: req.params.walletAddress },
      }),
      // Gift card transfers sent by user
      Transaction.findAll({
        where: {
          fromAddress: req.params.walletAddress,
          transactionType: "TRANSFER",
        },
        include: [
          {
            model: GiftCard,
            include: [{ model: Background }],
          },
        ],
      }),
      // Gift card transfers received by user
      Transaction.findAll({
        where: {
          toAddress: req.params.walletAddress,
          transactionType: "TRANSFER",
        },
        include: [
          {
            model: GiftCard,
            include: [{ model: Background }],
          },
        ],
      }),
    ]);

    // Calculate statistics
    const stats = {
      totalGiftCardsCreated: createdGiftCards.length,
      totalBackgroundsMinted: mintedBackgrounds.length,
      totalGiftCardsSent: sentTransactions.length,
      totalGiftCardsReceived: receivedTransactions.length,
      currentlyOwnedGiftCards: ownedGiftCards.length,
    };

    // Format transfer history
    const transferHistory = {
      sent: sentTransactions.map((tx) => ({
        transactionId: tx.id,
        giftCardId: tx.giftCardId,
        recipient: tx.toAddress,
        timestamp: tx.createdAt,
        giftCard: tx.GiftCard,
      })),
      received: receivedTransactions.map((tx) => ({
        transactionId: tx.id,
        giftCardId: tx.giftCardId,
        sender: tx.fromAddress,
        timestamp: tx.createdAt,
        giftCard: tx.GiftCard,
      })),
    };

    res.json({
      success: true,
      user,
      stats,
      details: {
        mintedBackgrounds,
        createdGiftCards,
        ownedGiftCards,
        transferHistory,
      },
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Delete User
app.delete("/api/user/:walletAddress", async (req, res) => {
  try {
    const user = await User.findOne({
      where: { walletAddress: req.params.walletAddress },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    await user.destroy();
    res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Get Top Users by Activity
app.get("/api/users/top", async (req, res) => {
  try {
    const users = await User.findAll({
      order: [
        ["totalGiftCardsCreated", "DESC"],
        ["totalBackgroundsMinted", "DESC"],
      ],
      limit: 10,
    });
    res.json({ success: true, users });
  } catch (error) {
    handleError(error, res);
  }
});

// Get Backgrounds by Category
app.get("/api/backgrounds/category/:category", async (req, res) => {
  try {
    const backgrounds = await Background.findAll({
      where: { category: req.params.category },
      include: [
        {
          model: User,
          attributes: ["username", "walletAddress", "profileImageUrl"],
        },
      ],
    });
    res.json({ success: true, backgrounds });
  } catch (error) {
    handleError(error, res);
  }
});

// Get Popular Backgrounds
app.get("/api/backgrounds/popular", async (req, res) => {
  try {
    const backgrounds = await Background.findAll({
      order: [["usageCount", "DESC"]],
      limit: 10,
      include: [
        {
          model: User,
          attributes: ["username", "walletAddress", "profileImageUrl"],
        },
      ],
    });
    res.json({ success: true, backgrounds });
  } catch (error) {
    handleError(error, res);
  }
});

// Get Recent Gift Card Transactions
app.get("/api/transactions/recent", async (req, res) => {
  try {
    const transactions = await Transaction.findAll({
      order: [["createdAt", "DESC"]],
      limit: 20,
      include: [
        {
          model: GiftCard,
          include: [{ model: Background }],
        },
      ],
    });
    res.json({ success: true, transactions });
  } catch (error) {
    handleError(error, res);
  }
});

// Search Users
app.get("/api/users/search", async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.status(400).json({
        success: false,
        error: "Search query is required",
      });
    }

    const users = await User.findAll({
      where: {
        [Op.or]: [
          { username: { [Op.iLike]: `%${query}%` } },
          { email: { [Op.iLike]: `%${query}%` } },
          { walletAddress: { [Op.iLike]: `%${query}%` } },
        ],
      },
      limit: 10,
    });
    res.json({ success: true, users });
  } catch (error) {
    handleError(error, res);
  }
});

// Get User Activity Feed
app.get("/api/users/:walletAddress/activity", async (req, res) => {
  try {
    const activities = await Transaction.findAll({
      where: {
        [Op.or]: [
          { fromAddress: req.params.walletAddress },
          { toAddress: req.params.walletAddress },
        ],
      },
      order: [["createdAt", "DESC"]],
      limit: 20,
      include: [
        {
          model: GiftCard,
          include: [{ model: Background }],
        },
      ],
    });

    const formattedActivities = activities.map((activity) => {
      const isOutgoing = activity.fromAddress === req.params.walletAddress;
      return {
        id: activity.id,
        type: activity.transactionType,
        direction: isOutgoing ? "outgoing" : "incoming",
        timestamp: activity.createdAt,
        giftCard: activity.GiftCard,
        otherParty: isOutgoing ? activity.toAddress : activity.fromAddress,
        amount: activity.amount,
      };
    });

    res.json({ success: true, activities: formattedActivities });
  } catch (error) {
    handleError(error, res);
  }
});

// Get All Users with Pagination
app.get("/api/users", async (req, res) => {
  try {
    const { limit, offset, page } = getPaginationParams(req);
    const { sortBy = "createdAt", sortOrder = "DESC" } = req.query;

    const validSortFields = [
      "createdAt",
      "totalGiftCardsCreated",
      "totalBackgroundsMinted",
    ];
    const validSortOrders = ["ASC", "DESC"];

    if (
      !validSortFields.includes(sortBy) ||
      !validSortOrders.includes(sortOrder.toUpperCase())
    ) {
      return res.status(400).json({
        success: false,
        error: "Invalid sort parameters",
      });
    }

    const { count, rows: users } = await User.findAndCountAll({
      limit,
      offset,
      order: [[sortBy, sortOrder.toUpperCase()]],
      attributes: {
        exclude: ["email"], // Don't expose emails in the list
      },
    });

    const totalPages = Math.ceil(count / limit);

    res.json({
      success: true,
      users,
      pagination: {
        currentPage: page,
        totalPages,
        totalItems: count,
        itemsPerPage: limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Get Recent Transactions
app.get("/api/transactions/recent", async (req, res) => {
  try {
    const transactions = await Transaction.findAll({
      order: [["createdAt", "DESC"]],
      limit: 10,
      include: [
        {
          model: GiftCard,
          include: [{ model: Background }],
        },
      ],
    });
    res.json({
      success: true,
      transactions,
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Get Top Users
app.get("/api/users/top", async (req, res) => {
  try {
    const users = await User.findAll({
      order: [
        ["totalGiftCardsCreated", "DESC"],
        ["totalBackgroundsMinted", "DESC"],
      ],
      limit: 10,
      attributes: {
        exclude: ["email"],
      },
    });
    res.json({
      success: true,
      users,
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Search Users
app.get("/api/users/search", async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.status(400).json({
        success: false,
        error: "Search query is required",
      });
    }

    const users = await User.findAll({
      where: {
        [Op.or]: [
          { username: { [Op.iLike]: `%${query}%` } },
          { walletAddress: { [Op.iLike]: `%${query}%` } },
        ],
      },
      attributes: {
        exclude: ["email"],
      },
    });
    res.json({
      success: true,
      users,
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Get User Activity
app.get("/api/users/:walletAddress/activity", async (req, res) => {
  try {
    const { walletAddress } = req.params;
    const user = await User.findOne({
      where: { walletAddress },
      include: [
        {
          model: Transaction,
          as: "transactions",
          include: [
            {
              model: GiftCard,
              include: [{ model: Background }],
            },
          ],
          order: [["createdAt", "DESC"]],
          limit: 20,
        },
      ],
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    res.json({
      success: true,
      activity: user.transactions,
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Get User Profile with Received and Sent Gift Cards
app.get("/api/profile/:walletAddress", async (req, res) => {
  try {
    const { walletAddress } = req.params;
    if (!walletAddress) {
      return res.status(400).json({
        success: false,
        error: "Wallet address is required",
      });
    }

    // Find received cards (where user is current owner but not creator)
    const receivedCards = await GiftCard.findAll({
      where: {
        currentOwner: walletAddress,
        creatorAddress: {
          [Op.ne]: walletAddress, // Not equal to user's address
        },
      },
      include: [{ model: Background }],
      order: [["createdAt", "DESC"]],
    });

    // Find sent cards (where user is creator but not current owner)
    const sentCards = await GiftCard.findAll({
      where: {
        creatorAddress: walletAddress,
        currentOwner: {
          [Op.ne]: walletAddress, // Not equal to user's address
        },
      },
      include: [{ model: Background }],
      order: [["createdAt", "DESC"]],
    });

    res.json({
      success: true,
      profile: {
        address: walletAddress,
        receivedCards,
        sentCards,
      },
    });
  } catch (error) {
    handleError(error, res);
  }
});

// Global request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Legacy route - redirect to the new implementation
app.post("/api/giftcard/set-secret", async (req, res) => {
  try {
    const { giftCardId, secret } = req.body;

    // Forward the request to the new route
    console.log(
      `Legacy global route for setting secret key called, redirecting to gift-cards API`
    );

    // Make an internal request to the correct route
    req.url = `/api/gift-cards/set-secret`;
    req.body = { giftCardId, secret };

    // Continue processing with the routes middleware
    return app._router.handle(req, res);
  } catch (error) {
    console.error("Error in legacy giftcard/set-secret route:", error);
    return res.status(500).json({
      success: false,
      error: "Internal server error processing API request",
    });
  }
});

// Helper function to check if an image file exists (for use in various routes)
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
  const filePath = path.join(__dirname, "uploads", filename);
  return fs.existsSync(filePath);
}

// Add this helper function to the app object for use in routes
app.imageExists = imageExists;

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
