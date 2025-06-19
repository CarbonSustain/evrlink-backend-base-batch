const express = require("express");
const router = express.Router();

// Import all route files
const authRoutes = require("./auth.routes");
const userRoutes = require("./user.routes");
const backgroundRoutes = require("./background.routes");
const giftCardRoutes = require("./giftCard.routes");
const imageRoutes = require("./image.routes");
const walletRoutes = require("./wallet.routes");
const agentRoutes = require("./agent.routes");

// Mount all routes
router.use("/auth", authRoutes);
router.use("/user", userRoutes);
router.use("/background", backgroundRoutes);
router.use("/gift-cards", giftCardRoutes);
router.use("/images", imageRoutes);
router.use("/wallet", walletRoutes);
router.use("/agent", agentRoutes);

module.exports = router;
