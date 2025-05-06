const express = require("express");
const router = express.Router();
const { upload } = require("../middleware/multer"); // Updated to use S3 multer configuration
const { verifyToken } = require("../middleware/auth");

// Create new background
router.post("/", verifyToken, upload.single("image"), async (req, res) => {
  try {
    const { category, price } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "Image file is required" });
    }

    const imageUrl = req.file.location; // S3 URL
    console.log("Creating background with:", { imageUrl, category, price });

    if (!category || !price) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const background = await Background.create({
      artistAddress: req.user ? req.user.userId : req.body.artistAddress,
      imageURI: imageUrl,
      category,
      price,
      usageCount: 0,
    });

    res.status(201).json({
      success: true,
      background,
    });
  } catch (error) {
    console.error("Create background error:", error);
    res.status(500).json({ error: "Failed to create background" });
  }
});

module.exports = router;
