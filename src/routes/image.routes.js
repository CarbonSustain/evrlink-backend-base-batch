const express = require('express');
const router = express.Router();
const { upload } = require('../middleware/multer');
const { verifyToken } = require('../middleware/auth');
const path = require('path');
const fs = require('fs');

// Upload image
router.post('/upload', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image uploaded' });
    }

    // Get the S3 URL from multer-s3
    const imageUrl = req.file.location; // multer-s3 automatically adds the location property

    console.log(`Image uploaded successfully: ${imageUrl}`);

    res.json({
      imageUrl: imageUrl,
      filename: req.file.filename,
      size: req.file.size,
      mimetype: req.file.mimetype
    });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// Get image details
router.get('/:id', async (req, res) => {
  try {
    const imagePath = path.join(__dirname, '..', '..', 'uploads', req.params.id);
    
    if (!fs.existsSync(imagePath)) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const stats = fs.statSync(imagePath);
    res.json({
      id: req.params.id,
      size: stats.size,
      createdAt: stats.birthtime
    });
  } catch (error) {
    console.error('Get image error:', error);
    res.status(500).json({ error: 'Failed to get image details' });
  }
});

// Validate image before upload
router.post('/validate', async (req, res) => {
  try {
    const { file } = req.body;
    
    if (!file) {
      return res.status(400).json({ error: 'File is required' });
    }

    // Basic validation
    const isValid = file.mimetype.startsWith('image/') && 
                    file.size <= 5 * 1024 * 1024; // 5MB limit

    if (!isValid) {
      return res.status(400).json({
        error: 'Invalid file',
        details: {
          allowedTypes: ['image/jpeg', 'image/png', 'image/gif'],
          maxSize: '5MB'
        }
      });
    }

    res.json({
      valid: true,
      details: {
        type: file.mimetype,
        size: file.size
      }
    });
  } catch (error) {
    console.error('Validate image error:', error);
    res.status(500).json({ error: 'Failed to validate image' });
  }
});

module.exports = router;
