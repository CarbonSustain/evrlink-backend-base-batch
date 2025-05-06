-- Add new columns to users table
ALTER TABLE "User"
ADD COLUMN bio TEXT,
ADD COLUMN profile_image_url TEXT,
ADD COLUMN total_gift_cards_created INT DEFAULT 0,
ADD COLUMN total_gift_cards_sent INT DEFAULT 0,
ADD COLUMN total_gift_cards_received INT DEFAULT 0,
ADD COLUMN total_backgrounds_minted INT DEFAULT 0,
ADD COLUMN last_login_at TIMESTAMP;
