INSERT INTO backgrounds (id, artist_address, image_uri, usage_count, minted_at) VALUES
(1, '0xArtistAddress1', 'https://example.com/background1.png', 0, NOW()),
(2, '0xArtistAddress2', 'https://example.com/background2.png', 0, NOW()),
(3, '0xArtistAddress3', 'https://example.com/background3.png', 0, NOW());

INSERT INTO gift_cards (id, creator_address, current_owner, price, message, secret_hash, background_id, is_claimable, created_at, updated_at) VALUES
(1, '0xCreatorAddress1', '0xOwnerAddress1', 0.01, 'Happy Birthday!', NULL, 1, FALSE, NOW(), NOW()),
(2, '0xCreatorAddress2', '0xOwnerAddress2', 0.02, 'Congratulations!', NULL, 2, FALSE, NOW(), NOW()),
(3, '0xCreatorAddress3', '0xOwnerAddress3', 0.015, 'Enjoy your gift!', NULL, 3, FALSE, NOW(), NOW());

INSERT INTO transactions (id, gift_card_id, from_address, to_address, transaction_type, amount, timestamp) VALUES
(1, 1, '0xOwnerAddress1', '0xBuyerAddress1', 'purchase', 0.01, NOW()),
(2, 2, '0xOwnerAddress2', '0xBuyerAddress2', 'purchase', 0.02, NOW()),
(3, 3, '0xOwnerAddress3', '0xBuyerAddress3', 'transfer', 0.015, NOW());

INSERT INTO "User" (id, wallet_address, username, email, created_at) VALUES
(1, '0xUserAddress1', 'User1', 'user1@example.com', NOW()),
(2, '0xUserAddress2', 'User2', 'user2@example.com', NOW()),
(3, '0xUserAddress3', 'User3', 'user3@example.com', NOW());