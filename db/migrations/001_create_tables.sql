CREATE TABLE backgrounds (
    id SERIAL PRIMARY KEY,
    artist_address VARCHAR(255) NOT NULL,
    image_uri TEXT NOT NULL,
    usage_count INT DEFAULT 0,
    minted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE gift_cards (
    id SERIAL PRIMARY KEY,
    creator_address VARCHAR(255) NOT NULL,
    current_owner VARCHAR(255) NOT NULL,
    price NUMERIC(10, 4) NOT NULL,
    message TEXT,
    secret_hash VARCHAR(255),
    background_id INT NOT NULL,
    is_claimable BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (background_id) REFERENCES backgrounds(id)
);

CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    gift_card_id INT NOT NULL,
    from_address VARCHAR(255),
    to_address VARCHAR(255),
    transaction_type VARCHAR(50),
    amount NUMERIC(10, 4),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (gift_card_id) REFERENCES gift_cards(id)
);

CREATE TABLE "User" (
    id SERIAL PRIMARY KEY,
    wallet_address VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255),
    email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);