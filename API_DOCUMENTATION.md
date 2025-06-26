# Evrlink Backend API Documentation

This document describes the available REST API endpoints for the Evrlink NFT Gift Marketplace backend.

---

## Authentication

### POST `/api/auth/email-wallet`
Associate an email with a wallet address or update user info.

**Body:**
```json
{
  "walletAddress": "0x...",
  "email": "user@example.com",
  "user_name": "username",
  "role_id": 1
}
```
**Response:**  
- `201 Created` or `200 OK` with user info

### GET `/api/auth/email-wallet?email=...`
Get wallet address by email.

---

## Email-Wallet Association (Legacy)

### POST `/email-wallet`
Associate an email with a wallet address (legacy/raw SQL).

### GET `/email-wallet?email=...`
Get wallet address by email (legacy/raw SQL).

---

## Agent

### POST `/api/agent`
Interact with the on-chain agent.

**Body:**
```json
{
  "message": "Your message",
  "userId": "optional"
}
```
**Response:**  
- `{ "response": "Agent reply" }`

---

## Art NFTs / Backgrounds

### POST `/api/artnfts`
Mint a new Art NFT (background).

**Form Data:**  
- `image`: image file (required)
- `priceUsdc`: number (required)
- `artistAddress`: string (required)
- `giftCardId`: string (required)
- `category`: string (optional)

### GET `/api/backgrounds`
List all backgrounds (Art NFTs), supports pagination and category filter.

### GET `/api/background/:id`
Get background by ID.

### GET `/api/backgrounds/category/:category`
Get backgrounds by category.

### GET `/api/backgrounds/popular`
Get popular backgrounds.

### GET `/api/backgrounds/test`
Test endpoint for backgrounds.

---

## Gift Cards

### POST `/api/giftcard/create` or `/api/gift-cards/create`
Create a new gift card.

**Body:**  
- `backgroundId`, `price`, `message`, `creatorAddress`, `artNftId`, `secret`, `recipientAddress`

### POST `/api/giftcard/price`
Calculate required ETH for minting a gift card.

**Body:**  
- `backgroundId`, `price`

### GET `/api/giftcards`
List all gift cards (pagination and filters supported).

### GET `/api/giftcard/:id`
Get gift card by ID.

### GET `/api/giftcards/owner/:address`
Get all gift cards owned by a wallet.

### GET `/api/giftcards/creator/:address`
Get all gift cards created by a wallet.

### POST `/api/giftcard/transfer`
Transfer a gift card to another wallet.

**Body:**  
- `giftCardId`, `recipient`

### POST `/api/giftcard/transfer-by-baseusername`
Transfer a gift card to a user by their base username.

**Body:**  
- `giftCardId`, `baseUsername`

### POST `/api/giftcard/claim`
Claim a gift card with a secret.

**Body:**  
- `giftCardId`, `secret`, `claimerAddress`

### POST `/api/gift-cards/:id/set-secret`
Set a secret for a gift card.

**Body:**  
- `secret`, `ownerAddress`, `artNftId` (optional)

---

## Transactions

### GET `/api/giftcard/:id/transactions`
Get all transactions for a gift card.

### GET `/api/transactions/recent`
Get recent gift card transactions.

---

## Users

### POST `/api/user`
Register or update a user.

**Body:**  
- `walletAddress`, `username`, `email`, `roleId`, `bio`, `profileImageUrl`

### GET `/api/user/:walletAddress`
Get user profile with detailed statistics.

### DELETE `/api/user/:walletAddress`
Delete a user.

### GET `/api/users/top`
Get top users by activity.

### GET `/api/users/search?query=...`
Search users by username, email, or wallet address.

### GET `/api/users/:walletAddress/activity`
Get user activity feed.

### GET `/api/users`
Get all users with pagination and sorting.

---

## Profiles

### GET `/api/profile/:walletAddress`
Get user profile with received and sent gift cards.

---

## Images

### POST `/api/image/upload`
Upload an image (for backgrounds or gift cards).

---

## ENS/CB.ID Resolution

### POST `/api/resolve-cbid`
Resolve a base username (cb.id) to a wallet address.

**Body:**  
- `name`: string

---

## Chatbot

### POST `/api/chatbot/message`
Send a message to the chatbot.

**Body:**  
- `message`: string

---

## Notes

- All endpoints (except `/auth/email-wallet`, `/email-wallet`, `/api/resolve-cbid`, `/api/chatbot/message`) may require authentication.
- Error responses are returned with appropriate HTTP status codes and a JSON error message.
- For more details on request/response formats, see the source code or contact the maintainers.

---
