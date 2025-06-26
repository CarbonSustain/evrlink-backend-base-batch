# Evrlink Backend

## Overview

Evrlink is a backend application for managing an NFT gift marketplace. It enables users to mint NFT backgrounds, create and transfer gift cards, and handle transactions. The backend is built with **Node.js**, **Express**, and **PostgreSQL**, and integrates with **Ethereum smart contracts (Solidity)**. The project leverages a variety of tools for development, deployment, and testing.

---

## Tools & Technologies

- **Node.js**: JavaScript runtime for backend logic.
- **Express**: Web framework for RESTful APIs.
- **MySQL**: Relational database for persistent storage.
- **Sequelize**: ORM for database interaction.
- **dotenv**: Environment variable management.
- **Ethereum (Solidity)**: Smart contracts for NFT and gift card logic.
- **Hardhat**: Ethereum development environment for compiling, deploying, and testing smart contracts.
- **Ethers.js**: Ethereum wallet and contract interaction.
- **Chai**: Testing framework for backend and smart contracts.
- **CORS**: Security and logging middleware.
- **Frontend Integration**: Serves a frontend build.

---

## Functionality

- **User Management**: Register, authenticate, and manage users.
- **NFT Backgrounds**: Mint, list, and manage NFT backgrounds.
- **Gift Cards**: Create, transfer, and redeem NFT-based gift cards.
- **Transactions**: Record and retrieve transaction history.
- **Wallet Integration**: Connect and interact with Ethereum wallets.
- **Smart Contract Interaction**: Mint NFTs, transfer ownership, and verify transactions on-chain.
- **API Endpoints**: RESTful endpoints for all major resources.
- **Frontend Serving**: Optionally serves a frontend SPA if configured.
- **Testing**: Comprehensive backend and smart contract tests.
- **Database Migration & Seeding**: Scripts for initializing and populating the database.

---

## Project Structure

```text
evrlink-backend-base-batch
├── contracts
│   ├── GiftCard.sol
│   ├── MockUSDC.sol
├── dist/
│   └── services/
│       └── onchain-agent/
│           ├── create-agent.js
│           └── prepare-agentkit.js
├── evrlink_chatbot/
├── scripts
│   ├── deploy.js
│   ├── deployMockUSDC.js
│   ├── mintMockUSDC.js
│   ├── uploadToS3.js
│   └── usdc_deploy.js
├── services
│   ├── agent.service.js
│   ├── blockchain.js
│   ├── onchain-agent/
│   │   ├── create-agent.js / .ts
│   │   └── prepare-agentkit.js / .ts
│   └── utils/
│       ├── blockchain-updates.js
│       └── crypto.js
├── src
│   ├── app.js
│   ├── server.js
│   ├── contracts/
│   │   └── GiftCard.json
│   ├── controllers/
│   │   └── dbController.js
│   ├── middleware/
│   │   ├── auth.js
│   │   └── multer.js
│   ├── models/
│   │   ├── ArtNft.js
│   │   ├── Background.js
│   │   ├── BlockchainTransaction.js
│   │   ├── BlockchainTransactionCategory.js
│   │   ├── BlockchainTransactionGiftcard.js
│   │   ├── EvrlinkConstant.js
│   │   ├── GiftCard.js
│   │   ├── GiftCardArtNft.js
│   │   ├── GiftCardCategory.js
│   │   ├── GiftCardSecret.js
│   │   ├── GiftCardSettlement.js
│   │   ├── Transaction.js
│   │   ├── User.js
│   │   ├── UserRole.js
│   │   └── index.js
│   ├── routes/
│   │   ├── agent.routes.js
│   │   ├── auth.routes.js
│   │   ├── background.routes.js
│   │   ├── backgrounds.js
│   │   ├── chatbot.routes.js
│   │   ├── giftCard.routes.js
│   │   ├── image.routes.js
│   │   ├── index.js
│   │   ├── nft.routes.js
│   │   ├── user.routes.js
│   │   └── wallet.routes.js
├── test/
│   ├── Giftcard.test.js
│   └── NFTGiftMarketplace.test.js
├── .env
├── buildspec.yml
├── config.js
├── package.json
├── README.md
└── server.js
```

---

## Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url>
cd evrlink2-backend
```

### 2. Install Dependencies

Installs all Node.js dependencies (backend, smart contract, and tooling):

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the root directory with the following:
### 5. Smart Contract Development & Deployment

- Contracts are in the `contracts/` directory (e.g., `GiftCard.sol`).
- Use [Hardhat](https://hardhat.org/) for compiling, deploying, and testing contracts.

**Compile contracts:**

```bash
npm run compile
```

**Deploy to Base Sepolia:**

1. Ensure your `.env` is set up with the correct RPC URL and private key.
2. Run your deployment script:
   ```bash
   npx hardhat run scripts/deploy.js --network base_sepolia
   ```
3. Update the deployed contract address in your `.env` file.

**Verify contract (optional):**

```bash
npx hardhat verify --network base_sepolia <DEPLOYED_CONTRACT_ADDRESS>
```

---

## Running the Application

### Development Mode

Runs the backend with auto-reload on changes (if `nodemon` is installed):

```bash
npm run dev
```

### Production Mode

Runs the backend server (ensure all environment variables are set):

```bash
npm start
```

Or, using PM2 for process management:

```bash
pm2 start src/app.js --name evrlink2-backend
```

### What Runs

- **Backend API**: RESTful endpoints for all resources.
- **Smart Contract Integration**: All NFT and gift card operations interact with the deployed smart contract.
- **Database**: All persistent data is stored in MySQL.
- **Frontend Serving**: If `FRONTEND_DIST_PATH` is set, the backend serves the frontend SPA.
- **Logging & Security**: Middleware for logging requests and securing HTTP headers.
- **Testing**: Run backend and smart contract tests as described below.

---

## Testing

**Backend tests:**  
Runs all backend unit/integration tests (see `test/`):

```bash
npm test
```

**Smart contract tests:**  
Runs all smart contract tests using Hardhat:

```bash
npx hardhat test
```

---

## Deployment

- Ensure all environment variables are set for production.
- Secure your `.env` file and never commit secrets to version control.

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements or bug fixes.

---

## Contact

For questions or onboarding, please reach out to the project maintainer or check the internal documentation.
