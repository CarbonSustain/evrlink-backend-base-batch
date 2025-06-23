# Evrlink2 Backend

## Overview

Evrlink2 is a backend application for managing an NFT gift marketplace. It enables users to mint NFT backgrounds, create and transfer gift cards, and handle transactions. The backend is built with **Node.js**, **Express**, and **MySQL**, and integrates with **Ethereum smart contracts (Solidity)**.

---

## Project Structure

```
evrlink2-backend
├── db
│   ├── migrations
│   │   └── 001_create_tables.sql
│   ├── seeds
│   │   └── seed_data.sql
│   └── db_config.js
├── src
│   ├── app.js
│   ├── controllers
│   │   └── dbController.js
│   └── models
│       ├── Background.js
│       ├── GiftCard.js
│       ├── Transaction.js
│       └── User.js
├── contracts
│   └── GiftCard.sol
├── scripts
│   └── deploy.js
├── test
│   └── NFTGiftMarketplace.test.js
├── .env
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

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the root directory with the following:

```
DB_HOST=your_database_host
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_NAME=your_database_name
SEPOLIA_RPC_URL=https://base-sepolia.g.alchemy.com/v2/YOUR-API-KEY
PRIVATE_KEY=your-metamask-wallet-private-key
ETHERSCAN_API_KEY=your-etherscan-api-key
CONTRACT_ADDRESS=your_deployed_contract_address
FRONTEND_DIST_PATH=/absolute/path/to/your/frontend/dist # Optional
```

### 4. Database Setup

**Run migrations:**

```bash
mysql -u your_database_user -p your_database_name < db/migrations/001_create_tables.sql
```

**(Optional) Seed the database:**

```bash
mysql -u your_database_user -p your_database_name < db/seeds/seed_data.sql
```

### 5. Start the Backend

```bash
node src/app.js
```

---

## Smart Contract Development & Deployment

- Contracts are in the `contracts/` directory (e.g., `GiftCard.sol`).
- Use [Hardhat](https://hardhat.org/) for compiling and deploying contracts.

**Compile contracts:**

```bash
npx hardhat compile
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

## Testing

**Backend tests:**

```bash
npm test
```

**Smart contract tests:**

```bash
npx hardhat test
```

---

## API Usage

- The backend exposes RESTful endpoints for authentication, user management, backgrounds, gift cards, images, wallet, and NFTs.
- See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) for detailed endpoint info, request/response formats, and examples.

---

## Frontend Integration

- The backend can serve the frontend build if you set the `FRONTEND_DIST_PATH` environment variable in `.env`.
- If not set, defaults to `../frontend/dist`.

---

## Deployment

- Ensure all environment variables are set for production.
- Use a process manager like [PM2](https://pm2.keymetrics.io/) for running the server in production.
- Secure your `.env` file and never commit secrets to version control.

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements or bug fixes.

---

## License

MIT License. See the `LICENSE` file for details.

---

## Contact

For questions or onboarding, please reach out to the project maintainer or check the internal documentation.
