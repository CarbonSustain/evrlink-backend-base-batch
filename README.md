# Evrlink2 Backend

## Overview
Evrlink2 is a backend application designed to manage an NFT gift marketplace. It allows users to mint backgrounds as NFTs, create gift cards, and facilitate transactions between users. The application is built using Node.js, Express, and MySQL.

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
├── package.json
├── .env
└── README.md
```

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd evrlink2-backend
   ```

2. **Install Dependencies**
   Make sure you have Node.js and npm installed. Then run:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**
   Create a `.env` file in the root directory and add your database connection details:
   ```
   DB_HOST=your_database_host
   DB_USER=your_database_user
   DB_PASSWORD=your_database_password
   DB_NAME=your_database_name
   ```

4. **Run Database Migrations**
   Execute the SQL commands to create the necessary tables:
   ```bash
   mysql -u your_database_user -p your_database_name < db/migrations/001_create_tables.sql
   ```

5. **Seed the Database**
   Optionally, you can populate the database with initial data:
   ```bash
   mysql -u your_database_user -p your_database_name < db/seeds/seed_data.sql
   ```

6. **Start the Application**
   Run the application using:
   ```bash
   node src/app.js
   ```

## Smart Contract Development and Deployment

### Prerequisites
- Hardhat environment setup
- Sepolia testnet ETH (get from a Sepolia faucet)
- Alchemy or Infura API key for Sepolia network access
- MetaMask wallet with private key

### Environment Setup
Create a `.env` file in the root directory with the following variables:
```env
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY
PRIVATE_KEY=your-metamask-wallet-private-key
ETHERSCAN_API_KEY=your-etherscan-api-key
```

### Compile Smart Contracts
```bash
# Navigate to the backend directory
cd Evrlink-backend

# Install dependencies (if not done already)
npm install

# Compile the smart contracts
npm run compile
```

### Deploy Smart Contracts
1. Make sure you have Sepolia testnet ETH in your wallet
2. Deploy to Sepolia testnet:
```bash
npm run deploy:sepolia
```
3. After deployment, copy the contract address and update it in:
   - Frontend `.env` file as `REACT_APP_CONTRACT_ADDRESS`
   - Backend `.env` file as `CONTRACT_ADDRESS`

### Verify Contract (Optional)
```bash
npx hardhat verify --network sepolia <DEPLOYED_CONTRACT_ADDRESS>
```

### Testing Smart Contracts
```bash
# Run all smart contract tests
npm test

# Run specific test file
npx hardhat test test/GiftCard.test.js
```

## Usage
- The API endpoints are available for interacting with the NFT gift marketplace. You can use tools like Postman or curl to test the endpoints.
- Refer to the API documentation for details on available routes and their functionalities.

## Frontend Integration
When running the frontend and backend in separate repositories, you can configure the backend to serve the frontend from any location by setting the `FRONTEND_DIST_PATH` environment variable:

```
# In your backend .env file
FRONTEND_DIST_PATH=/absolute/path/to/your/frontend/dist
```

This allows you to:
1. Keep both repos completely separate
2. Avoid hardcoded path references
3. Configure different paths for development and production

If you don't set this variable, the server will look for the frontend at `../frontend/dist` relative to the backend directory.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## API Documentation

For detailed API documentation, see the [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) file which contains information about available endpoints, request/response formats, and example code for integrating with the frontend.

The API follows REST principles with the following main resource endpoints:

- `/api/auth` - Authentication endpoints
- `/api/users` - User management 
- `/api/backgrounds` - Background image management
- `/api/gift-cards` - Gift card operations
- `/api/images` - Image uploads and management
- `/api/wallet` - Wallet operations
- `/api/nfts` - NFT-related operations