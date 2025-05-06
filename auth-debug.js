require('dotenv').config();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

console.log('===== Authentication Debug Tool =====');

// 1. Check JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;
console.log('\n1. Checking JWT_SECRET:');
if (!JWT_SECRET) {
  console.error('❌ ERROR: JWT_SECRET is not defined in .env file');
  console.log('Please set JWT_SECRET in your .env file');
} else {
  console.log('✅ JWT_SECRET is properly configured:', JWT_SECRET.substring(0, 5) + '...');
}

// 2. Test token generation with mock wallet
const testWalletAddress = '0xb459fa28bb622f9aa45764008f98173a25da0158';
console.log('\n2. Testing token generation with wallet:', testWalletAddress);

try {
  const mockUserId = parseInt(testWalletAddress.substring(2, 10), 16) % 1000000;
  const token = jwt.sign({ 
    userId: mockUserId,
    walletAddress: testWalletAddress
  }, JWT_SECRET, { expiresIn: '24h' });

  console.log('✅ JWT token generated successfully:');
  console.log('Token:', token);
  
  // 3. Test token verification
  console.log('\n3. Testing token verification:');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('✅ Token verification successful');
    console.log('Decoded token contents:', decoded);
  } catch (error) {
    console.error('❌ ERROR: Token verification failed:', error.message);
  }
} catch (error) {
  console.error('❌ ERROR: Token generation failed:', error.message);
}

// 4. Verify signature function test
console.log('\n4. Testing signature verification:');
const mockSignature = `mock_signature_for_${testWalletAddress}`;
console.log('Mock signature:', mockSignature);

function verifyMockSignature(address, signature) {
  if (signature.startsWith('mock_signature_for_')) {
    const mockAddress = signature.substring('mock_signature_for_'.length);
    const result = mockAddress.toLowerCase() === address.toLowerCase();
    console.log('Mock signature verification result:', result);
    return result;
  }
  return false;
}

const signatureValid = verifyMockSignature(testWalletAddress, mockSignature);
console.log(signatureValid ? '✅ Signature verification passed' : '❌ Signature verification failed');

// 5. Database connection string check
console.log('\n5. Checking database configuration:');
const DB_CONFIG = {
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD ? '********' : undefined,
  database: process.env.DATABASE_NAME,
  port: process.env.DATABASE_PORT
};

console.log('Database Configuration:', DB_CONFIG);
if (!DB_CONFIG.host || !DB_CONFIG.user || !DB_CONFIG.password || !DB_CONFIG.database) {
  console.log('❌ WARNING: Some database configuration values are missing');
} else {
  console.log('✅ Database configuration looks complete');
}

console.log('\n===== Debug Complete ====='); 