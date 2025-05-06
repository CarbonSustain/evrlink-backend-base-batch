const ethers = require('ethers');
const crypto = require('crypto');

// Verify Ethereum signature
const verifySignature = (address, signature) => {
  try {
    // For development only: accept mock signatures
    if (process.env.NODE_ENV !== 'production' && signature.startsWith('mock_signature_for_')) {
      const mockAddress = signature.substring('mock_signature_for_'.length);
      return mockAddress.toLowerCase() === address.toLowerCase();
    }

    // In production: verify real signatures
    const message = 'Sign this message to verify your wallet ownership';
    const signer = ethers.utils.verifyMessage(message, signature);
    return signer.toLowerCase() === address.toLowerCase();
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
};

// Hash secret for gift card claims
const hashSecret = (secret) => {
  return crypto.createHash('sha256').update(secret).digest('hex');
};

// Verify secret against hash
const verifySecret = (secret, secretHash) => {
  const hashedSecret = hashSecret(secret);
  return hashedSecret === secretHash;
};

module.exports = {
  verifySignature,
  hashSecret,
  verifySecret
};
