const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;

const verifyToken = (req, res, next) => {
  // Debugging
  console.log('[Auth Middleware] Request headers:', JSON.stringify(req.headers));
  
  const authHeader = req.headers.authorization;
  
  console.log('[Auth Middleware] Authorization header:', authHeader);
  
  // Check if auth header exists
  if (!authHeader) {
    console.log('[Auth Middleware] No authorization header in request');
    return res.status(401).json({ 
      error: 'No authorization header provided',
      details: 'Please include an Authorization header with format: Bearer <token>'
    });
  }
  
  // Extract token from auth header
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('[Auth Middleware] No token provided in request');
    return res.status(401).json({ 
      error: 'No token provided',
      details: 'Authorization header format should be: Bearer <token>'
    });
  }

  try {
    console.log('[Auth Middleware] Verifying token:', token.substring(0, 20) + '...');
    
    if (!JWT_SECRET) {
      console.error('[Auth Middleware] JWT_SECRET is not defined in environment variables');
      return res.status(500).json({ 
        error: 'Server authentication configuration error',
        details: 'JWT_SECRET is missing in server configuration'
      });
    }
    
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('[Auth Middleware] Token verified, decoded contents:', JSON.stringify(decoded));
    
    // More flexible field checking - either userId/id must exist
    // and preferably walletAddress too
    if ((!decoded.userId && !decoded.id)) {
      console.error('[Auth Middleware] Token missing required fields:', JSON.stringify(decoded));
      return res.status(401).json({ 
        error: 'Invalid token format - no user ID found',
        details: 'Token payload must contain userId or id field'
      });
    }
    
    // Normalize the user object with consistent field names
    req.user = {
      userId: decoded.userId || decoded.id,
      walletAddress: decoded.walletAddress || null
    };
    
    console.log('[Auth Middleware] User attached to request:', JSON.stringify(req.user));
    next();
  } catch (error) {
    console.error('[Auth Middleware] Token verification error:', error.message);
    
    let errorMessage = 'Invalid token';
    let details = error.message;
    
    if (error.name === 'TokenExpiredError') {
      errorMessage = 'Token has expired. Please login again.';
      details = `Token expired at: ${new Date(error.expiredAt)}`;
    } else if (error.name === 'JsonWebTokenError') {
      errorMessage = 'Invalid token. Please login again.';
      details = `JWT Error: ${error.message}`;
    }
    
    return res.status(401).json({ 
      error: errorMessage,
      details: details
    });
  }
};

module.exports = {
  verifyToken
};
