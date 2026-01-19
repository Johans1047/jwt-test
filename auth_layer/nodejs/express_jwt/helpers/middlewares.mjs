import { verifyToken } from '../auth/config.mjs';
import { validationResult } from 'express-validator';
import { constants } from '../utils/constants.mjs';

// --------- JWT Authentication Middlewares ---------
export function cookieToAuthHeader(req, res, next) {
  // Retrieve access token from cookies
  const accessToken = req.cookies.accessToken;

  // If token exists, set it in Authorization header 
  if (accessToken) {
    req.headers.authorization = `Bearer ${accessToken}`;
  }

  next();
}

export function authenticateRequest(req, res, next) {
  const authHeader = req.headers?.authorization || req.headers?.Authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({
      errorName: 'AccessTokenRequired',
      errorMessage: 'Access token is required'
    });
  }
  
  const token = authHeader.substring(7);
  const result = verifyToken(token, constants.ACCESS_TOKEN_SECRET);

  // Token expired
  if (result.valid === true && result.error) {
    return res.status(401).json(result.error);
  }
  
  // Invalid token
  if (!result || result.valid === false) {
    return res.status(403).json(result.error);
  }
  
  // Valid token
  req.user = result.payload;
  next();
}

// --------- Validation Schema Middleware ---------
// Validation middleware to handle errors
export function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}