import express from 'express';
import serverless from 'serverless-http';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import 'dotenv/config';
import { writeCookie, extractUserInfo } from './express_jwt/helpers/functions.mjs';
import { constants } from './express_jwt/utils/constants.mjs';
import { userDB, refreshTokenDB } from './express_jwt/db/index.mjs';
import { generateAccessToken, generateRefreshToken, verifyToken } from './express_jwt/auth/config.mjs';
import { authenticateRequest, cookieToAuthHeader } from './express_jwt/helpers/middlewares.mjs';
import { registerValidation, loginValidation, refreshTokenValidation } from './express_jwt/utils/validation.mjs';

// Initialize Express app
const app = express();

app.use(express.json()); // For parsing application/json
app.use(cookieParser()); // For parsing cookies
app.use(cookieToAuthHeader); // Middleware to copy token from cookie to Authorization header

// Simple request logger to help debug missing request bodies
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - body:`, req.body);
  next();
});

// Destructure userDB functions
const { getUserById, getUserByEmail, createUser } = userDB;
const { 
  createRefreshToken, 
  getRefreshToken, 
  updateRefreshTokenLastUsed,
  revokeRefreshToken,
  revokeAllUserTokens,
  cleanExpiredTokens,
  limitUserTokens
} = refreshTokenDB;

// Public routes
app.post('/auth/register', registerValidation, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Check if user exists
    const existingUser = await getUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'This email is associated with an existing account' });
    }
    
    // Create user
    const user = await createUser({ email, password, name });
    
    res.json({ user: extractUserInfo(user) });
  } catch (error) {
    return res.status(500).json({
      error: `An unknown error of type ${error.constructor.name} caused the server to return 500 Internal Server Error`
    });
  }
});

// Ruta de prueba protegida con información detallada
app.get('/api/protected-test', cookieToAuthHeader, authenticateRequest, async (req, res) => {
  try {

    const user = await getUserByEmail(req.user.email);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ 
      message: 'Valid token! Access granted.',
      authenticatedAt: new Date().toLocaleString(),
      user: extractUserInfo(user)
    });
  } catch (error) {
    return res.status(500).json({
      error: `An unknown error of type ${error.constructor.name} caused the server to return 500 Internal Server Error`
    });
  }
});

app.post('/auth/login', loginValidation, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await getUserByEmail(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // OPCIÓN 1: Revocar todos los tokens anteriores (single session)
    await revokeAllUserTokens(user.id);
    
    // OPCIÓN 2: Limitar a máximo N tokens activos (ej: 5 dispositivos)
    // await limitUserTokens(user.id, 5);
    
    // Generate tokens (pass secrets and expiries via env or use sensible defaults)
    const accessToken = generateAccessToken(
      user,
      process.env.ACCESS_TOKEN_SECRET,
      constants.ACCESS_TOKEN_EXPIRY
    );

    const refreshToken = generateRefreshToken(
      user,
      process.env.REFRESH_TOKEN_SECRET,
      constants.REFRESH_TOKEN_EXPIRY
    );
    
    // Store refresh token in database
    await createRefreshToken(user.id, refreshToken);
    
    // Set tokens in httpOnly cookies
    const accessCookie = writeCookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60, // 7 días en segundos
      path: '/'
    });

    const refreshCookie = writeCookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60, // 7 días en segundos
      path: '/'
    });
    
    // Set cookies in response header
    res.setHeader('Set-Cookie', [accessCookie, refreshCookie]);
    
    // return tokens and user info in response body
    res.json({ accessToken, user: extractUserInfo(user) });
  } catch (error) {
    return res.status(500).json({
      error: `An unknown error of type ${error.constructor.name} caused the server to return 500 Internal Server Error`
    });
  }
});

app.post('/auth/refresh', refreshTokenValidation, async (req, res) => {
  try {
    const oldRefreshToken = req.cookies.refreshToken;
    
    if (!oldRefreshToken) {
      return res.status(401).json({ error: 'Refresh token not found' });
    }
    
    // Verify refresh token using the configured secret
    const result = verifyToken(oldRefreshToken, process.env.REFRESH_TOKEN_SECRET);

    if (!result) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    if (!result.valid) {
      return res.status(403).json({ error: 'Invalid or expired refresh token', details: result.error });
    }

    const payload = result.payload;
    
    const storedToken = await getRefreshToken(oldRefreshToken);
    
    if (!storedToken) {
      return res.status(403).json({ error: 'Refresh token not found or revoked' });
    }
    
    if (new Date(storedToken.expires_at) < new Date()) {
      return res.status(403).json({ error: 'Refresh token expired' });
    }
    
    await revokeRefreshToken(oldRefreshToken);
    
    const accessToken = generateAccessToken(
      { id: payload.sub, email: payload.email },
      process.env.ACCESS_TOKEN_SECRET,
      constants.ACCESS_TOKEN_EXPIRY
    );

    const newRefreshToken = generateRefreshToken(
      { id: payload.sub, email: payload.email },
      process.env.REFRESH_TOKEN_SECRET,
      constants.REFRESH_TOKEN_EXPIRY
    );
    
    // Store new refresh token in database
    await createRefreshToken(payload.sub, newRefreshToken);
    
    const accessCookie = writeCookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60, // 7 días en segundos
      path: '/'
    });

    const refreshCookie = writeCookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60, // 7 días en segundos
      path: '/'
    });
    
    res.setHeader('Set-Cookie', [accessCookie, refreshCookie]);
    
    res.status(200).json({ success: true });
  } catch (error) {
    return res.status(500).json({
      error: `An unknown error of type ${error.constructor.name} caused the server to return 500 Internal Server Error`
    });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Use endpoints:');
  console.log('  POST /auth/register');
  console.log('  POST /auth/login');
  console.log('  POST /auth/refresh');
  console.log('  POST /auth/logout');
  console.log('  POST /auth/logout-all');
  console.log('  GET  /api/profile');
  console.log('  GET  /api/dashboard');
  console.log('  GET  /api/protected-test');
  console.log('http://localhost:3000 \n');
});

// export const handler = serverless(app);
