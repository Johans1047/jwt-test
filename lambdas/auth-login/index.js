// lambdas/auth-login/index.js
import { userDB, refreshTokenDB } from '/opt/nodejs/db/user.js';
import { generateAccessToken, generateRefreshToken } from '/opt/nodejs/auth/jwt.js';
import { createCookieHeader } from '/opt/nodejs/middlewares/auth.js';

// TODO: The plan is to have each express endpoint with the path /, because the real path will be set in the API Gateway and the lambdas are just using express serverless as a proxy
// TODO: e.g. /auth/login -> / -> lambda function
// Meanwhile we keep the paths as a normal express server (server.mjs) for easier local testing

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

export const handler = async (event) => {
  try {
    console.log('Login request received');
    
    // Parse body
    const body = JSON.parse(event.body || '{}');
    const { email, password } = body;

    // Validación básica
    if (!email || !password) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true'
        },
        body: JSON.stringify({ 
          error: 'Email and password are required' 
        })
      };
    }

    console.log(`Attempting login for email: ${email}`);

    // Buscar usuario en DynamoDB
    const user = await userDB.getUserByEmail(email);
    
    if (!user) {
      console.log('User not found');
      return {
        statusCode: 401,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true'
        },
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    // TODO: En producción, usar bcrypt.compare(password, user.password)
    if (user.password !== password) {
      console.log('Invalid password');
      return {
        statusCode: 401,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true'
        },
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    console.log('User authenticated successfully');

    // OPCIÓN 1: Revocar todos los tokens anteriores (single session)
    await refreshTokenDB.revokeAllUserTokens(user.id);
    
    // OPCIÓN 2: Limitar a máximo N tokens activos (comentar línea anterior)
    // await refreshTokenDB.limitUserTokens(user.id, 5);

    // Generar nuevos tokens
    const accessToken = generateAccessToken(
      user, 
      ACCESS_TOKEN_SECRET, 
      ACCESS_TOKEN_EXPIRY
    );
    const refreshToken = generateRefreshToken(
      user, 
      REFRESH_TOKEN_SECRET, 
      REFRESH_TOKEN_EXPIRY
    );

    console.log('Tokens generated');

    // Guardar refresh token en DynamoDB
    await refreshTokenDB.createRefreshToken(user.id, refreshToken);

    console.log('Refresh token stored in DynamoDB');

    // Remover password de la respuesta
    const { password: _, ...userWithoutPassword } = user;

    // Crear cookies
    const accessTokenCookie = createCookieHeader('accessToken', accessToken, {
      maxAge: 15 * 60 // 15 minutos en segundos
    });
    
    const refreshTokenCookie = createCookieHeader('refreshToken', refreshToken, {
      maxAge: 7 * 24 * 60 * 60 // 7 días en segundos
    });

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
        'Set-Cookie': `${accessTokenCookie}, ${refreshTokenCookie}`
      },
      body: JSON.stringify({
        success: true,
        accessToken,
        user: userWithoutPassword,
        message: 'Login successful'
      })
    };

  } catch (error) {
    console.error('Login error:', error);
    
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true'
      },
      body: JSON.stringify({
        error: 'Login failed',
        message: error.message,
        details: process.env.NODE_ENV === 'development' ? error.stack : undefined
      })
    };
  }
};
