import jwt from 'jsonwebtoken';
const { JsonWebTokenError, TokenExpiredError, NotBeforeError } = jwt;

export function generateAccessToken(user, secret, expiry) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    secret,
    { expiresIn: expiry }
  );
}

export function generateRefreshToken(user, secret, expiry) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    secret,
    { expiresIn: expiry }
  );
}

export function verifyToken(token, secret) {
  try {
    return { valid: true, payload: jwt.verify(token, secret) };
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      return {
        valid: true,
        error: {
          errorName: error.name,
          errorMessage: error.message,
          expiredAt: error.expiredAt
        }
      };
    }

    if (error instanceof JsonWebTokenError || error instanceof NotBeforeError) {
      return {
        valid: false,
        error: {
          errorName: error.name,
          errorMessage: error.message,
          date: error.date || new Date().toISOString()
        }
      };
    }
    
    return null;
  }
}