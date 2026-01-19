/**
 * Generates a cookie string with all configurable options
 * Compatible with res.setHeader('Set-Cookie', ...) from Express
 * 
 * @param {string} name - Cookie name
 * @param {string} value - Cookie value
 * @param {Object} options - Configuration options
 * @param {boolean} [options.httpOnly=false] - Cookie only accessible via HTTP
 * @param {boolean} [options.secure=false] - Cookie only over HTTPS
 * @param {string|null} [options.domain=null] - Cookie domain
 * @param {string} [options.path='/'] - Cookie path
 * @param {'Strict'|'Lax'|'None'} [options.sameSite='Strict'] - SameSite policy
 * @param {Date|null} [options.expires=null] - Expiration date
 * @param {number} [options.maxAge=3600] - Lifetime in seconds
 * @returns {string} Formatted cookie string
 */
export function writeCookie(name, value, options = {}) {
  const {
    httpOnly = false,
    secure = false,
    domain = null,
    path = '/',
    sameSite = 'Strict',
    expires = null,
    maxAge = 3600
  } = options;

  // Calculate expires if not provided
  const expiresDate = expires || new Date(Date.now() + maxAge * 1000);
  
  // Format date in GMT format (RFC 2822)
  const expiresStr = expiresDate.toUTCString();

  // Build cookie string
  let cookie = `${name}=${value}; `;
  
  if (domain) cookie += `Domain=${domain}; `;
  
  cookie += `Path=${path}; `;
  cookie += `SameSite=${sameSite}; `;
  cookie += `Expires=${expiresStr}; `;
  cookie += `Max-Age=${maxAge}; `;
  
  if (httpOnly) cookie += 'HttpOnly; ';
  if (secure) cookie += 'Secure;';

  return cookie.trim();
}

export function clearCookie(name, options = {}) {
  return writeCookie(name, '', {
    ...options,
    expires: new Date(0),
    maxAge: 0
  });
}

export function extractUserInfo(user) {
  return {
    email: user.email,
    name: user.name
  };
}