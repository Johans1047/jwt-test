// layers/auth-layer/nodejs/db/index.js
import * as userRepository from './repositories/userRepository.mjs';
import * as refreshTokenRepository from './repositories/refreshTokenRepository.mjs';

// Export as organized objects (maintains backward compatibility)
export const userDB = {
  getUserById: userRepository.getUserById,
  getUserByEmail: userRepository.getUserByEmail,
  createUser: userRepository.createUser,
  updateUser: userRepository.updateUser,
  deleteUser: userRepository.deleteUser
};

export const refreshTokenDB = {
  createRefreshToken: refreshTokenRepository.createRefreshToken,
  getRefreshToken: refreshTokenRepository.getRefreshToken,
  updateRefreshTokenLastUsed: refreshTokenRepository.updateRefreshTokenLastUsed,
  revokeRefreshToken: refreshTokenRepository.revokeRefreshToken,
  revokeAllUserTokens: refreshTokenRepository.revokeAllUserTokens,
  cleanExpiredTokens: refreshTokenRepository.cleanExpiredTokens,
  limitUserTokens: refreshTokenRepository.limitUserTokens,
  getUserTokens: refreshTokenRepository.getUserTokens
};

// Also export repositories directly if needed
export { userRepository, refreshTokenRepository };