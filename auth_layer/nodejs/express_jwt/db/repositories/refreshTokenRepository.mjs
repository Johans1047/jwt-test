// layers/auth-layer/nodejs/db/repositories/refreshTokenRepository.js
import { 
  PutCommand, 
  GetCommand, 
  QueryCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand
} from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';
import { dbClient, REFRESH_TOKENS_TABLE } from '../config.mjs';

/**
 * Create refresh token
 */
export async function createRefreshToken(userId, token) {
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const timestamp = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    const newToken = {
      id: crypto.randomUUID(),
      token_hash: tokenHash,
      user_id: userId,
      expires_at: expiresAt.toISOString(),
      ttl: Math.floor(expiresAt.getTime() / 1000), // TTL in epoch seconds for DynamoDB
      revoked: false,
      created_at: timestamp,
      last_used_at: timestamp
    };

    const command = new PutCommand({
      TableName: REFRESH_TOKENS_TABLE,
      Item: newToken
    });

    await dbClient.send(command);
    return newToken;
  } catch (error) {
    console.error('Error creating refresh token:', error);
    throw error;
  }
}

/**
 * Get refresh token by token hash
 */
export async function getRefreshToken(token) {
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const command = new GetCommand({
      TableName: REFRESH_TOKENS_TABLE,
      Key: { token_hash: tokenHash }
    });

    const response = await dbClient.send(command);
    const tokenData = response.Item;

    // Check if token exists and is not revoked
    if (!tokenData || tokenData.revoked) {
      return null;
    }

    return tokenData;
  } catch (error) {
    console.error('Error getting refresh token:', error);
    throw error;
  }
}

/**
 * Update refresh token last used timestamp
 */
export async function updateRefreshTokenLastUsed(token) {
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const timestamp = new Date().toISOString();

    const command = new UpdateCommand({
      TableName: REFRESH_TOKENS_TABLE,
      Key: { token_hash: tokenHash },
      UpdateExpression: 'SET last_used_at = :timestamp',
      ExpressionAttributeValues: {
        ':timestamp': timestamp
      },
      ReturnValues: 'ALL_NEW'
    });

    const response = await dbClient.send(command);
    return response.Attributes;
  } catch (error) {
    console.error('Error updating refresh token:', error);
    throw error;
  }
}

/**
 * Revoke a specific refresh token
 */
export async function revokeRefreshToken(token) {
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const command = new UpdateCommand({
      TableName: REFRESH_TOKENS_TABLE,
      Key: { token_hash: tokenHash },
      UpdateExpression: 'SET revoked = :revoked',
      ExpressionAttributeValues: {
        ':revoked': true
      },
      ReturnValues: 'ALL_NEW'
    });

    await dbClient.send(command);
    return true;
  } catch (error) {
    console.error('Error revoking refresh token:', error);
    return false;
  }
}

/**
 * Revoke all refresh tokens for a user
 */
export async function revokeAllUserTokens(userId) {
  try {
    // Query all tokens for user using GSI
    const queryCommand = new QueryCommand({
      TableName: REFRESH_TOKENS_TABLE,
      IndexName: 'user_id-index',
      KeyConditionExpression: 'user_id = :userId',
      ExpressionAttributeValues: {
        ':userId': userId
      }
    });

    const queryResponse = await dbClient.send(queryCommand);
    const tokens = queryResponse.Items || [];

    // Revoke each token
    const revokePromises = tokens
      .filter(token => !token.revoked)
      .map(token => {
        return dbClient.send(new UpdateCommand({
          TableName: REFRESH_TOKENS_TABLE,
          Key: { token_hash: token.token_hash },
          UpdateExpression: 'SET revoked = :revoked',
          ExpressionAttributeValues: {
            ':revoked': true
          }
        }));
      });

    await Promise.all(revokePromises);
    return tokens.length;
  } catch (error) {
    console.error('Error revoking all user tokens:', error);
    throw error;
  }
}

/**
 * Clean expired tokens (manually - DynamoDB TTL handles this automatically)
 * This function is mostly for manual cleanup or reporting
 */
export async function cleanExpiredTokens() {
  try {
    const now = new Date();
    let deletedCount = 0;
    let lastEvaluatedKey = undefined;

    do {
      const scanCommand = new ScanCommand({
        TableName: REFRESH_TOKENS_TABLE,
        FilterExpression: 'expires_at < :now',
        ExpressionAttributeValues: {
          ':now': now.toISOString()
        },
        ExclusiveStartKey: lastEvaluatedKey
      });

      const scanResponse = await dbClient.send(scanCommand);
      const expiredTokens = scanResponse.Items || [];

      // Delete expired tokens
      const deletePromises = expiredTokens.map(token => {
        return dbClient.send(new DeleteCommand({
          TableName: REFRESH_TOKENS_TABLE,
          Key: { token_hash: token.token_hash }
        }));
      });

      await Promise.all(deletePromises);
      deletedCount += expiredTokens.length;

      lastEvaluatedKey = scanResponse.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return deletedCount;
  } catch (error) {
    console.error('Error cleaning expired tokens:', error);
    throw error;
  }
}

/**
 * Limit number of active tokens per user
 */
export async function limitUserTokens(userId, maxTokens = 5) {
  try {
    // Query all active tokens for user
    const queryCommand = new QueryCommand({
      TableName: REFRESH_TOKENS_TABLE,
      IndexName: 'user_id-index',
      KeyConditionExpression: 'user_id = :userId',
      FilterExpression: 'revoked = :revoked',
      ExpressionAttributeValues: {
        ':userId': userId,
        ':revoked': false
      }
    });

    const queryResponse = await dbClient.send(queryCommand);
    const tokens = queryResponse.Items || [];

    // Sort by created_at (newest first)
    tokens.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    // If user has more than maxTokens, revoke the oldest ones
    if (tokens.length >= maxTokens) {
      const tokensToRevoke = tokens.slice(maxTokens - 1);

      const revokePromises = tokensToRevoke.map(token => {
        return dbClient.send(new UpdateCommand({
          TableName: REFRESH_TOKENS_TABLE,
          Key: { token_hash: token.token_hash },
          UpdateExpression: 'SET revoked = :revoked',
          ExpressionAttributeValues: {
            ':revoked': true
          }
        }));
      });

      await Promise.all(revokePromises);
      return tokensToRevoke.length;
    }

    return 0;
  } catch (error) {
    console.error('Error limiting user tokens:', error);
    throw error;
  }
}

/**
 * Get all active tokens for a user (optional - for admin/debugging)
 */
export async function getUserTokens(userId) {
  try {
    const command = new QueryCommand({
      TableName: REFRESH_TOKENS_TABLE,
      IndexName: 'user_id-index',
      KeyConditionExpression: 'user_id = :userId',
      FilterExpression: 'revoked = :revoked',
      ExpressionAttributeValues: {
        ':userId': userId,
        ':revoked': false
      }
    });

    const response = await dbClient.send(command);
    return response.Items || [];
  } catch (error) {
    console.error('Error getting user tokens:', error);
    throw error;
  }
}