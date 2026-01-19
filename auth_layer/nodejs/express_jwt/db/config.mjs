import 'dotenv/config';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';

// Initialize DynamoDB Client
const client = new DynamoDBClient({ 
  region: process.env.AWS_REG || 'us-east-1' 
});

export const dbClient = DynamoDBDocumentClient.from(client);

// Table names from environment variables
export const USERS_TABLE = process.env.USERS_TABLE || 'HQ_Users';
export const REFRESH_TOKENS_TABLE = process.env.REFRESH_TOKENS_TABLE || 'HQ_RefreshTokens';