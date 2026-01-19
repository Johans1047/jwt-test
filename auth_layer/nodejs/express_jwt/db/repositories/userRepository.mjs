// layers/auth-layer/nodejs/db/repositories/userRepository.js
import { 
  PutCommand, 
  GetCommand, 
  QueryCommand,
  UpdateCommand,
  DeleteCommand
} from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { dbClient, USERS_TABLE } from '../config.mjs';

/**
 * Get user by ID
 */
export async function getUserById(id) {
  try {
    const command = new GetCommand({
      TableName: USERS_TABLE,
      Key: { id }
    });

    const response = await dbClient.send(command);
    return response.Item || null;
  } catch (error) {
    console.error('Error getting user by ID:', error);
    throw error;
  }
}

/**
 * Get user by email using GSI
 */
export async function getUserByEmail(email) {
  try {
    const command = new QueryCommand({
      TableName: USERS_TABLE,
      IndexName: 'email-index',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: {
        ':email': email
      },
      Limit: 1
    });

    const response = await dbClient.send(command);
    return response.Items && response.Items.length > 0 ? response.Items[0] : null;
  } catch (error) {
    console.error('Error getting user by email:', error);
    throw error;
  }
}

/**
 * Create new user
 */
export async function createUser(userData) {
  try {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const hashedPassword = await bcrypt.hash(userData.password, 10);

    const newUser = {
      id,
      email: userData.email,
      password: hashedPassword,
      name: userData.name,
      created_at: timestamp,
      updated_at: timestamp
    };

    const command = new PutCommand({
      TableName: USERS_TABLE,
      Item: newUser,
      ConditionExpression: 'attribute_not_exists(id)' // Prevent overwrites
    });

    await dbClient.send(command);

    // Return user without password
    const { password, ...userWithoutPassword } = newUser;
    return userWithoutPassword;
  } catch (error) {
    console.error('Error creating user:', error);
    throw error;
  }
}

/**
 * Update user (optional - for future use)
 */
export async function updateUser(id, updates) {
  try {
    const timestamp = new Date().toISOString();
    
    // Build update expression dynamically
    const updateExpressions = [];
    const expressionAttributeNames = {};
    const expressionAttributeValues = {
      ':updated_at': timestamp
    };

    Object.keys(updates).forEach((key) => {
      if (key !== 'id' && key !== 'created_at') {
        updateExpressions.push(`#${key} = :${key}`);
        expressionAttributeNames[`#${key}`] = key;
        expressionAttributeValues[`:${key}`] = updates[key];
      }
    });

    updateExpressions.push('#updated_at = :updated_at');
    expressionAttributeNames['#updated_at'] = 'updated_at';

    const command = new UpdateCommand({
      TableName: USERS_TABLE,
      Key: { id },
      UpdateExpression: `SET ${updateExpressions.join(', ')}`,
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
      ReturnValues: 'ALL_NEW'
    });

    const response = await dbClient.send(command);
    return response.Attributes;
  } catch (error) {
    console.error('Error updating user:', error);
    throw error;
  }
}

/**
 * Delete user (optional - for future use)
 */
export async function deleteUser(id) {
  try {
    const command = new DeleteCommand({
      TableName: USERS_TABLE,
      Key: { id }
    });

    await dbClient.send(command);
    return true;
  } catch (error) {
    console.error('Error deleting user:', error);
    throw error;
  }
}