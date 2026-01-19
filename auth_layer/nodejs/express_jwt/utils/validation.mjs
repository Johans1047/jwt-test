import { body } from 'express-validator';
import { handleValidationErrors } from '../helpers/middlewares.mjs';

export const registerValidation = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must be a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  handleValidationErrors
];

export const loginValidation = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must be a valid email address')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

export const refreshTokenValidation = [
  handleValidationErrors
];

// export function validateRequest(validations) {
//   return async (body) => {
//     // Simular req object para express-validator
//     const req = { body };
    
//     for (const validation of validations) {
//       await validation.run(req);
//     }
    
//     const errors = validationResult(req);
//     return errors;
//   };
// }