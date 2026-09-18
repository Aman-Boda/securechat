const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const { validate } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../utils/asyncHandler');

const router = express.Router();

const registerValidators = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be 3-20 characters.')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores.'),
  body('email').trim().isEmail().withMessage('Please enter a valid email address.').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters.'),
];

const loginValidators = [
  body('identifier').trim().notEmpty().withMessage('Username or email is required.'),
  body('password').notEmpty().withMessage('Password is required.'),
];

router.post('/register', authLimiter, registerValidators, validate, asyncHandler(authController.register));
router.post('/login', authLimiter, loginValidators, validate, asyncHandler(authController.login));
router.post('/logout', requireAuth, authController.logout);
router.get('/me', requireAuth, authController.me);

router.post(
  '/verify-email',
  authLimiter,
  body('token').isString().notEmpty(),
  validate,
  asyncHandler(authController.verifyEmail)
);
router.post('/resend-verification', authLimiter, requireAuth, asyncHandler(authController.resendVerification));
router.post(
  '/forgot-password',
  authLimiter,
  body('email').trim().isEmail().withMessage('Please enter a valid email address.').normalizeEmail(),
  validate,
  asyncHandler(authController.forgotPassword)
);
router.post(
  '/reset-password',
  authLimiter,
  body('token').isString().notEmpty(),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters.'),
  validate,
  asyncHandler(authController.resetPassword)
);

module.exports = router;
