const express = require('express');
const { body } = require('express-validator');
const { validate } = require('../middleware/validate');
const { asyncHandler } = require('../utils/asyncHandler');
const messageController = require('../controllers/messageController');

// mergeParams lets this router read :roomId from the parent router (rooms.js).
// Auth + room-membership checks are applied by the parent before this mounts.
const router = express.Router({ mergeParams: true });

const validators = [
  body('content').isString().withMessage('content is required.'),
  body('iv').optional().isString().withMessage('iv must be a string.'),
  body('epochIndex').optional().isInt({ min: 0 }).withMessage('epochIndex must be a non-negative integer.'),
  body('senderEpochPublicKey').optional().isObject().withMessage('senderEpochPublicKey must be an object.'),
  body('keyMode').optional().isIn(['mutual', 'identity']).withMessage("keyMode must be 'mutual' or 'identity'."),
];

router.get('/', asyncHandler(messageController.history));
router.post('/', validators, validate, asyncHandler(messageController.send));
router.patch('/:messageId', validators, validate, asyncHandler(messageController.edit));
router.delete('/:messageId', asyncHandler(messageController.del));

module.exports = router;
