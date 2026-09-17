const express = require('express');
const { body } = require('express-validator');
const { validate } = require('../middleware/validate');
const { asyncHandler } = require('../utils/asyncHandler');
const messageController = require('../controllers/messageController');

// mergeParams lets this router read :roomId from the parent router (rooms.js).
// Auth + room-membership checks are applied by the parent before this mounts.
const router = express.Router({ mergeParams: true });

router.get('/', asyncHandler(messageController.history));
router.post(
  '/',
  body('content').isString().withMessage('content is required.'),
  body('iv').optional().isString().withMessage('iv must be a string.'),
  validate,
  asyncHandler(messageController.send)
);
router.patch(
  '/:messageId',
  body('content').isString().withMessage('content is required.'),
  body('iv').optional().isString().withMessage('iv must be a string.'),
  validate,
  asyncHandler(messageController.edit)
);
router.delete('/:messageId', asyncHandler(messageController.del));

module.exports = router;
