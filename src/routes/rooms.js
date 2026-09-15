const express = require('express');
const { body } = require('express-validator');
const { requireAuth } = require('../middleware/auth');
const { loadRoom, requireRoomMembership } = require('../middleware/roomAccess');
const { apiLimiter } = require('../middleware/rateLimiter');
const { validate } = require('../middleware/validate');
const { asyncHandler } = require('../utils/asyncHandler');
const roomController = require('../controllers/roomController');
const messagesRouter = require('./messages');

const router = express.Router();
router.use(requireAuth, apiLimiter);

router.get('/', asyncHandler(roomController.listMine));
router.get('/joinable', asyncHandler(roomController.listJoinable));

router.post(
  '/group',
  body('name').trim().isLength({ min: 2, max: 40 }).withMessage('Room name must be 2-40 characters.'),
  validate,
  asyncHandler(roomController.createGroup)
);

router.post(
  '/direct',
  body('userId').trim().notEmpty().withMessage('userId is required.'),
  validate,
  asyncHandler(roomController.startDirect)
);

router.post('/:roomId/join', loadRoom, asyncHandler(roomController.join));
router.post('/:roomId/leave', requireRoomMembership, asyncHandler(roomController.leave));
router.get('/:roomId/members', requireRoomMembership, asyncHandler(roomController.getMembers));
router.use('/:roomId/messages', requireRoomMembership, messagesRouter);

module.exports = router;
