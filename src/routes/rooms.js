const express = require('express');
const { body } = require('express-validator');
const { requireAuth } = require('../middleware/auth');
const { loadRoom, requireRoomMembership } = require('../middleware/roomAccess');
const { apiLimiter } = require('../middleware/rateLimiter');
const { validate } = require('../middleware/validate');
const { asyncHandler } = require('../utils/asyncHandler');
const roomController = require('../controllers/roomController');
const groupController = require('../controllers/groupController');
const attachmentController = require('../controllers/attachmentController');
const reactionController = require('../controllers/reactionController');
const messagesRouter = require('./messages');

const router = express.Router();
router.use(requireAuth, apiLimiter);

router.get('/', asyncHandler(roomController.listMine));
router.get('/joinable', asyncHandler(roomController.listJoinable));

router.post(
  '/group',
  body('name').trim().isLength({ min: 2, max: 40 }).withMessage('Room name must be 2-40 characters.'),
  body('joinPolicy').optional().isIn(['open', 'invite']).withMessage("joinPolicy must be 'open' or 'invite'."),
  body('historyPolicy').optional().isIn(['after_join', 'full']).withMessage("historyPolicy must be 'after_join' or 'full'."),
  body('key').optional().isObject().withMessage('key must be an object.'),
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
router.post('/:roomId/read', requireRoomMembership, asyncHandler(roomController.markRead));
router.get('/:roomId/members', requireRoomMembership, asyncHandler(roomController.getMembers));
router.post('/:roomId/members', requireRoomMembership, asyncHandler(groupController.addMember));
router.delete('/:roomId/members/:userId', requireRoomMembership, asyncHandler(groupController.removeMember));
router.patch('/:roomId/settings', requireRoomMembership, asyncHandler(groupController.updateSettings));
router.get('/:roomId/keys', requireRoomMembership, asyncHandler(groupController.getMyKeys));
router.get('/:roomId/key-status', requireRoomMembership, asyncHandler(groupController.getKeyStatus));
router.put('/:roomId/keys', requireRoomMembership, asyncHandler(groupController.putKeys));
router.get('/:roomId/attachments/:attachmentId', requireRoomMembership, asyncHandler(attachmentController.download));
router.put('/:roomId/messages/:messageId/reaction', requireRoomMembership, asyncHandler(reactionController.put));
router.delete('/:roomId/messages/:messageId/reaction', requireRoomMembership, asyncHandler(reactionController.del));
router.use('/:roomId/messages', requireRoomMembership, messagesRouter);

module.exports = router;
