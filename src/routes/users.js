const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { apiLimiter } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../utils/asyncHandler');
const userController = require('../controllers/userController');

const router = express.Router();
router.use(requireAuth, apiLimiter);

router.get('/search', asyncHandler(userController.search));
router.put('/me/public-key', asyncHandler(userController.setPublicKey));
router.put('/me/epoch-key', asyncHandler(userController.setEpochKey));
router.get('/:userId/epoch-key/:epochIndex', asyncHandler(userController.getEpochKey));
router.put('/me/security-mode', asyncHandler(userController.setSecurityMode));
router.put('/me/key-backup', asyncHandler(userController.setKeyBackup));
router.get('/me/key-backup', asyncHandler(userController.getKeyBackup));

module.exports = router;
