const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { apiLimiter } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../utils/asyncHandler');
const userController = require('../controllers/userController');

const router = express.Router();
router.use(requireAuth, apiLimiter);

router.get('/search', asyncHandler(userController.search));
router.put('/me/public-key', asyncHandler(userController.setPublicKey));

module.exports = router;
