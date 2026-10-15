const { validationResult } = require('express-validator');

// Drop this after a chain of express-validator checks on any route.
// If any check failed, responds 400 with the first, clearest error message
// instead of leaking internal validation details.
function validate(req, res, next) {
  const result = validationResult(req);
  if (result.isEmpty()) return next();

  const firstError = result.array({ onlyFirstError: true })[0];
  return res.status(400).json({ error: firstError.msg });
}

module.exports = { validate };
