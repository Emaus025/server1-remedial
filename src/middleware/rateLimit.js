const rateLimit = require('express-rate-limit');
const { saveLog } = require('../models/log');

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 10, // Limit to exactly 10 requests
  skipFailedRequests: true, // Don't count failed requests
  keyGenerator: function (req) {
    // Generate a unique key based on IP and route
    return req.ip + req.baseUrl + req.path;
  },
  message: {
    error: 'Too many requests, please try again later.',
    code: 429
  },
  handler: async (req, res, next) => {
    await saveLog('error', 'Rate limit exceeded', { ip: req.ip }, req);
    res.status(429).json({
      error: 'Too many requests, please try again later.'
    });
  }
});

module.exports = limiter;