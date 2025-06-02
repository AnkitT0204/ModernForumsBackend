const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  // Allow GET requests without authentication
  if (req.method === 'GET') {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
      } catch (err) {
        // Invalid token; proceed without user
        req.user = null;
      }
    } else {
      req.user = null;
    }
    return next();
  }

  // Require authentication for non-GET requests
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};