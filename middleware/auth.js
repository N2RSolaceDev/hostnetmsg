/**
 * middleware/auth.js
 * 
 * JWT Authentication Middleware
 * 
 * Verifies user tokens on protected routes.
 * Used across /api/* endpoints.
 * 
 * This is real security. Not a wrapper. Not a simulation.
 * Just pure, raw authentication logic — split out so the server stays clean.
 */

const jwt = require('jsonwebtoken');

/**
 * Authenticates JWT token from Authorization header
 * 
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Function} next - Next middleware
 */
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      error: 'Access denied. No token provided.' 
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ 
          error: 'Session expired. Please log in again.' 
        });
      }
      return res.status(403).json({ 
        error: 'Invalid or expired token.' 
      });
    }
    req.user = user;
    next();
  });
}

/**
 * Admin-only middleware
 * 
 * Checks if the authenticated user is solace@unfiltereduk.co.uk
 */
function requireAdmin(req, res, next) {
  if (!req.user || req.user.email !== 'solace@unfiltereduk.co.uk') {
    return res.status(403).json({ 
      error: 'Admin access required.' 
    });
  }
  next();
}

/**
 * Role-based access (future extension)
 * 
 * @param {string} role - Required role
 */
function requireRole(role) {
  return (req, res, next) => {
    // In future: integrate with user.roles
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ 
        error: `This action requires ${role} privileges.` 
      });
    }
    next();
  };
}

module.exports = {
  authenticateToken,
  requireAdmin,
  requireRole
};
