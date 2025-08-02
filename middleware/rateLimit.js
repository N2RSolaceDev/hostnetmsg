/**
 * middleware/rateLimit.js
 * 
 * Advanced rate limiting for abuse prevention
 * 
 * Protects against brute force, spam, and DDoS-style flooding.
 * Configured exactly like your original server.js.
 * 
 * This isn't just "limiting".  
 * It's digital border control.
 */

const rateLimit = require('express-rate-limit');

/**
 * Limits general API usage
 * Prevents flooding of public endpoints
 */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { 
    error: 'Too many requests from this IP. Please try again later.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  },
  handler: (req, res) => {
    console.warn(`Rate limit exceeded: ${req.ip} -> ${req.method} ${req.url}`);
    res.status(429).json(this.message);
  }
});

/**
 * Limits auth attempts
 * Protects login and register from brute force
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { 
    error: 'Too many login/register attempts. Please try again later.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use IP + email if available to prevent rotating IPs
    const email = req.body?.email?.toLowerCase() || '';
    return `${req.ip}-${email}`;
  },
  handler: (req, res) => {
    console.warn(`Auth rate limit hit: ${req.ip} (${req.body?.email || 'unknown'})`);
    res.status(429).json(this.message);
  }
});

/**
 * Limits admin panel access
 * Only 20 requests per hour from any IP
 */
const adminLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: { 
    error: 'Too many requests to admin routes.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`Admin rate limit hit: ${req.ip}`);
    res.status(429).json(this.message);
  }
});

/**
 * Custom limiter for message sending
 * Prevents spam in chats
 */
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  message: { 
    error: 'Message rate limit exceeded. Slow down.' 
  },
  skipSuccessfulRequests: false
});

/**
 * File upload limiter
 * For future /upload endpoint
 */
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: { 
    error: 'Too many uploads. Please try again later.' 
  }
});

module.exports = {
  apiLimiter,
  authLimiter,
  adminLimiter,
  messageLimiter,
  uploadLimiter
};
