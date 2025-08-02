/**
 * middleware/sanitize.js
 * 
 * HTML Sanitization Middleware
 * 
 * Prevents XSS attacks by stripping dangerous HTML.
 * Uses the `xss` library exactly as in your original server.js.
 * 
 * This is not optional.
 * This is survival.
 */

const xss = require('xss');

/**
 * Sanitizes user input to prevent XSS
 * Removes all HTML tags and encodes dangerous characters
 */
function sanitizeBody(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = sanitizeInput(req.body[key]);
      }
    }
  }
  next();
}

/**
 * Sanitizes a single string input
 * 
 * @param {string} str - Input string
 * @returns {string} - Cleaned string
 */
function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  return xss(str, {
    whiteList: [],                    // No HTML allowed
    stripIgnoreTag: true,             // Remove unknown tags
    escapeHtml: true                  // Escape <, >, &, etc.
  });
}

/**
 * Allows limited HTML formatting (optional)
 * For rich text in future versions
 */
function sanitizeRichInput(str) {
  if (typeof str !== 'string') return str;
  return xss(str, {
    whiteList: {
      'b': [],
      'i': [],
      'u': [],
      'strong': [],
      'em': [],
      'br': [],
      'p': [],
      'span': ['style'],
      'div': ['style'],
      'h1': [], 'h2': [], 'h3': [], 'h4': [], 'h5': [], 'h6': []
    },
    stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
    escapeHtml: true
  });
}

/**
 * Sanitizes entire request query and params
 * Defense in depth
 */
function deepSanitize(req, res, next) {
  // Sanitize query
  if (req.query) {
    for (const key in req.query) {
      if (typeof req.query[key] === 'string') {
        req.query[key] = sanitizeInput(req.query[key]);
      }
    }
  }

  // Sanitize params
  if (req.params) {
    for (const key in req.params) {
      if (typeof req.params[key] === 'string') {
        req.params[key] = sanitizeInput(req.params[key]);
      }
    }
  }

  next();
}

module.exports = {
  sanitizeBody,
  sanitizeInput,
  sanitizeRichInput,
  deepSanitize
};
