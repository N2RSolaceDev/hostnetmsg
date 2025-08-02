/**
 * generateId.js
 * 
 * Generates a cryptographically secure hex ID.
 * Used for messages, reports, servers, channels, etc.
 * 
 * I wrote this at 3 AM. It works. That’s all I need to know.
 */

const crypto = require('crypto');

module.exports = function generateId() {
  return crypto.randomBytes(16).toString('hex');
};
