/**
 * routes/users.js
 * 
 * User profile and lookup routes
 * Supports both real users and API key identities
 */

const express = require('express');
const router = express.Router();

// In-memory storage
const users = require('../models/User');
const apiKeys = require('../models/ApiKey');

// Get current user profile
router.get('/profile', (req, res) => {
  const user = users.get(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const { password, ...safeUser } = user;
  res.json(safeUser);
});

// Update profile
router.post('/profile', (req, res) => {
  const user = users.get(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const { fullName, avatar } = req.body;
  if (fullName) user.fullName = fullName.trim();
  if (avatar) user.avatar = avatar;

  res.json({ message: 'Profile updated.' });
});

// Lookup user by email (for autocomplete, mentions)
router.get('/email/:email', (req, res) => {
  const email = req.params.email.toLowerCase();
  const localPart = email.split('@')[0];

  // Check API keys first
  for (let [key, apiKey] of apiKeys) {
    if ((apiKey.customFrom && apiKey.customFrom === email) || 
        apiKey.partnerName === localPart) {
      if (!apiKey.revoked && (!apiKey.expiresAt || apiKey.expiresAt > new Date())) {
        return res.json({
          fullName: apiKey.partnerName,
          avatar: apiKey.avatar || null
        });
      }
    }
  }

  // Check real users
  const user = users.get(email);
  if (user) {
    const { password, ...safeUser } = user;
    return res.json(safeUser);
  }

  res.status(404).json({ error: 'User not found.' });
});

module.exports = router;
