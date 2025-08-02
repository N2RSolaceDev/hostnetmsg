/**
 * routes/auth.js
 * 
 * Authentication routes: Register & Login
 * Only allows @unfiltereduk.co.uk emails
 * Uses JWT + bcrypt
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();

// In-memory storage (no MongoDB for messages)
const users = require('../models/User');

// Register
router.post('/register', async (req, res) => {
  const { email, password, fullName } = req.body;
  const normalized = email.toLowerCase().trim();

  if (!normalized.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ 
      error: 'Only @unfiltereduk.co.uk email addresses are allowed.' 
    });
  }

  if (users.has(normalized)) {
    return res.status(400).json({ 
      error: 'This email or identity is already taken.' 
    });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({ 
      error: 'Password must be at least 6 characters.' 
    });
  }

  if (!fullName || fullName.trim().length === 0) {
    return res.status(400).json({ 
      error: 'Full name is required.' 
    });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    users.set(normalized, {
      email: normalized,
      password: hashed,
      fullName: fullName.trim(),
      avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${normalized.split('@')[0]}`,
      createdAt: new Date()
    });

    const token = jwt.sign({ email: normalized }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email: normalized });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed.' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email.toLowerCase().trim());
  if (!user) return res.status(400).json({ error: 'Invalid credentials.' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials.' });

  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});

module.exports = router;
