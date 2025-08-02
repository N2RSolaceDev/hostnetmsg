/**
 * routes/admin.js
 * 
 * Admin-only routes: reports, bans, API keys
 * Only solace@unfiltereduk.co.uk can access
 */

const express = require('express');
const router = express.Router();

// In-memory storage
const reports = require('../models/Report');
const bans = require('../models/Ban');
const apiKeys = require('../models/ApiKey');
const messages = require('../models/Message');
const generateId = require('../utils/generateId');

// Check if admin
function isAdmin(req, res, next) {
  if (req.user.email !== 'solace@unfiltereduk.co.uk') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// List all reports
router.get('/reports', isAdmin, (req, res) => {
  res.json(Array.from(reports.values()));
});

// Handle report: ignore, accept, delete
router.post('/report/:id/action', isAdmin, (req, res) => {
  const { action } = req.body;
  const report = reports.get(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found.' });

  if (action === 'ignore') {
    report.status = 'ignored';
  } else if (action === 'delete') {
    const message = messages.get(report.messageId);
    if (message) messages.delete(report.messageId);
    report.status = 'resolved';
  } else if (action === 'accept') {
    report.status = 'accepted';
  } else {
    return res.status(400).json({ error: 'Invalid action.' });
  }

  res.json({ message: `Report ${action}ed.` });
});

// Take action after accept
router.post('/report/:id/take-action', isAdmin, (req, res) => {
  const { action, duration, reason } = req.body;
  const report = reports.get(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found.' });

  const message = messages.get(report.messageId);
  if (!message) return res.status(404).json({ error: 'Message not found.' });

  const offender = message.from;

  if (action === 'ban') {
    bans.set(offender, {
      reason: reason || 'Violation of rules',
      timestamp: new Date(),
      expiresAt: duration ? new Date(Date.now() + duration * 86400000) : null
    });
    messages.delete(report.messageId);
  } else if (action === 'mute') {
    // Implement mute logic
  } else if (action === 'warn') {
    const warnId = generateId();
    messages.set(warnId, {
      id: warnId,
      from: 'HostNet Admin',
      to: offender,
      body: `You have been warned: ${reason || 'Inappropriate message'}`,
      timestamp: new Date().toISOString()
    });
  }

  report.status = 'resolved';
  res.json({ message: `Action taken: ${action}.` });
});

// Generate API key
router.post('/generate-key', isAdmin, (req, res) => {
  const { partnerName, customFrom, avatar, expiresDays } = req.body;
  const key = 'ukapi_' + require('crypto').randomBytes(32).toString('hex');

  const apiKey = {
    key,
    partnerName,
    customFrom,
    avatar,
    createdBy: req.user.email,
    createdAt: new Date(),
    expiresAt: expiresDays ? new Date(Date.now() + expiresDays * 86400000) : null,
    revoked: false,
    permissions: ['send']
  };

  apiKeys.set(key, apiKey);
  res.json({ message: 'API key generated.', key, from: customFrom });
});

// List API keys
router.get('/keys', isAdmin, (req, res) => {
  res.json(Array.from(apiKeys.values()));
});

// Revoke API key
router.post('/revoke-key', isAdmin, (req, res) => {
  const { key } = req.body;
  const apiKey = apiKeys.get(key);
  if (!apiKey) return res.status(404).json({ error: 'Key not found.' });
  apiKey.revoked = true;
  res.json({ message: 'API key revoked.' });
});

module.exports = router;
