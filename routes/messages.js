/**
 * routes/messages.js
 * 
 * Messaging routes: Send, inbox, read, delete
 * No MongoDB for messages — all in RAM
 */

const express = require('express');
const router = express.Router();
const { sanitizeInput } = require('../utils/sanitize');
const wss = require('../server').wss; // Access WebSocket server

// In-memory storage
const messages = require('../models/Message');
const generateId = require('../utils/generateId');

// Send message
router.post('/send', (req, res) => {
  const { to, subject, body, channel } = req.body;
  const from = req.user.email;

  if (!to && !channel) return res.status(400).json({ error: 'Recipient required.' });
  if (!body || body.trim().length === 0) return res.status(400).json({ error: 'Message body required.' });

  const msgId = generateId();
  const message = {
    id: msgId,
    from,
    to,
    channel,
    subject: subject || '(No subject)',
    body: sanitizeInput(body),
    timestamp: new Date().toISOString(),
    read: false
  };

  messages.set(msgId, message);

  // Deliver via WebSocket
  broadcastMessage(message);

  res.json({ id: msgId, message: 'Sent' });
});

// Get inbox
router.get('/inbox', (req, res) => {
  const userMsgs = Array.from(messages.values())
    .filter(m => m.to === req.user.email)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  res.json(userMsgs);
});

// Get single message
router.get('/:id', (req, res) => {
  const msg = messages.get(req.params.id);
  if (!msg || msg.to !== req.user.email) return res.status(404).json({ error: 'Not found.' });
  msg.read = true;
  res.json(msg);
});

// Delete message
router.delete('/:id', (req, res) => {
  const msg = messages.get(req.params.id);
  if (!msg || (msg.to !== req.user.email && msg.from !== req.user.email)) {
    return res.status(404).json({ error: 'Not found.' });
  }
  messages.delete(req.params.id);
  res.json({ message: 'Deleted' });
});

// Broadcast to WebSocket clients
function broadcastMessage(msg) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && (client.userEmail === msg.to || client.userEmail === msg.from)) {
      client.send(JSON.stringify({ type: 'message', data: msg }));
    }
  });
}

module.exports = router;
