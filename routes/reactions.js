/**
 * routes/reactions.js
 * 
 * Message reactions (emojis)
 */

const express = require('express');
const router = express.Router();

// In-memory storage
const reactions = new Map(); // msgId:emoji → user[]

// Add reaction
router.post('/add', (req, res) => {
  const { messageId, emoji } = req.body;
  const userId = req.user.email;
  const key = `${messageId}:${emoji}`;

  if (!reactions.has(key)) {
    reactions.set(key, []);
  }

  const users = reactions.get(key);
  if (!users.includes(userId)) {
    users.push(userId);
  }

  broadcastReaction({ messageId, emoji, user: userId });
  res.json({ message: 'Reaction added.' });
});

// Remove reaction
router.post('/remove', (req, res) => {
  const { messageId, emoji } = req.body;
  const userId = req.user.email;
  const key = `${messageId}:${emoji}`;

  if (reactions.has(key)) {
    const users = reactions.get(key);
    reactions.set(key, users.filter(u => u !== userId));
  }

  res.json({ message: 'Reaction removed.' });
});

function broadcastReaction(data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'reaction', data }));
    }
  });
}

module.exports = router;
