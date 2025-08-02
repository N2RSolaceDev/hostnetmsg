/**
 * routes/voice.js
 * 
 * Voice channel management
 * WebRTC-ready
 */

const express = require('express');
const router = express.Router();

// In-memory storage
const voiceRooms = new Map(); // roomId → { serverId, name, users: [], host }

// Join voice room
router.post('/join', (req, res) => {
  const { roomId } = req.body;
  const userId = req.user.email;

  if (!voiceRooms.has(roomId)) {
    return res.status(404).json({ error: 'Voice room not found.' });
  }

  const room = voiceRooms.get(roomId);
  if (!room.users.includes(userId)) {
    room.users.push(userId);
  }

  // Broadcast update
  broadcastVoiceUpdate(roomId);

  res.json({ room, message: 'Joined voice.' });
});

// Leave voice room
router.post('/leave', (req, res) => {
  const { roomId } = req.body;
  const userId = req.user.email;

  const room = voiceRooms.get(roomId);
  if (room) {
    room.users = room.users.filter(u => u !== userId);
    if (room.users.length === 0) {
      voiceRooms.delete(roomId);
    } else {
      broadcastVoiceUpdate(roomId);
    }
  }

  res.json({ message: 'Left voice.' });
});

// Create voice room
router.post('/create', (req, res) => {
  const { serverId, name } = req.body;
  const roomId = 'voice_' + require('../utils/generateId')();

  const room = {
    id: roomId,
    serverId,
    name,
    users: [],
    host: req.user.email,
    createdAt: new Date()
  };

  voiceRooms.set(roomId, room);
  res.json(room);
});

function broadcastVoiceUpdate(roomId) {
  const room = voiceRooms.get(roomId);
  const data = { type: 'voice-update', roomId, users: room?.users || [] };
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

module.exports = router;
