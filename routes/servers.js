/**
 * routes/servers.js
 * 
 * Server creation and management
 * Like Discord servers
 */

const express = require('express');
const router = express.Router();
const generateId = require('../utils/generateId');

// In-memory storage
const servers = require('../models/Server');
const channels = require('../models/Channel');

// Create server
router.post('/create', (req, res) => {
  const { name } = req.body;
  const serverId = generateId();

  const server = {
    id: serverId,
    name,
    ownerId: req.user.email,
    members: [req.user.email],
    channels: [],
    createdAt: new Date()
  };

  servers.set(serverId, server);

  // Create default channel
  const channelId = generateId();
  const channel = {
    id: channelId,
    name: 'general',
    serverId,
    type: 'text',
    createdAt: new Date()
  };
  channels.set(channelId, channel);
  server.channels.push(channelId);

  res.json({ server, channel });
});

// Get user's servers
router.get('/my', (req, res) => {
  const userServers = Array.from(servers.values())
    .filter(s => s.members.includes(req.user.email));
  res.json(userServers);
});

// Join server (by invite or public)
router.post('/join/:id', (req, res) => {
  const server = servers.get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });

  if (!server.members.includes(req.user.email)) {
    server.members.push(req.user.email);
  }

  res.json({ message: 'Joined server.' });
});

module.exports = router;
