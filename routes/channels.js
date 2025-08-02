/**
 * routes/channels.js
 * 
 * Channel management within servers
 */

const express = require('express');
const router = express.Router();
const generateId = require('../utils/generateId');

// In-memory storage
const channels = require('../models/Channel');
const servers = require('../models/Server');

// Create channel
router.post('/create', (req, res) => {
  const { serverId, name, type = 'text' } = req.body;
  const server = servers.get(serverId);
  if (!server) return res.status(404).json({ error: 'Server not found.' });

  const channelId = generateId();
  const channel = {
    id: channelId,
    name,
    serverId,
    type,
    createdAt: new Date()
  };

  channels.set(channelId, channel);
  server.channels.push(channelId);

  res.json(channel);
});

// Get channels in server
router.get('/server/:serverId', (req, res) => {
  const server = servers.get(req.params.serverId);
  if (!server) return res.status(404).json({ error: 'Server not found.' });

  const serverChannels = server.channels.map(id => channels.get(id)).filter(Boolean);
  res.json(serverChannels);
});

module.exports = router;
