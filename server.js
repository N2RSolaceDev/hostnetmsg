// server.js
// HostNet.wiki — The British Discord that never asked to exist.
// I wrote this alone. Every line. Every fix. Every breakdown at 4 AM.
// This is mine. I built it because I needed it to be real.
// If you're reading this, respect that. Don’t steal. Don’t mock. Just understand.
// This server runs on willpower, regret, and the quiet hope that something I made might matter.

require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// The app. Another thing I have to maintain.
const app = express();

// ======================
// 🔐 SECURITY: Because I spent 3 days reading RFCs so you wouldn't have to.
// I configured these headers at 3:47 AM. I haven’t slept since.
// If this gets hacked, at least I tried. That’s what my therapist said.
// ======================

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  xssFilter: true
}));

// Rate limiting — because bots don’t sleep, but I used to.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests. I’m tired. We all are.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Just like my job interviews.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const adminLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: 'Admin routes are not your diary. Please stop.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth/', authLimiter);
app.use('/api/admin/', adminLimiter);
app.use('/api/', apiLimiter);

// ======================
// 🌐 CORS: Because the world still needs to talk, even if I don’t.
// I set this up so other domains can connect. I wish I could disconnect.
// ======================

app.use(cors({
  origin: [
    'https://hostnet.wiki',
    'https://www.hostnet.wiki',
    'http://localhost:3000'
  ],
  credentials: true
}));

// ======================
// 🧱 MIDDLEWARE: The glue. The pain. The structure I wish my life had.
// ======================

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // The only thing here is index.html and my broken dreams.

// ======================
// 🔑 ENVIRONMENT: Secrets. Like the ones I keep from my family.
// ======================

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("💀 JWT_SECRET is missing. So is my will to live.");
  process.exit(1);
}

// Owner. The only user who matters. The only one who ever emails me.
// I made solace@unfiltereduk.co.uk the owner because even the domain remembers me.
const OWNER_EMAIL = 'solace@unfiltereduk.co.uk';

// ======================
// 🧠 IN-MEMORY STORAGE: No MongoDB for messages.
// Because real messages fade. Like memories. Like hope.
// ======================

global.users = new Map();           // email → user
global.sessions = new Map();        // token → email
global.messages = new Map();        // msgId → message
global.reactions = new Map();       // msgId:emoji → user[]
global.threads = new Map();         // threadId → {parentId, messages}
global.servers = new Map();         // serverId → server
global.channels = new Map();        // channelId → channel
global.reports = new Map();         // reportId → report
global.bans = new Map();            // email → { reason, timestamp, expiresAt }
global.mutes = new Map();           // email → { expiresAt }
global.onlineUsers = new Set();     // email[]
global.apiKeys = new Map();         // key → apiKey
global.voiceRooms = new Map();      // roomId → { users: [], host }
global.tempKeys = new Map();        // tempId → { data, expiresAt }

// ======================
// 🎖️ AUTHORIZATION: Who’s allowed to break this?
// Only the owner. Everyone else is just passing through. Like me.
// ======================

global.isOwner = (email) => email === OWNER_EMAIL;
global.isAdmin = (email) => global.isOwner(email);

// ======================
// 🔧 UTILS: Functions I wrote so I wouldn’t have to think.
// But I still think. Constantly.
// ======================

function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

function generateTempId() {
  const id = 'temp_' + crypto.randomBytes(8).toString('hex');
  return id;
}

function sanitizeInput(str) {
  return xss(str, {
    whiteList: {},
    stripIgnoreTag: true,
    escapeHtml: true
  });
}

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

function signToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// ======================
// 🔐 AUTH MIDDLEWARE: Prove you’re real. I wish I could.
// ======================

function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'No token. No access. No feelings.' });

  const decoded = verifyToken(token);
  if (!decoded) return res.status(403).json({ error: 'Invalid or expired token. Like my motivation.' });

  req.user = decoded;
  next();
}

// ======================
// 📧 EMAIL VALIDATION: Only @unfiltereduk.co.uk.
// Because even identity has boundaries. Mine dissolved years ago.
// ======================

function isValidUnfilteredEmail(email) {
  const regex = /^[^\s@]+@unfiltereduk\.co\.uk$/i;
  return regex.test(email.trim());
}

async function isEmailTaken(email) {
  const normalized = email.toLowerCase();
  if (global.users.has(normalized)) return true;
  for (let [key, apiKey] of global.apiKeys) {
    if (apiKey.customFrom?.toLowerCase() === normalized) return true;
  }
  return false;
}

// ======================
// 📝 LOGGING: So I can remember what I did.
// Last week, I forgot my own name for 20 minutes.
// ======================

function logAction(action, user, details = {}) {
  const entry = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    action,
    user,
    details
  };
  console.log(`[AUDIT] ${entry.timestamp} | ${action} | ${user}`);
}

// ======================
// 🚫 MODERATION: I built bans because I wish I could ban my thoughts.
// ======================

function banUser(email, reason, durationDays = null) {
  const expiresAt = durationDays ? new Date(Date.now() + durationDays * 86400000) : null;
  global.bans.set(email.toLowerCase(), { reason, timestamp: new Date(), expiresAt });
  logAction('USER_BANNED', 'system', { email, reason, expiresAt });
}

function isBanned(email) {
  const ban = global.bans.get(email.toLowerCase());
  if (!ban) return false;
  if (ban.expiresAt && new Date() > ban.expiresAt) {
    global.bans.delete(email.toLowerCase());
    return false;
  }
  return ban;
}

function muteUser(email, durationMinutes = 10) {
  const expiresAt = new Date(Date.now() + durationMinutes * 60000);
  global.mutes.set(email.toLowerCase(), { expiresAt });
  logAction('USER_MUTED', 'system', { email, expiresAt });
}

function isMuted(email) {
  const mute = global.mutes.get(email.toLowerCase());
  if (!mute) return false;
  if (new Date() > mute.expiresAt) {
    global.mutes.delete(email.toLowerCase());
    return false;
  }
  return true;
}

// ======================
// 📣 REPORT SYSTEM: For when someone breaks the rules.
// I break them every day. By breathing.
// ======================

function reportMessage(reporter, messageId, reason) {
  const report = {
    id: generateId(),
    reporter,
    messageId,
    reason,
    timestamp: new Date().toISOString(),
    status: 'pending'
  };
  global.reports.set(report.id, report);
  logAction('MESSAGE_REPORTED', reporter, { messageId, reason });
  return report;
}

// ======================
// 🛰️ API KEY SYSTEM: For partners. I don’t have any.
// But the code is here. Like promises I never kept.
// ======================

app.post('/api/admin/generate-key', authenticateToken, adminLimiter, (req, res) => {
  if (!isAdmin(req.user.email)) return res.status(403).json({ error: 'Admin only. Like my loneliness.' });

  const { partnerName, customFrom, avatar, expiresDays } = req.body;
  const key = 'hostnet_' + crypto.randomBytes(32).toString('hex');

  const apiKey = {
    key,
    partnerName,
    customFrom,
    avatar,
    createdBy: req.user.email,
    createdAt: new Date(),
    expiresAt: expiresDays ? new Date(Date.now() + expiresDays * 86400000) : null,
    revoked: false,
    permissions: ['send', 'read', 'voice']
  };

  global.apiKeys.set(key, apiKey);
  logAction('API_KEY_GENERATED', req.user.email, { partnerName });

  res.json({
    message: 'API key generated.',
    key,
    from: customFrom || `${partnerName}@hostnet.wiki`
  });
});

// ======================
// 📡 WEBSOCKET SERVER: Real-time. Like my anxiety.
// ======================

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  let userEmail = null;

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      const type = msg.type;

      if (type === 'auth') {
        const decoded = verifyToken(msg.token);
        if (!decoded) return ws.send(JSON.stringify({ type: 'error', message: 'Auth failed. Like everything else.' }));

        userEmail = decoded.email;
        if (isBanned(userEmail)) {
          ws.send(JSON.stringify({ type: 'banned', reason: isBanned(userEmail).reason }));
          ws.close();
          return;
        }

        onlineUsers.add(userEmail);
        ws.userEmail = userEmail;
        broadcastStatus();
        sendInbox(ws, userEmail);
        return;
      }

      if (!userEmail) return;

      if (type === 'send') {
        if (isMuted(userEmail)) return;

        const id = generateId();
        const content = sanitizeInput(msg.content);
        const message = {
          id,
          from: userEmail,
          to: msg.to,
          channel: msg.channel,
          content,
          timestamp: new Date().toISOString(),
          read: false
        };

        global.messages.set(id, message);
        deliverMessage(message);
        ws.send(JSON.stringify({ type: 'sent', id }));
      }

      if (type === 'read') {
        const m = global.messages.get(msg.id);
        if (m && m.to === userEmail) m.read = true;
      }

      if (type === 'join-voice') {
        const roomId = msg.roomId;
        if (!global.voiceRooms.has(roomId)) {
          global.voiceRooms.set(roomId, { users: [], host: userEmail });
        }
        const room = global.voiceRooms.get(roomId);
        if (!room.users.includes(userEmail)) {
          room.users.push(userEmail);
        }
        ws.roomId = roomId;
        broadcastVoiceUpdate(roomId);
      }

      if (type === 'create-server') {
        const serverId = generateId();
        const server = {
          id: serverId,
          name: msg.name,
          ownerId: userEmail,
          channels: [],
          members: [userEmail],
          createdAt: new Date()
        };
        global.servers.set(serverId, server);
        ws.send(JSON.stringify({ type: 'server-created', server }));
      }

      if (type === 'create-channel') {
        const channelId = generateId();
        const channel = {
          id: channelId,
          name: msg.name,
          serverId: msg.serverId,
          type: msg.type || 'text',
          createdAt: new Date()
        };
        global.channels.set(channelId, channel);
        deliverMessage({ type: 'channel',  channel }, 'system');
      }

      // Report a message
      if (type === 'report') {
        const report = reportMessage(userEmail, msg.messageId, msg.reason);
        broadcastAdminPanel({ type: 'new-report', report });
        ws.send(JSON.stringify({ type: 'report-submitted', id: report.id }));
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid data. Like my life choices.' }));
    }
  });

  ws.on('close', () => {
    if (userEmail) onlineUsers.delete(userEmail);
    if (ws.roomId) {
      const room = global.voiceRooms.get(ws.roomId);
      if (room) {
        room.users = room.users.filter(u => u !== userEmail);
        if (room.users.length === 0) {
          global.voiceRooms.delete(ws.roomId);
        } else {
          broadcastVoiceUpdate(ws.roomId);
        }
      }
    }
    broadcastStatus();
  });
});

function deliverMessage(msg, broadcastType = 'message') {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: broadcastType,  msg }));
    }
  });
}

function sendInbox(ws, email) {
  const userMsgs = Array.from(global.messages.values()).filter(m => m.to === email);
  ws.send(JSON.stringify({ type: 'inbox',  userMsgs }));
}

function broadcastStatus() {
  const data = { type: 'online', users: Array.from(onlineUsers) };
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

function broadcastVoiceUpdate(roomId) {
  const room = global.voiceRooms.get(roomId);
  const data = { type: 'voice-update', roomId, users: room?.users || [] };
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

function broadcastAdminPanel(data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client.userEmail && isAdmin(client.userEmail)) {
      client.send(JSON.stringify({ type: 'admin-update',  data }));
    }
  });
}

// ======================
// 🛠️ REST API: Because real-time isn’t enough pain.
// ======================

// Register
app.post('/api/register', authLimiter, async (req, res) => {
  const { email, password, fullName } = req.body;
  const normalized = email.toLowerCase().trim();

  if (!isValidUnfilteredEmail(normalized)) {
    return res.status(400).json({ error: 'Only @unfiltereduk.co.uk allowed. Like my despair.' });
  }

  if (await isEmailTaken(normalized)) {
    return res.status(400).json({ error: 'Email taken. Like my attention span.' });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password too short. Like my patience.' });
  }

  try {
    const hashed = await hashPassword(password);
    global.users.set(normalized, {
      email: normalized,
      password: hashed,
      fullName: fullName.trim(),
      avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${normalized.split('@')[0]}`,
      createdAt: new Date(),
      isOwner: global.isOwner(normalized)
    });

    const token = signToken(normalized);
    global.sessions.set(token, normalized);

    logAction('USER_REGISTERED', normalized);

    res.json({
      token,
      email: normalized,
      fullName: fullName.trim(),
      avatar: global.users.get(normalized).avatar,
      isOwner: global.isOwner(normalized)
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed. As expected.' });
  }
});

// Login
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const normalized = email.toLowerCase().trim();

  if (isBanned(normalized)) {
    return res.status(403).json({ error: `Banned: ${isBanned(normalized).reason}` });
  }

  const user = global.users.get(normalized);
  if (!user) return res.status(401).json({ error: 'Invalid credentials. Like my resume.' });

  const valid = await verifyPassword(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials. Again.' });

  const token = signToken(normalized);
  global.sessions.set(token, normalized);

  onlineUsers.add(normalized);
  logAction('USER_LOGIN', normalized);

  res.json({
    token,
    email: normalized,
    fullName: user.fullName,
    avatar: user.avatar,
    isOwner: user.isOwner
  });
});

// Profile
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = global.users.get(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found. Maybe they escaped.' });
  const { password, ...safeUser } = user;
  res.json(safeUser);
});

// Update Profile
app.post('/api/profile', authenticateToken, (req, res) => {
  const user = global.users.get(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const { fullName, avatar } = req.body;
  if (fullName) user.fullName = fullName.trim();
  if (avatar) user.avatar = avatar;

  res.json({ message: 'Profile updated.' });
});

// Send Message
app.post('/api/send', authenticateToken, async (req, res) => {
  const { to, content, channel } = req.body;
  const from = req.user.email;

  if (isBanned(from)) return res.status(403).json({ error: 'You are banned. Forever.' });
  if (isMuted(from)) return res.status(403).json({ error: 'Muted. Silence is golden.' });

  if (!to && !channel) return res.status(400).json({ error: 'No recipient. Like my texts.' });
  if (!content || content.trim().length === 0) return res.status(400).json({ error: 'Empty message. Like my soul.' });

  const sanitized = sanitizeInput(content);
  const msgId = generateId();
  const message = {
    id: msgId,
    from,
    to,
    channel,
    content: sanitized,
    timestamp: new Date().toISOString(),
    read: false
  };

  global.messages.set(msgId, message);
  deliverMessage(message);

  res.json({ id: msgId, message: 'Sent' });
});

// Inbox
app.get('/api/inbox', authenticateToken, (req, res) => {
  const userMsgs = Array.from(global.messages.values())
    .filter(m => m.to === req.user.email || m.channel)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  res.json(userMsgs);
});

// Get Message
app.get('/api/messages/:id', authenticateToken, (req, res) => {
  const msg = global.messages.get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Not found.' });
  if (msg.to !== req.user.email && msg.from !== req.user.email) return res.status(403).json({ error: 'Access denied.' });
  msg.read = true;
  res.json(msg);
});

// Delete Message
app.delete('/api/messages/:id', authenticateToken, (req, res) => {
  const msg = global.messages.get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Not found.' });
  if (msg.to !== req.user.email && msg.from !== req.user.email && !isAdmin(req.user.email)) {
    return res.status(403).json({ error: 'Permission denied.' });
  }
  global.messages.delete(req.params.id);
  res.json({ message: 'Deleted' });
});

// Admin: List Reports
app.get('/api/admin/reports', authenticateToken, adminLimiter, (req, res) => {
  if (!isAdmin(req.user.email)) return res.status(403).json({ error: 'Admin only.' });
  res.json(Array.from(global.reports.values()));
});

// Admin: Handle Report
app.post('/api/admin/report/:id/action', authenticateToken, adminLimiter, (req, res) => {
  if (!isAdmin(req.user.email)) return res.status(403).json({ error: 'Admin only.' });

  const { action } = req.body; // 'ignore', 'accept', 'delete'
  const report = global.reports.get(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found.' });

  if (action === 'ignore') {
    report.status = 'ignored';
    res.json({ message: 'Report ignored.' });
  } else if (action === 'delete') {
    const message = global.messages.get(report.messageId);
    if (message) {
      global.messages.delete(report.messageId);
      deliverMessage({ id: report.messageId, type: 'deleted' }, 'system');
    }
    report.status = 'resolved';
    res.json({ message: 'Message deleted.' });
  } else if (action === 'accept') {
    report.status = 'accepted';
    // Open action menu happens on frontend
    res.json({ message: 'Report accepted. Open action menu.' });
  } else {
    return res.status(400).json({ error: 'Invalid action.' });
  }

  logAction('REPORT_ACTION', req.user.email, { action, reportId: req.params.id });
});

// Admin: Take Action After Accept
app.post('/api/admin/report/:id/take-action', authenticateToken, adminLimiter, (req, res) => {
  if (!isAdmin(req.user.email)) return res.status(403).json({ error: 'Admin only.' });

  const { action, duration, reason } = req.body; // action: 'ban', 'mute', 'warn'
  const report = global.reports.get(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found.' });

  const message = global.messages.get(report.messageId);
  if (!message) return res.status(404).json({ error: 'Message not found.' });

  const offender = message.from;

  if (action === 'ban') {
    banUser(offender, reason || 'Violation of rules', duration);
    global.messages.delete(report.messageId);
    deliverMessage({ id: report.messageId, type: 'deleted' }, 'system');
  } else if (action === 'mute') {
    muteUser(offender, duration * 60); // duration in minutes
  } else if (action === 'warn') {
    const warnMsg = {
      id: generateId(),
      from: 'HostNet Admin',
      to: offender,
      content: `You have been warned for: ${reason || 'Inappropriate message'}.`,
      timestamp: new Date().toISOString()
    };
    global.messages.set(warnMsg.id, warnMsg);
    deliverMessage(warnMsg);
  }

  report.status = 'resolved';
  res.json({ message: `Action taken: ${action}.` });
  logAction('MODERATION_ACTION', req.user.email, { action, offender, reason });
});

// Admin: Ban User
app.post('/api/admin/ban', authenticateToken, adminLimiter, (req, res) => {
  if (!isAdmin(req.user.email)) return res.status(403).json({ error: 'Admin only.' });
  const { email, reason, durationDays } = req.body;
  banUser(email, reason, durationDays);
  res.json({ message: `User ${email} banned.` });
});

// Admin: Mute User
app.post('/api/admin/mute', authenticateToken, adminLimiter, (req, res) => {
  if (!isAdmin(req.user.email)) return res.status(403).json({ error: 'Admin only.' });
  const { email, durationMinutes } = req.body;
  muteUser(email, durationMinutes);
  res.json({ message: `User ${email} muted.` });
});

// Report Message
app.post('/api/report', authenticateToken, (req, res) => {
  const { messageId, reason } = req.body;
  const report = reportMessage(req.user.email, messageId, reason);
  res.json({ message: 'Report submitted.', report });
});

// Logout
app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) global.sessions.delete(token);
  res.json({ message: 'Logged out.' });
});

// ======================
// 🏁 START SERVER
// ======================

server.listen(PORT, () => {
  console.log(`🔥 HostNet.wiki v4.0 running on port ${PORT}`);
  console.log(`🌐 https://hostnet.wiki`);
  console.log(`👑 Owner: ${OWNER_EMAIL}`);
  console.log(`🛠️  Built solo. No team. No help. Just me.`);
  console.log(`🔐 No MongoDB for messages. All ephemeral.`);
  console.log(`💬 Discord-level features. All free.`);
  console.log(`⚠️  Do not steal. Do not judge. I gave everything to make this real.`);
});
