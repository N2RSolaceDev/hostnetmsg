require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const xss = require('xss');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secure_32_char_secret_minimum';

// In-memory storage (no MongoDB for messages)
const users = new Map(); // email → { password, fullName, avatar }
const sessions = new Map(); // token → email
const messages = new Map(); // msgId → { from, to, subject, content, timestamp, read }
const onlineUsers = new Set();

// HTTP + WebSocket Server
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Generate ID
function genId() {
  return require('crypto').randomBytes(16).toString('hex');
}

// Password hashing
async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

// Verify password
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Auth Middleware
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    req.user = user;
    next();
  });
}

// 🔐 Register (only @unfiltereduk.co.uk)
app.post('/api/register', async (req, res) => {
  const { email, password, fullName } = req.body;
  const normalized = email.toLowerCase().trim();

  if (!normalized.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ error: 'Only @unfiltereduk.co.uk allowed.' });
  }

  if (users.has(normalized)) {
    return res.status(400).json({ error: 'Email already taken.' });
  }

  const hash = await hashPassword(password);
  users.set(normalized, {
    password: hash,
    fullName: xss(fullName),
    avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${normalized.split('@')[0]}`
  });

  res.json({ message: 'Registered. Please login.' });
});

// 🔐 Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const normalized = email.toLowerCase().trim();
  const userData = users.get(normalized);

  if (!userData) return res.status(401).json({ error: 'Invalid credentials.' });

  const valid = await verifyPassword(password, userData.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials.' });

  const token = jwt.sign({ email: normalized }, JWT_SECRET, { expiresIn: '1d' });
  sessions.set(token, normalized);

  res.json({
    token,
    email: normalized,
    fullName: userData.fullName,
    avatar: userData.avatar
  });
});

// 📥 Get Profile
app.get('/api/profile', authenticateToken, (req, res) => {
  const data = users.get(req.user.email);
  if (!data) return res.status(404).json({ error: 'User not found.' });
  res.json(data);
});

// WebSocket Server
wss.on('connection', (ws) => {
  let userEmail = null;

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      const type = msg.type;

      // Authenticate
      if (type === 'auth') {
        jwt.verify(msg.token, JWT_SECRET, (err, user) => {
          if (err) return ws.send(JSON.stringify({ type: 'error', message: 'Auth failed.' }));
          userEmail = user.email;
          onlineUsers.add(userEmail);
          broadcastStatus();
          // Send unread count
          const unread = Array.from(messages.values())
            .filter(m => m.to === userEmail && !m.read)
            .map(m => ({ id: m.id, from: m.from, subject: m.subject, timestamp: m.timestamp }));
          ws.send(JSON.stringify({ type: 'inbox', data: unread }));
        });
        return;
      }

      if (!userEmail) return ws.send(JSON.stringify({ type: 'error', message: 'Authenticate first.' }));

      // Send message
      if (type === 'send') {
        const { to, subject, content } = msg;
        const newMsg = {
          id: genId(),
          from: userEmail,
          to,
          subject: xss(subject),
          content: xss(content),
          timestamp: new Date().toISOString(),
          read: false
        };

        messages.set(newMsg.id, newMsg);

        // Deliver if online
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN && client.userEmail === to) {
            client.send(JSON.stringify({ type: 'new_message', data: newMsg }));
          }
        });

        ws.send(JSON.stringify({ type: 'sent', id: newMsg.id }));
      }

      // Read message (show once, then delete)
      if (type === 'read') {
        const message = messages.get(msg.id);
        if (message && message.to === userEmail && !message.read) {
          message.read = true;
          // Delete after read (Snapchat-style)
          setTimeout(() => {
            messages.delete(msg.id);
            // Notify sender
            wss.clients.forEach(client => {
              if (client.readyState === WebSocket.OPEN && client.userEmail === message.from) {
                client.send(JSON.stringify({ type: 'deleted', id: msg.id }));
              }
            });
          }, 100);
        }
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message.' }));
    }
  });

  ws.on('close', () => {
    if (userEmail) {
      onlineUsers.delete(userEmail);
      broadcastStatus();
    }
  });
});

// Broadcast online users
function broadcastStatus() {
  const data = { type: 'online', users: Array.from(onlineUsers) };
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

// Start server
server.listen(PORT, () => {
  console.log(`🔐 HostNet running on port ${PORT}`);
  console.log(`🔗 Connect to https://yourdomain.com`);
});
