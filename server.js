const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));
const PORT = process.env.PORT || 3001;
const INACTIVITY_LIMIT_MS = 15 * 60 * 1000;
const users = new Map();
const sessions = new Map();
let messages = [];

function now() {
  return Date.now();
}

function genToken() {
  return crypto.randomBytes(24).toString('hex');
}

function touchUser(username) {
  const u = users.get(username);
  if (u) u.lastActive = now();
}

function touchSession(token) {
  const s = sessions.get(token);
  if (s) {
    s.lastActive = now();
    touchUser(s.username);
  }
}

function getUserFromToken(token) {
  const s = sessions.get(token);
  if (!s) return null;
  return s.username;
}

function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  touchSession(token);
  req.username = sessions.get(token).username;
  next();
}

function publicUser(u) {
  return {
    username: u.username,
    friends: Array.from(u.friends),
  };
}

function sweep() {
  const cutoff = now() - INACTIVITY_LIMIT_MS;

  for (const [token, s] of sessions) {
    if (s.lastActive < cutoff) sessions.delete(token);
  }

  for (const [username, u] of users) {
    if (u.lastActive < cutoff) {
      users.delete(username);
      for (const other of users.values()) {
        other.friends.delete(username);
      }
    }
  }

  messages = messages.filter((m) => {
    if (m.ts < cutoff) return false;
    if (!users.has(m.from) || !users.has(m.to)) return false;
    return true;
  });
}

setInterval(sweep, 5000);

app.post('/create', async (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  const cleanUsername = username.trim();
  if (cleanUsername.length < 3 || cleanUsername.length > 20) {
    return res.status(400).json({ error: 'Username must be 3-20 characters.' });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername)) {
    return res.status(400).json({ error: 'Username may only contain letters, numbers, underscores.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  if (users.has(cleanUsername)) {
    return res.status(409).json({ error: 'Username already taken.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.set(cleanUsername, {
    username: cleanUsername,
    passwordHash,
    lastActive: now(),
    friends: new Set(),
  });

  const token = genToken();
  sessions.set(token, { username: cleanUsername, lastActive: now() });

  res.json({ token, user: publicUser(users.get(cleanUsername)) });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  const u = users.get(username.trim());
  if (!u) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  touchUser(u.username);
  const token = genToken();
  sessions.set(token, { username: u.username, lastActive: now() });

  res.json({ token, user: publicUser(u) });
});

app.post('/logout', requireAuth, (req, res) => {
  const token = req.headers['x-session-token'];
  sessions.delete(token);
  res.json({ ok: true });
});

app.post('/heartbeat', requireAuth, (req, res) => {
  res.json({ ok: true, serverTime: now() });
});

app.post('/addfriend', requireAuth, (req, res) => {
  const { username } = req.body || {};
  if (typeof username !== 'string' || !username.trim()) {
    return res.status(400).json({ error: 'Username required.' });
  }
  const target = username.trim();

  if (target === req.username) {
    return res.status(400).json({ error: "You can't add yourself." });
  }
  if (!users.has(target)) {
    return res.status(404).json({ error: 'No such user (they may be offline/expired).' });
  }

  const me = users.get(req.username);
  const them = users.get(target);
  me.friends.add(target);
  them.friends.add(req.username);

  res.json({ ok: true, friends: Array.from(me.friends) });
});

app.get('/friends', requireAuth, (req, res) => {
  const me = users.get(req.username);
  res.json({ friends: Array.from(me.friends) });
});

app.post('/send', requireAuth, (req, res) => {
  const { to, ciphertext, iv } = req.body || {};
  if (typeof to !== 'string' || typeof ciphertext !== 'string' || typeof iv !== 'string') {
    return res.status(400).json({ error: 'to, ciphertext, and iv are required.' });
  }
  if (!users.has(to)) {
    return res.status(404).json({ error: 'Recipient not found (may be offline/expired).' });
  }
  const me = users.get(req.username);
  if (!me.friends.has(to)) {
    return res.status(403).json({ error: 'You must both be added as friends to message.' });
  }

  const msg = {
    id: crypto.randomUUID(),
    from: req.username,
    to,
    ciphertext,
    iv,
    ts: now(),
    delivered: false,
  };
  messages.push(msg);

  res.json({ ok: true, id: msg.id });
});

app.get('/receive', requireAuth, (req, res) => {
  const inbox = messages.filter((m) => m.to === req.username && !m.delivered);
  inbox.forEach((m) => (m.delivered = true));

  res.json({
    messages: inbox.map((m) => ({
      id: m.id,
      from: m.from,
      ciphertext: m.ciphertext,
      iv: m.iv,
      ts: m.ts,
    })),
  });
});

app.post('/request', requireAuth, (req, res) => {
  const since = Number(req.body?.since) || 0;
  const me = users.get(req.username);

  const relevant = messages.filter(
    (m) => (m.to === req.username || m.from === req.username) && m.ts > since
  );
  relevant.forEach((m) => (m.delivered = true));

  res.json({
    serverTime: now(),
    friends: Array.from(me.friends),
    messages: relevant.map((m) => ({
      id: m.id,
      from: m.from,
      to: m.to,
      ciphertext: m.ciphertext,
      iv: m.iv,
      ts: m.ts,
    })),
  });
});

app.get('/history', requireAuth, (req, res) => {
  const relevant = messages.filter(
    (m) => m.to === req.username || m.from === req.username
  );

  res.json({
    serverTime: now(),
    messages: relevant.map((m) => ({
      id: m.id,
      from: m.from,
      to: m.to,
      ciphertext: m.ciphertext,
      iv: m.iv,
      ts: m.ts,
    })),
  });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', users: users.size, messages: messages.length });
});

app.listen(PORT, () => {
  console.log(`nChat server running on http://localhost:${PORT}`);
});