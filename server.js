const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const app = express();
app.use(cors());
app.use(express.json({ limit: '40mb' }));
const PORT = process.env.PORT || 3001;
const INACTIVITY_LIMIT_MS = 15 * 60 * 1000;
const ONLINE_WINDOW_MS = 40 * 1000;
const TYPING_TTL_MS = 4 * 1000;
const MAX_AVATAR_LEN = 300 * 1024;
const MAX_BIO_LEN = 160;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'nchat.db');
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA synchronous = NORMAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    last_active INTEGER NOT NULL,
    avatar TEXT,
    bio TEXT NOT NULL DEFAULT '',
    idle INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    last_active INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

  CREATE TABLE IF NOT EXISTS friends (
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    friend_username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    PRIMARY KEY (username, friend_username)
  );
  CREATE INDEX IF NOT EXISTS idx_friends_username ON friends(username);

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_user TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    to_user TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    ts INTEGER NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_messages_to_ts ON messages(to_user, ts);
  CREATE INDEX IF NOT EXISTS idx_messages_from_ts ON messages(from_user, ts);
  CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
`);

const stmt = {
  insertUser: db.prepare('INSERT INTO users (username, password_hash, last_active, avatar, bio, idle) VALUES (?, ?, ?, NULL, \'\', 0)'),
  getUser: db.prepare('SELECT * FROM users WHERE username = ?'),
  touchUser: db.prepare('UPDATE users SET last_active = ? WHERE username = ?'),
  setIdle: db.prepare('UPDATE users SET idle = ? WHERE username = ?'),
  setAvatar: db.prepare('UPDATE users SET avatar = ? WHERE username = ?'),
  setBio: db.prepare('UPDATE users SET bio = ? WHERE username = ?'),
  userExists: db.prepare('SELECT 1 FROM users WHERE username = ?'),
  insertSession: db.prepare('INSERT INTO sessions (token, username, last_active) VALUES (?, ?, ?)'),
  getSession: db.prepare('SELECT * FROM sessions WHERE token = ?'),
  touchSession: db.prepare('UPDATE sessions SET last_active = ? WHERE token = ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  addFriendPair: db.prepare(`
    INSERT INTO friends (username, friend_username) VALUES (?, ?)
    ON CONFLICT (username, friend_username) DO NOTHING
  `),
  isFriend: db.prepare('SELECT 1 FROM friends WHERE username = ? AND friend_username = ?'),
  listFriends: db.prepare('SELECT friend_username FROM friends WHERE username = ? ORDER BY friend_username'),
  insertMessage: db.prepare('INSERT INTO messages (id, from_user, to_user, ciphertext, iv, ts, delivered) VALUES (?, ?, ?, ?, ?, ?, 0)'),
  inboxFor: db.prepare('SELECT * FROM messages WHERE to_user = ? AND delivered = 0'),
  markDelivered: db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?'),
  relevantSince: db.prepare('SELECT * FROM messages WHERE (to_user = ? OR from_user = ?) AND ts > ? ORDER BY ts ASC'),
  historyFor: db.prepare('SELECT * FROM messages WHERE to_user = ? OR from_user = ? ORDER BY ts ASC'),
  sweepExpiredSessions: db.prepare('DELETE FROM sessions WHERE last_active < ?'),
  sweepExpiredUsers: db.prepare('DELETE FROM users WHERE last_active < ?'),
  sweepOldMessages: db.prepare('DELETE FROM messages WHERE ts < ?'),
  countUsers: db.prepare('SELECT COUNT(*) AS c FROM users'),
  countMessages: db.prepare('SELECT COUNT(*) AS c FROM messages'),
};

const callSignals = new Map();
const typingStatus = new Map();

function now() { return Date.now(); }
function genToken() { return crypto.randomBytes(24).toString('hex'); }

function touchUser(username) {
  stmt.touchUser.run(now(), username);
}

function touchSession(token) {
  const s = stmt.getSession.get(token);
  if (s) {
    stmt.touchSession.run(now(), token);
    touchUser(s.username);
  }
}

function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  const session = token && stmt.getSession.get(token);
  if (!session) { return res.status(401).json({ error: 'Not authenticated.' }); }
  touchSession(token);
  req.username = session.username;
  next();
}

function statusFor(u) {
  const age = now() - u.last_active;
  if (age > ONLINE_WINDOW_MS) return 'offline';
  return u.idle ? 'idle' : 'online';
}

function friendPublic(username) {
  const u = stmt.getUser.get(username);
  if (!u) return null;
  return { username: u.username, status: statusFor(u), avatar: u.avatar || null, bio: u.bio || '' };
}

function friendsPublicFor(username) {
  return stmt.listFriends.all(username)
    .map((row) => friendPublic(row.friend_username))
    .filter(Boolean);
}

function publicUser(u) {
  return { username: u.username, friends: friendsPublicFor(u.username), avatar: u.avatar || null, bio: u.bio || '' };
}

function userExists(username) {
  return !!stmt.userExists.get(username);
}

function sweep() {
  const cutoff = now() - INACTIVITY_LIMIT_MS;
  stmt.sweepExpiredSessions.run(cutoff);
  stmt.sweepExpiredUsers.run(cutoff);
  stmt.sweepOldMessages.run(cutoff);

  const signalCutoff = now() - 30 * 1000;
  for (const [username, list] of callSignals) {
    const kept = list.filter((s) => s.ts >= signalCutoff && userExists(username));
    if (kept.length) callSignals.set(username, kept);
    else callSignals.delete(username);
  }
  const typingCutoff = now() - TYPING_TTL_MS;
  for (const [from, info] of typingStatus) {
    if (info.ts < typingCutoff || !userExists(from) || !userExists(info.to)) {
      typingStatus.delete(from);
    }
  }
}

setInterval(sweep, 5000);

app.post('/create', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') { return res.status(400).json({ error: 'Username and password are required.' }); }
  const cleanUsername = username.trim();
  if (cleanUsername.length < 3 || cleanUsername.length > 20) { return res.status(400).json({ error: 'Username must be 3-20 characters.' }); }
  if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername)) { return res.status(400).json({ error: 'Username may only contain letters, numbers, underscores.' }); }
  if (password.length < 6) { return res.status(400).json({ error: 'Password must be at least 6 characters.' }); }
  if (userExists(cleanUsername)) { return res.status(409).json({ error: 'Username already taken.' }); }
  const passwordHash = await bcrypt.hash(password, 10);
  stmt.insertUser.run(cleanUsername, passwordHash, now());
  const token = genToken();
  stmt.insertSession.run(token, cleanUsername, now());
  res.json({ token, user: publicUser(stmt.getUser.get(cleanUsername)) });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') { return res.status(400).json({ error: 'Username and password are required.' }); }
  const u = stmt.getUser.get(username.trim());
  if (!u) { return res.status(401).json({ error: 'Invalid username or password.' }); }
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) { return res.status(401).json({ error: 'Invalid username or password.' }); }
  touchUser(u.username);
  const token = genToken();
  stmt.insertSession.run(token, u.username, now());
  res.json({ token, user: publicUser(u) });
});

app.post('/logout', requireAuth, (req, res) => {
  const token = req.headers['x-session-token'];
  stmt.deleteSession.run(token);
  res.json({ ok: true });
});

app.post('/heartbeat', requireAuth, (req, res) => {
  stmt.setIdle.run(req.body && req.body.idle ? 1 : 0, req.username);
  res.json({ ok: true, serverTime: now() });
});

app.post('/profile', requireAuth, (req, res) => {
  const { avatar, bio } = req.body || {};
  const u = stmt.getUser.get(req.username);
  if (!u) return res.status(401).json({ error: 'Not authenticated.' });
  if (avatar !== undefined) {
    if (avatar === null || avatar === '') {
      stmt.setAvatar.run(null, req.username);
    } else if (typeof avatar === 'string' && /^data:image\/(png|jpeg|jpg|webp|gif);base64,/.test(avatar)) {
      if (avatar.length > MAX_AVATAR_LEN) { return res.status(400).json({ error: 'Avatar image is too large.' }); }
      stmt.setAvatar.run(avatar, req.username);
    } else {
      return res.status(400).json({ error: 'Invalid avatar format.' });
    }
  }
  if (bio !== undefined) {
    if (typeof bio !== 'string' || bio.length > MAX_BIO_LEN) { return res.status(400).json({ error: 'Bio must be a string up to ' + MAX_BIO_LEN + ' characters.' }); }
    stmt.setBio.run(bio.trim(), req.username);
  }
  res.json({ ok: true, user: publicUser(stmt.getUser.get(req.username)) });
});

app.post('/typing', requireAuth, (req, res) => {
  const { to, typing } = req.body || {};
  if (typeof to !== 'string') { return res.status(400).json({ error: 'to is required.' }); }
  if (!stmt.isFriend.get(req.username, to)) { return res.status(403).json({ error: 'You must both be added as friends.' }); }
  if (typing) { typingStatus.set(req.username, { to, ts: now() }); }
  else { const existing = typingStatus.get(req.username); if (existing && existing.to === to) typingStatus.delete(req.username); }
  res.json({ ok: true });
});

app.post('/addfriend', requireAuth, (req, res) => {
  const { username } = req.body || {};
  if (typeof username !== 'string' || !username.trim()) { return res.status(400).json({ error: 'Username required.' }); }
  const target = username.trim();
  if (target === req.username) { return res.status(400).json({ error: "You can't add yourself." }); }
  if (!userExists(target)) { return res.status(404).json({ error: 'No such user (they may be offline/expired).' }); }
  stmt.addFriendPair.run(req.username, target);
  stmt.addFriendPair.run(target, req.username);
  res.json({ ok: true, friends: friendsPublicFor(req.username) });
});

app.get('/friends', requireAuth, (req, res) => {
  res.json({ friends: friendsPublicFor(req.username) });
});

app.post('/send', requireAuth, (req, res) => {
  const { to, ciphertext, iv } = req.body || {};
  if (typeof to !== 'string' || typeof ciphertext !== 'string' || typeof iv !== 'string') { return res.status(400).json({ error: 'to, ciphertext, and iv are required.' }); }
  if (!userExists(to)) { return res.status(404).json({ error: 'Recipient not found (may be offline/expired).' }); }
  if (!stmt.isFriend.get(req.username, to)) { return res.status(403).json({ error: 'You must both be added as friends to message.' }); }
  const id = crypto.randomUUID();
  stmt.insertMessage.run(id, req.username, to, ciphertext, iv, now());
  res.json({ ok: true, id });
});

app.get('/receive', requireAuth, (req, res) => {
  const inbox = stmt.inboxFor.all(req.username);
  for (const m of inbox) stmt.markDelivered.run(m.id);
  res.json({ messages: inbox.map((m) => ({ id: m.id, from: m.from_user, ciphertext: m.ciphertext, iv: m.iv, ts: m.ts })) });
});

const SIGNAL_TYPES = new Set(['offer', 'answer', 'ice', 'hangup', 'busy', 'ringing']);

app.post('/call/signal', requireAuth, (req, res) => {
  const { to, type, data, callId } = req.body || {};
  if (typeof to !== 'string' || !SIGNAL_TYPES.has(type) || typeof callId !== 'string') { return res.status(400).json({ error: 'to, valid type, and callId are required.' }); }
  if (!userExists(to)) { return res.status(404).json({ error: 'Recipient not found (may be offline/expired).' }); }
  if (!stmt.isFriend.get(req.username, to)) { return res.status(403).json({ error: 'You must both be added as friends to call.' }); }
  const signal = { id: crypto.randomUUID(), from: req.username, type, data: data ?? null, callId, ts: now() };
  if (!callSignals.has(to)) callSignals.set(to, []);
  callSignals.get(to).push(signal);
  res.json({ ok: true });
});

app.get('/call/poll', requireAuth, (req, res) => {
  const pending = callSignals.get(req.username) || [];
  callSignals.set(req.username, []);
  res.json({ serverTime: now(), signals: pending.map((s) => ({ id: s.id, from: s.from, type: s.type, data: s.data, callId: s.callId, ts: s.ts })) });
});

app.post('/request', requireAuth, (req, res) => {
  const since = Number(req.body?.since) || 0;
  const relevant = stmt.relevantSince.all(req.username, req.username, since);
  for (const m of relevant) stmt.markDelivered.run(m.id);

  const typingCutoff = now() - TYPING_TTL_MS;
  const typingFrom = [];
  for (const [from, info] of typingStatus) { if (info.to === req.username && info.ts >= typingCutoff) typingFrom.push(from); }

  res.json({
    serverTime: now(),
    friends: friendsPublicFor(req.username),
    typing: typingFrom,
    messages: relevant.map((m) => ({ id: m.id, from: m.from_user, to: m.to_user, ciphertext: m.ciphertext, iv: m.iv, ts: m.ts })),
  });
});

app.get('/history', requireAuth, (req, res) => {
  const relevant = stmt.historyFor.all(req.username, req.username);
  res.json({
    serverTime: now(),
    messages: relevant.map((m) => ({ id: m.id, from: m.from_user, to: m.to_user, ciphertext: m.ciphertext, iv: m.iv, ts: m.ts })),
  });
});

app.get('/session', requireAuth, (req, res) => {
  const user = stmt.getUser.get(req.username);

  if (!user) {
    return res.status(410).json({ error: 'Your account has expired.' });
  }

  res.json({
    token: req.headers['x-session-token'],
    user: publicUser(user)
  });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', users: stmt.countUsers.get().c, messages: stmt.countMessages.get().c });
});

app.listen(PORT, () => { console.log(`nChat server running on http://localhost:${PORT}`); });

process.on('SIGTERM', () => { db.close(); process.exit(0); });
process.on('SIGINT', () => { db.close(); process.exit(0); });
