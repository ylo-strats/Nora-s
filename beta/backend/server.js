/**
 * SecureDRM License Server v2.0
 * Production-grade license validation, device binding, and admin API
 *
 * ENV VARS REQUIRED:
 *   ADMIN_SECRET       - Bearer token for admin endpoints
 *   CONTENT_KEY        - 32-char AES key for content encryption
 *   TOKEN_SECRET       - HMAC secret for signed session tokens
 *   ALLOWED_ORIGINS    - Comma-separated allowed CORS origins
 *   PORT               - Server port (default 3001)
 */

'use strict';

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');
const fs        = require('fs');
const path      = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

const ADMIN_SECRET = process.env.ADMIN_SECRET  || 'CHANGE_ME_ADMIN_SECRET_32CHARS!!';
const TOKEN_SECRET = process.env.TOKEN_SECRET  || 'CHANGE_ME_TOKEN_SECRET_32CHARS!!';
const CONTENT_KEY  = process.env.CONTENT_KEY   || 'CHANGE_ME_CONTENT_KEY_32CHARS!!!';

// ─── Persistence ─────────────────────────────────────────────────────────────

const DB_FILE = path.join(__dirname, 'data', 'db.json');
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
  }
  return {
    config: { maxUsers: 20, maxDevicesPerUser: 2 },
    users: {},
    suspiciousLog: [],
  };
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = loadDB();

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function now() { return new Date().toISOString(); }

function hashFp(fp) {
  return crypto.createHmac('sha256', TOKEN_SECRET).update(fp).digest('hex');
}

function issueToken(userId, fpHash) {
  const payload = { userId, fpHash, exp: Date.now() + 13 * 60 * 60 * 1000 };
  const data    = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig     = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  try {
    const [data, sig] = (token || '').split('.');
    if (!data || !sig) return null;
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

function aesDecrypt(ciphertext) {
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  const key      = Buffer.from(CONTENT_KEY.slice(0, 32).padEnd(32, '0'), 'utf8');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(encHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

function aesEncrypt(plaintext) {
  const key    = Buffer.from(CONTENT_KEY.slice(0, 32).padEnd(32, '0'), 'utf8');
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + cipher.getAuthTag().toString('hex') + ':' + enc.toString('hex');
}

function logSuspicious(userId, fingerprint, reason, ip) {
  const entry = { ts: now(), userId, fp: String(fingerprint).slice(0, 20) + '…', reason, ip };
  db.suspiciousLog.unshift(entry);
  if (db.suspiciousLog.length > 1000) db.suspiciousLog.length = 1000;
  saveDB(db);
  console.warn('[SUSPICIOUS]', entry);
}

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '512kb' }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 40,
  message: { error: 'Rate limited', code: 'RATE_LIMITED' },
});
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 200,
  message: { error: 'Rate limited', code: 'RATE_LIMITED' },
});

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${ADMIN_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── License Routes ───────────────────────────────────────────────────────────

// POST /api/license/activate  { userId, fingerprint }
app.post('/api/license/activate', apiLimiter, (req, res) => {
  const { userId, fingerprint } = req.body || {};
  const ip = req.ip;

  if (!userId || !fingerprint || typeof userId !== 'string' || typeof fingerprint !== 'string') {
    return res.status(400).json({ allowed: false, reason: 'Bad request', code: 'BAD_REQUEST' });
  }

  const uid = userId.trim().toUpperCase().slice(0, 32);
  const fp  = fingerprint.trim().slice(0, 256);

  if (!db.users[uid]) {
    logSuspicious(uid, fp, 'Unknown package ID', ip);
    return res.json({ allowed: false, reason: 'Package not recognized', code: 'UNKNOWN_PACKAGE' });
  }

  const user = db.users[uid];

  if (user.banned) {
    logSuspicious(uid, fp, 'Banned user attempted access', ip);
    return res.json({ allowed: false, reason: 'Access revoked by administrator', code: 'BANNED' });
  }

  const fpHash      = hashFp(fp);
  const knownDevice = user.devices.find(d => d.fpHash === fpHash);

  if (!knownDevice) {
    if (user.devices.length >= db.config.maxDevicesPerUser) {
      logSuspicious(uid, fp, `Device limit exceeded (${user.devices.length}/${db.config.maxDevicesPerUser})`, ip);
      return res.json({
        allowed: false,
        reason:  `Document is already active on ${db.config.maxDevicesPerUser} device(s). Contact support to transfer your license.`,
        code:    'DEVICE_LIMIT',
      });
    }
    user.devices.push({ fpHash, registeredAt: now(), lastSeen: now(), ip });
  } else {
    knownDevice.lastSeen = now();
    knownDevice.ip = ip;
  }

  user.lastSeen    = now();
  user.accessCount = (user.accessCount || 0) + 1;
  saveDB(db);

  return res.json({ allowed: true, token: issueToken(uid, fpHash), userId: uid });
});

// POST /api/license/ping  { token, fingerprint }
app.post('/api/license/ping', apiLimiter, (req, res) => {
  const { token, fingerprint } = req.body || {};
  const ip = req.ip;

  const payload = verifyToken(token);
  if (!payload) {
    return res.json({ allowed: false, reason: 'Session expired — please reload', code: 'TOKEN_EXPIRED' });
  }

  const { userId, fpHash } = payload;
  const user = db.users[userId];

  if (!user) return res.json({ allowed: false, reason: 'Package not recognized', code: 'UNKNOWN_PACKAGE' });
  if (user.banned) {
    logSuspicious(userId, fingerprint, 'Banned user pinged', ip);
    return res.json({ allowed: false, reason: 'Access revoked', code: 'BANNED' });
  }

  const currentFpHash = hashFp(fingerprint);
  if (currentFpHash !== fpHash) {
    logSuspicious(userId, fingerprint, 'Fingerprint mismatch on ping', ip);
    return res.json({ allowed: false, reason: 'Device verification failed', code: 'FP_MISMATCH' });
  }

  const device = user.devices.find(d => d.fpHash === fpHash);
  if (device) { device.lastSeen = now(); device.ip = ip; }
  user.lastSeen = now();
  saveDB(db);

  return res.json({ allowed: true, token: issueToken(userId, fpHash) });
});

// POST /api/license/chunk  { token, fingerprint, chunkId }
app.post('/api/license/chunk', apiLimiter, (req, res) => {
  const { token, fingerprint, chunkId } = req.body || {};

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token', code: 'TOKEN_INVALID' });

  const { userId, fpHash } = payload;
  const user = db.users[userId];
  if (!user || user.banned) return res.status(403).json({ error: 'Access denied', code: 'DENIED' });
  if (hashFp(fingerprint) !== fpHash) {
    logSuspicious(userId, fingerprint, 'FP mismatch on chunk fetch', req.ip);
    return res.status(403).json({ error: 'Device mismatch', code: 'FP_MISMATCH' });
  }

  const chunksFile = path.join(__dirname, 'data', 'chunks.json');
  if (!fs.existsSync(chunksFile)) return res.status(503).json({ error: 'Content not loaded', code: 'NO_CONTENT' });

  const chunks = JSON.parse(fs.readFileSync(chunksFile, 'utf8'));
  const chunk  = chunks[chunkId];
  if (!chunk) return res.status(404).json({ error: 'Section not found', code: 'NOT_FOUND' });

  try {
    return res.json({ content: aesDecrypt(chunk.ciphertext), title: chunk.title });
  } catch (e) {
    console.error('Decrypt error', e.message);
    return res.status(500).json({ error: 'Decryption failed' });
  }
});

// ─── Admin Routes ─────────────────────────────────────────────────────────────

app.get('/api/admin/stats', adminLimiter, requireAdmin, (req, res) => {
  const users = Object.entries(db.users).map(([id, u]) => ({
    id,
    banned:      u.banned || false,
    devices:     u.devices,
    deviceCount: u.devices.length,
    lastSeen:    u.lastSeen,
    accessCount: u.accessCount || 0,
    created:     u.created,
  }));
  res.json({
    config:        db.config,
    totalIssued:   users.length,
    totalActive:   users.filter(u => !u.banned && u.deviceCount > 0).length,
    totalBanned:   users.filter(u => u.banned).length,
    users,
    suspiciousLog: db.suspiciousLog.slice(0, 200),
  });
});

app.post('/api/admin/config', adminLimiter, requireAdmin, (req, res) => {
  const { maxUsers, maxDevicesPerUser } = req.body || {};
  if (maxUsers !== undefined)          db.config.maxUsers          = Math.max(1, parseInt(maxUsers));
  if (maxDevicesPerUser !== undefined) db.config.maxDevicesPerUser = Math.max(1, parseInt(maxDevicesPerUser));
  saveDB(db);
  res.json({ ok: true, config: db.config });
});

app.post('/api/admin/issue', adminLimiter, requireAdmin, (req, res) => {
  const count = Object.keys(db.users).length;
  if (count >= db.config.maxUsers) {
    return res.status(400).json({ error: `User limit reached (${db.config.maxUsers})` });
  }
  const newId = req.body?.userId || `USER-${String(count + 1).padStart(3, '0')}`;
  if (db.users[newId]) return res.status(409).json({ error: 'User ID already exists' });
  db.users[newId] = { created: now(), banned: false, devices: [], lastSeen: null, accessCount: 0 };
  saveDB(db);
  res.json({ ok: true, userId: newId });
});

app.post('/api/admin/ban', adminLimiter, requireAdmin, (req, res) => {
  const { userId, ban } = req.body || {};
  if (!userId || !db.users[userId]) return res.status(404).json({ error: 'User not found' });
  db.users[userId].banned = ban !== false;
  if (db.users[userId].banned) logSuspicious(userId, '', 'Manually banned by admin', 'admin');
  saveDB(db);
  res.json({ ok: true, userId, banned: db.users[userId].banned });
});

app.post('/api/admin/revoke-device', adminLimiter, requireAdmin, (req, res) => {
  const { userId, fpHash } = req.body || {};
  const user = db.users[userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.devices = user.devices.filter(d => d.fpHash !== fpHash);
  saveDB(db);
  res.json({ ok: true, remaining: user.devices.length });
});

app.post('/api/admin/seed', adminLimiter, requireAdmin, (req, res) => {
  const n = Math.min(parseInt(req.body?.count) || 20, 500);
  let created = 0;
  for (let i = 1; i <= n; i++) {
    const uid = `USER-${String(i).padStart(3, '0')}`;
    if (!db.users[uid]) {
      db.users[uid] = { created: now(), banned: false, devices: [], lastSeen: null, accessCount: 0 };
      created++;
    }
  }
  saveDB(db);
  res.json({ ok: true, created, total: Object.keys(db.users).length });
});

// Expose encrypt for ingestion tool (admin-only)
app.post('/api/admin/encrypt-chunk', adminLimiter, requireAdmin, (req, res) => {
  const { plaintext } = req.body || {};
  if (!plaintext) return res.status(400).json({ error: 'plaintext required' });
  res.json({ ciphertext: aesEncrypt(plaintext) });
});

app.get('/health', (_, res) => res.json({ ok: true, ts: now() }));

const viewerPath = path.join(__dirname, "..", "viewer");

app.use(express.static(viewerPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(viewerPath, "index.html"));
});

app.listen(PORT, () => {
  console.log(`[SecureDRM] License server on :${PORT}`);
  if (ADMIN_SECRET.startsWith('CHANGE_ME')) console.warn('[WARNING] Change ADMIN_SECRET before production!');
});

module.exports = app;
