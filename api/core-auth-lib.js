const crypto = require('crypto');
const { Pool } = require('pg');

const COOKIE_NAME = 'core_session';
const SESSION_TTL = 60 * 60 * 8;

let pool;

function getAuthConfig() {
  return {
    databaseUrl:
      process.env.CORE_DATABASE_URL ||
      process.env.Core_database_url ||
      process.env.POSTGRES_URL,
    secret: process.env.CORE_AUTH_SECRET || process.env.Core_secret,
  };
}

function getPool(config) {
  if (!pool) {
    pool = new Pool({
      connectionString: config.databaseUrl,
      ssl: { rejectUnauthorized: false },
    });
  }
  return pool;
}

function makeSignature(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex');
}

function verifyPassword(password, stored) {
  const [salt, hashHex] = String(stored).split(':');
  if (!salt || !hashHex) return false;
  const hash = crypto.scryptSync(password, salt, 64);
  const storedBuf = Buffer.from(hashHex, 'hex');
  if (storedBuf.length !== hash.length) return false;
  return crypto.timingSafeEqual(storedBuf, hash);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) {
      return acc;
    }
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    acc[key] = decodeURIComponent(val);
    return acc;
  }, {});
}

function encodeSession(email, secret) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const payload = `${email}.${exp}`;
  const encoded = Buffer.from(payload).toString('base64url');
  const sig = makeSignature(payload, secret);
  return `${encoded}.${sig}`;
}

function decodeAndValidateSession(raw, secret) {
  if (!raw || !raw.includes('.')) {
    return null;
  }
  const [encoded, sig] = raw.split('.');
  const payload = Buffer.from(encoded, 'base64url').toString('utf8');
  const expected = makeSignature(payload, secret);
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }
  const [email, exp] = payload.split('.');
  if (!email || !exp || Date.now() / 1000 > Number(exp)) {
    return null;
  }
  return { email };
}

function sessionCookie(token) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`;
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function requireConfig(res) {
  const config = getAuthConfig();
  if (!config.databaseUrl || !config.secret) {
    res.status(500).json({ error: 'Core auth is not configured on the server.' });
    return null;
  }
  return config;
}

function isAuthenticated(req, config) {
  const cookies = parseCookies(req);
  const payload = decodeAndValidateSession(cookies[COOKIE_NAME], config.secret);
  if (!payload) {
    return false;
  }
  return Boolean(payload.email);
}

module.exports = {
  COOKIE_NAME,
  SESSION_TTL,
  getPool,
  requireConfig,
  verifyPassword,
  encodeSession,
  decodeAndValidateSession,
  parseCookies,
  sessionCookie,
  clearSessionCookie,
  isAuthenticated,
};
