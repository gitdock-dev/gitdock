// =============================================================================
// hub/auth.js - API key (agents) + session cookie (dashboard) authentication
// =============================================================================

const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("./db");

const SESSION_COOKIE = "gitdock_hub_session";
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const BCRYPT_ROUNDS = 12;

// In-memory session store: sessionId -> { userId, createdAt, csrfToken }
const sessions = new Map();

function getSecret() {
  const secret = process.env.HUB_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("HUB_SECRET must be set and at least 32 characters");
  }
  return secret;
}

function hashPassword(plain) {
  return bcrypt.hashSync(plain, BCRYPT_ROUNDS);
}

function verifyPasswordHash(plain, hash) {
  if (!hash || !plain) return false;
  return bcrypt.compareSync(plain, hash);
}

function hashApiKey(plainKey) {
  return bcrypt.hashSync(plainKey, BCRYPT_ROUNDS);
}

function verifyApiKeyStoredHash(plainKey, storedHash) {
  if (!storedHash) return null;
  return bcrypt.compareSync(plainKey, storedHash);
}

function createSession(userId) {
  const secret = getSecret();
  const sessionId = crypto.randomBytes(32).toString("hex");
  const csrfToken = crypto.randomBytes(24).toString("hex");
  const sig = crypto.createHmac("sha256", secret).update(sessionId).digest("hex");
  const token = `${sessionId}.${sig}`;
  sessions.set(sessionId, { userId, createdAt: Date.now(), csrfToken });
  return { token, sessionId, csrfToken };
}

function verifySessionCookie(cookieHeader) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  const value = match ? decodeURIComponent(match[1].trim()) : null;
  if (!value) return null;
  const [sessionId, sig] = value.split(".");
  if (!sessionId || !sig) return null;
  const secret = getSecret();
  const expected = crypto.createHmac("sha256", secret).update(sessionId).digest("hex");
  if (expected !== sig) return null;
  if (!sessions.has(sessionId)) return null;
  const s = sessions.get(sessionId);
  if (Date.now() - s.createdAt > SESSION_MAX_AGE_MS) {
    sessions.delete(sessionId);
    return null;
  }
  return { sessionId, userId: s.userId, csrfToken: s.csrfToken };
}

function destroySession(token) {
  const value = (token || "").split(".")[0];
  if (value) sessions.delete(value);
}

function apiKeyFromHeader(authHeader) {
  if (!authHeader || typeof authHeader !== "string") return null;
  const m = authHeader.trim().match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function resolveApiKey(authHeader) {
  const plainKey = apiKeyFromHeader(authHeader);
  if (!plainKey) return null;
  const keys = db.getApiKeyHashesForVerification();
  for (const k of keys) {
    if (bcrypt.compareSync(plainKey, k.key_hash)) {
      return { id: k.id, label: k.label, userId: k.user_id };
    }
  }
  return null;
}

module.exports = {
  SESSION_COOKIE,
  SESSION_MAX_AGE_MS,
  getSecret,
  hashPassword,
  verifyPasswordHash,
  hashApiKey,
  verifyApiKeyStoredHash,
  resolveApiKey,
  createSession,
  verifySessionCookie,
  destroySession,
  apiKeyFromHeader,
};
