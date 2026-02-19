// =============================================================================
// hub/db.js - SQLite schema and query layer for GitDock Hub (multi-tenant)
// Uses better-sqlite3-multiple-ciphers: same API as better-sqlite3, with
// optional encryption via PRAGMA key. Prebuilt binaries for Windows, Linux, Mac.
// =============================================================================

const Database = require("better-sqlite3-multiple-ciphers");

const path = require("path");
const fs = require("fs");

const DB_DIR = process.env.HUB_DB_DIR || path.join(__dirname);
const DB_PATH = path.join(DB_DIR, "hub.db");

let db = null;

function getDb() {
  if (db) return db;
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  db = new Database(DB_PATH);
  const dbKey = process.env.HUB_DB_KEY;
  if (dbKey && dbKey.length >= 32) {
    db.pragma(`key = '${dbKey.replace(/'/g, "''")}'`);
  }
  db.pragma("journal_mode = WAL");
  initSchema(db);
  return db;
}

function initSchema(database) {
  const hasUsers = database.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
  ).get();
  if (!hasUsers) {
    database.exec(`
      DROP TABLE IF EXISTS snapshots;
      DROP TABLE IF EXISTS machines;
      DROP TABLE IF EXISTS api_keys;
    `);
  }

  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      label TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
    CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked);

    CREATE TABLE IF NOT EXISTS machines (
      id TEXT PRIMARY KEY,
      api_key_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      platform TEXT,
      last_seen TEXT,
      FOREIGN KEY (api_key_id) REFERENCES api_keys(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_machines_api_key ON machines(api_key_id);
    CREATE INDEX IF NOT EXISTS idx_machines_user ON machines(user_id);

    CREATE TABLE IF NOT EXISTS snapshots (
      machine_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      data TEXT NOT NULL,
      received_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (machine_id) REFERENCES machines(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_snapshots_user ON snapshots(user_id);

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      ip TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
  `);
}

// --- Audit ---
function logAudit(userId, action, ip) {
  getDb()
    .prepare("INSERT INTO audit_log (user_id, action, ip) VALUES (?, ?, ?)")
    .run(userId, action, ip || null);
}

// --- Users ---
function createUser(id, email, passwordHash) {
  const d = getDb();
  d.prepare(
    "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)"
  ).run(id, email, passwordHash);
  return { id, email, created_at: d.prepare("SELECT datetime('now') as t").get().t };
}

function getUserByEmail(email) {
  return getDb()
    .prepare("SELECT id, email, password_hash FROM users WHERE email = ?")
    .get(email) || null;
}

function getUserById(id) {
  return getDb()
    .prepare("SELECT id, email FROM users WHERE id = ?")
    .get(id) || null;
}

// --- API Keys ---
function createApiKey(id, label, keyHash, userId) {
  const d = getDb();
  d.prepare(
    "INSERT INTO api_keys (id, user_id, label, key_hash) VALUES (?, ?, ?, ?)"
  ).run(id, userId, label, keyHash);
  return { id, label, created_at: d.prepare("SELECT datetime('now') as t").get().t };
}

function getApiKeyHashesForVerification() {
  return getDb()
    .prepare("SELECT id, user_id, label, key_hash FROM api_keys WHERE revoked = 0")
    .all();
}

function listApiKeys(userId) {
  return getDb()
    .prepare(
      `SELECT k.id, k.label, k.created_at, MAX(m.last_seen) as last_seen
       FROM api_keys k
       LEFT JOIN machines m ON m.api_key_id = k.id AND m.user_id = k.user_id
       WHERE k.revoked = 0 AND k.user_id = ?
       GROUP BY k.id ORDER BY k.created_at DESC`
    )
    .all(userId);
}

function revokeApiKey(id, userId) {
  getDb()
    .prepare("UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?")
    .run(id, userId);
}

// --- Machines ---
function upsertMachine(machineId, apiKeyId, name, platform, userId) {
  const d = getDb();
  const now = new Date().toISOString();
  d.prepare(
    `INSERT INTO machines (id, api_key_id, user_id, name, platform, last_seen)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       name = excluded.name,
       platform = excluded.platform,
       last_seen = excluded.last_seen,
       user_id = excluded.user_id`
  ).run(machineId, apiKeyId, userId, name, platform, now);
}

function getMachine(machineId, userId) {
  const row = getDb()
    .prepare("SELECT * FROM machines WHERE id = ? AND user_id = ?")
    .get(machineId, userId);
  return row || null;
}

function listMachines(userId) {
  return getDb()
    .prepare(
      `SELECT m.id, m.name, m.platform, m.last_seen,
              (SELECT data FROM snapshots s WHERE s.machine_id = m.id AND s.user_id = m.user_id) as snapshot_data
       FROM machines m
       WHERE m.user_id = ?
       ORDER BY m.last_seen DESC`
    )
    .all(userId);
}

function updateMachineName(machineId, name, userId) {
  const d = getDb();
  const r = d.prepare(
    "UPDATE machines SET name = ? WHERE id = ? AND user_id = ?"
  ).run(String(name).trim().slice(0, 128) || name, machineId, userId);
  return r.changes > 0;
}

function deleteMachine(machineId, userId) {
  const d = getDb();
  d.prepare("DELETE FROM snapshots WHERE machine_id = ? AND user_id = ?").run(machineId, userId);
  d.prepare("DELETE FROM machines WHERE id = ? AND user_id = ?").run(machineId, userId);
  return true;
}

// --- Snapshots ---
function saveSnapshot(machineId, dataJson, userId) {
  const d = getDb();
  const data = typeof dataJson === "string" ? dataJson : JSON.stringify(dataJson);
  const now = new Date().toISOString();
  d.prepare(
    `INSERT INTO snapshots (machine_id, user_id, data, received_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(machine_id) DO UPDATE SET
       data = excluded.data,
       received_at = excluded.received_at,
       user_id = excluded.user_id`
  ).run(machineId, userId, data, now);
}

function getSnapshot(machineId, userId) {
  const row = getDb()
    .prepare("SELECT data, received_at FROM snapshots WHERE machine_id = ? AND user_id = ?")
    .get(machineId, userId);
  if (!row) return null;
  try {
    return { data: JSON.parse(row.data), received_at: row.received_at };
  } catch (e) {
    return { data: null, received_at: row.received_at };
  }
}

function getAllSnapshots(userId) {
  const rows = getDb()
    .prepare("SELECT machine_id, data, received_at FROM snapshots WHERE user_id = ?")
    .all(userId);
  const out = [];
  for (const row of rows) {
    try {
      out.push({ machine_id: row.machine_id, data: JSON.parse(row.data), received_at: row.received_at });
    } catch (e) {
      out.push({ machine_id: row.machine_id, data: null, received_at: row.received_at });
    }
  }
  return out;
}

module.exports = {
  getDb,
  createUser,
  getUserByEmail,
  getUserById,
  createApiKey,
  getApiKeyHashesForVerification,
  listApiKeys,
  revokeApiKey,
  upsertMachine,
  getMachine,
  listMachines,
  updateMachineName,
  deleteMachine,
  saveSnapshot,
  getSnapshot,
  getAllSnapshots,
  logAudit,
};
