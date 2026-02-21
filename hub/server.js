// =============================================================================
// hub/server.js - GitDock Hub - central server for multi-machine git status
// =============================================================================

require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const db = require("./db");
const auth = require("./auth");

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3848;
const BASE = __dirname;

const sseClientsByUser = new Map();

function broadcastToUser(userId, event, data) {
  const set = sseClientsByUser.get(userId);
  if (!set) return;
  const payload = typeof data === "object" ? JSON.stringify(data) : String(data);
  const msg = `event: ${event}\ndata: ${payload}\n\n`;
  set.forEach((res) => {
    try {
      res.write(msg);
    } catch (e) {
      set.delete(res);
    }
  });
}

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(cookieParser());

// Lemon Squeezy webhook (must use raw body for signature verification; register before express.json)
app.post(
  "/api/webhooks/lemonsqueezy",
  express.raw({ type: "application/json", limit: "64kb" }),
  (req, res) => {
    const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
    if (!secret) {
      return res.status(500).json({ error: "Webhook not configured" });
    }
    const sig = (req.headers["x-signature"] || "").trim();
    if (!sig) {
      return res.status(400).json({ error: "Missing signature" });
    }
    const rawBody = req.body;
    if (!Buffer.isBuffer(rawBody)) {
      return res.status(400).json({ error: "Invalid body" });
    }
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(rawBody);
    const digest = hmac.digest("hex");
    try {
      if (digest.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(sig, "utf8"))) {
        return res.status(401).json({ error: "Invalid signature" });
      }
    } catch (e) {
      return res.status(401).json({ error: "Invalid signature" });
    }
    let payload;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch (e) {
      return res.status(400).json({ error: "Invalid JSON" });
    }
    const eventName = payload.meta?.event_name;
    const email = payload.data?.attributes?.user_email || payload.meta?.custom_data?.email;
    if (!email) {
      return res.status(200).json({ received: true });
    }
    const user = db.getUserByEmail(email);
    if (!user) {
      return res.status(200).json({ received: true });
    }
    const setPro = ["subscription_created", "subscription_updated", "subscription_resumed"].includes(eventName);
    const setFree = ["subscription_expired", "subscription_cancelled", "subscription_paused"].includes(eventName);
    if (setPro) {
      db.setUserPlan(user.id, "pro");
    } else if (setFree) {
      db.setUserPlan(user.id, "free");
    }
    res.status(200).json({ received: true });
  }
);

app.use(express.json({ limit: "1mb" }));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "Too many requests" },
});
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many login attempts" },
});
const registerLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many registration attempts" },
});
const snapshotLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 2,
  message: { error: "Rate limit: max 2 snapshots per minute per key" },
});

const CSRF_COOKIE = "gitdock_csrf";
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || null;
}
function isStrongPassword(p) {
  if (!p || p.length < 8) return false;
  if (!/[A-Z]/.test(p)) return false;
  if (!/[0-9]/.test(p)) return false;
  return true;
}

function requireSession(req, res, next) {
  const cookieHeader = req.headers.cookie;
  const session = auth.verifySessionCookie(cookieHeader);
  if (!session) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  req.session = session;
  req.userId = session.userId;
  next();
}

function requireApiKey(req, res, next) {
  const authHeader = req.headers.authorization || req.get("Authorization");
  const key = auth.resolveApiKey(authHeader);
  if (!key) {
    const msg = !authHeader || String(authHeader).trim() === ""
      ? "Missing API key (send Authorization: Bearer <key>)"
      : "Invalid API key";
    return res.status(401).json({ error: msg });
  }
  req.apiKey = key;
  req.userId = key.userId;
  next();
}

function requireCsrf(req, res, next) {
  const headerToken = (req.headers["x-csrf-token"] || "").trim();
  const cookieToken = req.cookies && req.cookies[CSRF_COOKIE];
  if (!headerToken || headerToken !== cookieToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  next();
}

// --- Static: dashboard and logo ---
app.get("/", (req, res) => {
  res.sendFile(path.join(BASE, "dashboard.html"));
});
app.get("/gitdock-logo.png", (req, res) => {
  const p = path.join(BASE, "gitdock-logo.png");
  if (fs.existsSync(p)) res.sendFile(p);
  else res.status(404).send("Not found");
});
app.get("/gitdock-logo-removebg.png", (req, res) => {
  const p = path.join(BASE, "gitdock-logo-removebg.png");
  if (fs.existsSync(p)) res.sendFile(p);
  else res.status(404).send("Not found");
});

// --- Public ---
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "gitdock-hub", timestamp: new Date().toISOString() });
});

// --- Auth (dashboard) ---
app.post("/api/auth/register", registerLimiter, (req, res) => {
  const email = (req.body && req.body.email && String(req.body.email).trim()) || "";
  const password = (req.body && req.body.password && String(req.body.password)) || "";
  if (!EMAIL_REGEX.test(email)) {
    return res.status(400).json({ success: false, error: "Invalid email" });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).json({ success: false, error: "Password must be at least 8 characters with one uppercase and one number" });
  }
  const existing = db.getUserByEmail(email);
  if (existing) {
    return res.status(409).json({ success: false, error: "Email already registered" });
  }
  const userId = crypto.randomBytes(16).toString("hex");
  const passwordHash = auth.hashPassword(password);
  db.createUser(userId, email, passwordHash);
  db.logAudit(userId, "register", getClientIp(req));
  const { token, csrfToken } = auth.createSession(userId);
  const isProduction = process.env.NODE_ENV === "production";
  res.cookie(auth.SESSION_COOKIE, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: auth.SESSION_MAX_AGE_MS,
    path: "/",
  });
  res.cookie(CSRF_COOKIE, csrfToken, {
    httpOnly: false,
    secure: isProduction,
    sameSite: "lax",
    maxAge: auth.SESSION_MAX_AGE_MS,
    path: "/",
  });
  res.json({ success: true });
});

app.post("/api/auth/login", loginLimiter, (req, res) => {
  const email = (req.body && req.body.email && String(req.body.email).trim()) || "";
  const password = (req.body && req.body.password && String(req.body.password)) || "";
  if (!email || !password) {
    return res.status(401).json({ success: false, error: "Invalid email or password" });
  }
  const user = db.getUserByEmail(email);
  if (!user || !auth.verifyPasswordHash(password, user.password_hash)) {
    return res.status(401).json({ success: false, error: "Invalid email or password" });
  }
  db.logAudit(user.id, "login", getClientIp(req));
  const { token, csrfToken } = auth.createSession(user.id);
  const isProduction = process.env.NODE_ENV === "production";
  res.cookie(auth.SESSION_COOKIE, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: auth.SESSION_MAX_AGE_MS,
    path: "/",
  });
  res.cookie(CSRF_COOKIE, csrfToken, {
    httpOnly: false,
    secure: isProduction,
    sameSite: "lax",
    maxAge: auth.SESSION_MAX_AGE_MS,
    path: "/",
  });
  res.json({ success: true });
});

app.post("/api/auth/logout", (req, res) => {
  const token = req.cookies && req.cookies[auth.SESSION_COOKIE];
  if (token) auth.destroySession(token);
  res.clearCookie(auth.SESSION_COOKIE, { path: "/" });
  res.clearCookie(CSRF_COOKIE, { path: "/" });
  res.json({ success: true });
});

app.get("/api/auth/check", (req, res) => {
  const session = auth.verifySessionCookie(req.headers.cookie);
  res.json({ ok: !!session });
});

app.get("/api/auth/me", apiLimiter, requireSession, (req, res) => {
  const user = db.getUserById(req.userId);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  const plan = user.plan || "free";
  const checkoutUrl = plan === "free" ? (process.env.LEMONSQUEEZY_CHECKOUT_URL || "") : "";
  res.json({ email: user.email, plan, checkoutUrl, csrfToken: req.session.csrfToken });
});

// --- Agent: receive snapshot ---
app.post("/api/agent/snapshot", snapshotLimiter, requireApiKey, (req, res) => {
  const body = req.body || {};
  const machineId = body.machineId && String(body.machineId).trim().slice(0, 64);
  const machineName = (body.machineName && String(body.machineName).trim().slice(0, 128)) || "Unknown";
  const platform = (body.platform && String(body.platform).trim().slice(0, 32)) || "";
  const repos = Array.isArray(body.repos) ? body.repos : [];

  if (!machineId) {
    return res.status(400).json({ error: "machineId required" });
  }

  const userId = req.userId;
  const user = db.getUserById(userId);
  if (user && user.plan !== "pro") {
    const existingIds = db.getMachineIdsByUserId(userId);
    if (existingIds.length >= 1 && !existingIds.includes(machineId)) {
      return res.status(403).json({
        error: "Free plan is limited to one machine. Upgrade to Pro for unlimited machines.",
        code: "MACHINE_LIMIT",
      });
    }
  }

  const snapshot = {
    machineId,
    machineName,
    platform: platform || undefined,
    timestamp: body.timestamp || new Date().toISOString(),
    repos: repos.map((r) => ({
      name: r.name,
      account: r.account,
      githubUser: r.githubUser,
      branch: r.branch,
      localStatus: r.localStatus,
      isCloned: r.isCloned,
      ahead: typeof r.ahead === "number" ? r.ahead : 0,
      behind: typeof r.behind === "number" ? r.behind : 0,
      lastCommit: r.lastCommit || {},
      summary: r.summary || {},
    })),
  };

  db.upsertMachine(machineId, req.apiKey.id, machineName, platform, userId);
  db.saveSnapshot(machineId, snapshot, userId);
  broadcastToUser(userId, "snapshot_updated", { machineId });
  res.json({ success: true, machineId });
});

// --- Dashboard API (session required) ---
app.get("/api/events", apiLimiter, requireSession, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();
  const userId = req.userId;
  if (!sseClientsByUser.has(userId)) sseClientsByUser.set(userId, new Set());
  sseClientsByUser.get(userId).add(res);
  const keepAlive = setInterval(() => {
    try {
      res.write(": ping\n\n");
    } catch (e) {
      clearInterval(keepAlive);
    }
  }, 30000);
  req.on("close", () => {
    clearInterval(keepAlive);
    const set = sseClientsByUser.get(userId);
    if (set) {
      set.delete(res);
      if (set.size === 0) sseClientsByUser.delete(userId);
    }
  });
});

app.use("/api/machines", apiLimiter, requireSession);
app.use("/api/repos", apiLimiter, requireSession);
app.use("/api/sync", apiLimiter, requireSession);
app.use("/api/keys", apiLimiter, requireSession);

app.get("/api/machines", (req, res) => {
  const rows = db.listMachines(req.userId);
  const machines = rows.map((r) => {
    let snapshotData = null;
    try {
      if (r.snapshot_data) snapshotData = JSON.parse(r.snapshot_data);
    } catch (e) {
      snapshotData = null;
    }
    const repoCount = (snapshotData && snapshotData.repos && snapshotData.repos.length) || 0;
    const issueCount = countMachineIssues(snapshotData);
    return {
      id: r.id,
      name: r.name,
      platform: r.platform,
      last_seen: r.last_seen,
      repo_count: repoCount,
      issue_count: issueCount,
    };
  });
  res.json({ success: true, machines });
});

app.get("/api/machines/:id", (req, res) => {
  const machine = db.getMachine(req.params.id, req.userId);
  if (!machine) return res.status(404).json({ error: "Machine not found" });
  const snap = db.getSnapshot(req.params.id, req.userId);
  res.json({
    success: true,
    machine: {
      id: machine.id,
      name: machine.name,
      platform: machine.platform,
      last_seen: machine.last_seen,
    },
    snapshot: snap ? snap.data : null,
    received_at: snap ? snap.received_at : null,
  });
});

app.patch("/api/machines/:id", requireCsrf, (req, res) => {
  const machine = db.getMachine(req.params.id, req.userId);
  if (!machine) return res.status(404).json({ error: "Machine not found" });
  const name = (req.body && req.body.name != null) ? String(req.body.name).trim().slice(0, 128) : "";
  if (!name) return res.status(400).json({ error: "Name is required" });
  const updated = db.updateMachineName(req.params.id, name, req.userId);
  if (!updated) return res.status(500).json({ error: "Update failed" });
  db.logAudit(req.userId, "machine_renamed", getClientIp(req));
  res.json({ success: true, name });
});

app.delete("/api/machines/:id", requireCsrf, (req, res) => {
  const machine = db.getMachine(req.params.id, req.userId);
  if (!machine) return res.status(404).json({ error: "Machine not found" });
  db.deleteMachine(req.params.id, req.userId);
  db.logAudit(req.userId, "machine_deleted", getClientIp(req));
  res.json({ success: true });
});

app.get("/api/repos", (req, res) => {
  const rows = db.listMachines(req.userId);
  const repos = [];
  for (const r of rows) {
    let snapshotData = null;
    try {
      if (r.snapshot_data) snapshotData = JSON.parse(r.snapshot_data);
    } catch (e) {
      snapshotData = null;
    }
    if (!snapshotData || !Array.isArray(snapshotData.repos)) continue;
    const machineName = r.name || r.id;
    for (const repo of snapshotData.repos) {
      repos.push({
        ...repo,
        machineId: r.id,
        machineName,
      });
    }
  }
  res.json({ success: true, repos });
});

app.get("/api/sync", (req, res) => {
  const snapshots = db.getAllSnapshots(req.userId);
  const issues = computeSyncIssues(snapshots);
  res.json({ success: true, issues });
});

app.get("/api/keys", (req, res) => {
  const keys = db.listApiKeys(req.userId);
  res.json({ success: true, keys });
});

app.post("/api/keys", requireCsrf, (req, res) => {
  const label = (req.body && req.body.label && String(req.body.label).trim().slice(0, 128)) || "Default";
  const id = crypto.randomBytes(12).toString("hex");
  const plainKey = "gdk_" + crypto.randomBytes(24).toString("hex");
  const keyHash = auth.hashApiKey(plainKey);
  db.createApiKey(id, label, keyHash, req.userId);
  db.logAudit(req.userId, "key_created", getClientIp(req));
  res.json({ success: true, key: plainKey, id, label });
});

app.delete("/api/keys/:id", requireCsrf, (req, res) => {
  db.revokeApiKey(req.params.id, req.userId);
  db.logAudit(req.userId, "key_revoked", getClientIp(req));
  res.json({ success: true });
});

// --- Helpers ---
function countMachineIssues(snapshotData) {
  if (!snapshotData || !Array.isArray(snapshotData.repos)) return 0;
  let n = 0;
  for (const r of snapshotData.repos) {
    if (r.localStatus === "dirty" || r.localStatus === "ahead" || r.localStatus === "behind") n += 1;
  }
  return n;
}

const STALE_MS = 60 * 60 * 1000;

function computeSyncIssues(snapshots) {
  const issues = [];
  const now = Date.now();

  for (const { machine_id, data, received_at } of snapshots) {
    if (!data || !data.repos) continue;
    const lastSeen = received_at ? new Date(received_at).getTime() : 0;
    if (now - lastSeen > STALE_MS) {
      issues.push({
        type: "stale_machine",
        machineId: machine_id,
        machineName: data.machineName || machine_id,
        message: `Machine has not reported in over 1 hour`,
      });
    }
    for (const repo of data.repos) {
      const key = `${repo.account}/${repo.name}`;
      if (repo.ahead > 0) {
        issues.push({
          type: "unpushed",
          machineId: machine_id,
          machineName: data.machineName || machine_id,
          repo: key,
          branch: repo.branch,
          ahead: repo.ahead,
          message: `${repo.name}: ${repo.ahead} commit(s) not pushed`,
        });
      }
      if (repo.behind > 0) {
        issues.push({
          type: "behind",
          machineId: machine_id,
          machineName: data.machineName || machine_id,
          repo: key,
          branch: repo.branch,
          behind: repo.behind,
          message: `${repo.name}: ${repo.behind} commit(s) behind remote`,
        });
      }
      if (repo.localStatus === "dirty") {
        issues.push({
          type: "dirty",
          machineId: machine_id,
          machineName: data.machineName || machine_id,
          repo: key,
          message: `${repo.name}: uncommitted changes`,
        });
      }
    }
  }

  const byRepo = {};
  for (const s of snapshots) {
    if (!s.data || !s.data.repos) continue;
    for (const r of s.data.repos) {
      const key = `${r.account}/${r.name}`;
      if (!byRepo[key]) byRepo[key] = [];
      byRepo[key].push({
        machineId: s.machine_id,
        machineName: s.data.machineName,
        branch: r.branch,
        localStatus: r.localStatus,
      });
    }
  }
  for (const [repoKey, entries] of Object.entries(byRepo)) {
    if (entries.length < 2) continue;
    const branches = [...new Set(entries.map((e) => e.branch))];
    if (branches.length > 1) {
      issues.push({
        type: "branch_mismatch",
        repo: repoKey,
        machines: entries.map((e) => ({ id: e.machineId, name: e.machineName, branch: e.branch })),
        message: `${repoKey}: different branches across machines`,
      });
    }
    const dirtyCount = entries.filter((e) => e.localStatus === "dirty").length;
    if (dirtyCount >= 2) {
      issues.push({
        type: "dirty_multiple",
        repo: repoKey,
        machines: entries.filter((e) => e.localStatus === "dirty").map((e) => e.machineName),
        message: `${repoKey}: uncommitted changes on multiple machines`,
      });
    }
  }

  return issues;
}

// --- Start ---
function start() {
  try {
    auth.getSecret();
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  db.getDb();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`GitDock Hub listening on port ${PORT}`);
    console.log(`Dashboard: http://localhost:${PORT}`);
  });
}

start();
