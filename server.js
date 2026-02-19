// =============================================================================
// server.js - GitDock local server and API
// =============================================================================
// - Listens ONLY on 127.0.0.1 (localhost) - not accessible from network
// - Only whitelisted operations allowed (no arbitrary command execution)
// - Path validation prevents directory traversal attacks
// - Safety checks before destructive operations
// =============================================================================

const express = require("express");
const { execSync, spawn, execFileSync, spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const https = require("https");
const http = require("http");

const isWindows = process.platform === "win32";
const isDarwin = process.platform === "darwin";

// --- Credential storage: in-memory session ---
const TOKEN_SERVICE = "GitDock";
const HUB_KEY_SERVICE = "GitDock-Hub";
const HUB_KEY_ACCOUNT = "hubApiKey";
const sessionTokens = new Map(); // accountName -> token (not persisted)
const tokenCache = new Map(); // accountName -> { login, ok, checkedAtMs }
const TOKEN_CACHE_TTL_MS = 60 * 1000;
let cachedHubApiKey = null; // In-memory cache for Hub API key (loaded at startup)

const app = express();
app.disable("x-powered-by"); // SECURITY: Don't expose framework info
const PORT = parseInt(process.env.GITDOCK_PORT, 10) || 3847;
const HOST = "127.0.0.1"; // SECURITY: localhost only

// --- Configuration ---
// When packaged (pkg or SEA), assets and config live next to the executable.
// In dev mode, __dirname is the project directory.
const isPkg = typeof process.pkg !== "undefined";
const execBase = path.basename(process.execPath, ".exe").toLowerCase();
const isStandalone = execBase === "gitdock";
const APP_DIR = isPkg || isStandalone ? path.dirname(process.execPath) : __dirname;
const workspaceModule = require("./workspace");
let BASE_DIR = (isPkg || isStandalone) ? (workspaceModule.loadWorkspace() || path.dirname(process.execPath)) : __dirname;
let CONFIG_PATH = path.join(BASE_DIR, "config.json");

function reloadBaseDirFromWorkspace() {
  if (!isPkg && !isStandalone) return;
  const ws = workspaceModule.loadWorkspace();
  if (ws) {
    BASE_DIR = ws;
    CONFIG_PATH = path.join(BASE_DIR, "config.json");
    console.log("[workspace] BASE_DIR updated to: " + BASE_DIR);
  }
}

const SSH_MARKER = "# --- GitHub Multi-Account (managed by GitDock) ---";
const SSH_MARKER_END = "# --- End GitHub Multi-Account ---";

// --- Config module (file-based, no hardcoded accounts) ---
function ensureMachineId(config) {
  const crypto = require("crypto");
  let updated = false;
  if (config.hub && config.hub.url && (config.hub.apiKey || config.hub.apiKeySecure || cachedHubApiKey)) {
    if (!config.machine) {
      config.machine = { id: crypto.randomUUID(), name: os.hostname() };
      updated = true;
    } else if (!config.machine.id || typeof config.machine.id !== "string") {
      config.machine.id = config.machine.id || crypto.randomUUID();
      updated = true;
    }
  }
  if (updated) saveConfig(config);
  return config;
}

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = fs.readFileSync(CONFIG_PATH, "utf8");
      const data = JSON.parse(raw);
      if (data && typeof data.accounts === "object") {
        return ensureMachineId(data);
      }
    }
  } catch (e) {
    console.warn("[config] Could not load config.json:", e.message);
  }
  // No config found — create empty config (user will add accounts via dashboard)
  const config = { accounts: {} };
  saveConfig(config);
  return config;
}

function readGitconfigEmail(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const content = fs.readFileSync(filePath, "utf8");
    const m = content.match(/\bemail\s*=\s*(.+)/);
    return m ? m[1].trim() : null;
  } catch (e) {
    return null;
  }
}

function saveConfig(config) {
  const out = { accounts: config.accounts };
  if (config.machine && typeof config.machine === "object") out.machine = config.machine;
  if (config.hub && typeof config.hub === "object") out.hub = config.hub;
  const data = JSON.stringify(out, null, 2);
  fs.writeFileSync(CONFIG_PATH, data, "utf8");
}

function getAccounts() {
  const config = loadConfig();
  const accounts = {};
  for (const [name, acc] of Object.entries(config.accounts || {})) {
    accounts[name] = {
      ...acc,
      localDir: path.join(BASE_DIR, name),
    };
  }
  return accounts;
}

function getSSHDir() {
  const home = isWindows ? (process.env.USERPROFILE || os.homedir()) : os.homedir();
  return path.join(home, ".ssh");
}

function writeGitconfigForAccount(accountName) {
  const account = validateAccount(accountName);
  if (!account) return;
  const gitconfigPath = path.join(BASE_DIR, `.gitconfig-${accountName}`);
  const safeStr = (s) => String(s || "").trim().replace(/[\r\n\[\]]/g, "").slice(0, 256);
  const name = safeStr(account.githubUser || accountName);
  const email = safeStr(account.email);
  const content = `# Git config for ${safeStr(account.label) || accountName} (${account.githubUser})\n# This file is auto-included when working inside the ${accountName}/ directory\n[user]\n    name = ${name}\n    email = ${email}\n`;
  fs.writeFileSync(gitconfigPath, content, "utf8");
}

function validateAccount(accountName) {
  const accounts = getAccounts();
  return accounts[accountName] || null;
}

// --- Active operations tracking (for SSE) ---
const activeOperations = new Map();
const MAX_ACTIVE_OPS = 200;
const sseClients = new Set();
const MAX_SSE_CLIENTS = 50;

// --- Rate limiting (in-memory, no external dependency) ---
const rateLimitBuckets = new Map();
function checkRateLimit(bucketKey, maxRequests, windowMs) {
  const now = Date.now();
  const entry = rateLimitBuckets.get(bucketKey);
  if (!entry || now > entry.resetAt) {
    rateLimitBuckets.set(bucketKey, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= maxRequests) return false;
  entry.count++;
  return true;
}

// --- Middleware ---
app.use(express.json({ limit: "10kb" })); // SECURITY: Limit request body size

// SECURITY: Only allow requests from localhost
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (ip !== "127.0.0.1" && ip !== "::1" && ip !== "::ffff:127.0.0.1") {
    return res.status(403).json({ error: "Access denied" });
  }
  next();
});

// SECURITY: Host header validation (prevents DNS rebinding attacks)
app.use((req, res, next) => {
  const host = (req.headers.host || "").split(":")[0].toLowerCase();
  if (host !== "127.0.0.1" && host !== "localhost") {
    return res.status(403).json({ error: "Access denied" });
  }
  next();
});

// SECURITY: Standard security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data:; " +
    "connect-src 'self';"
  );
  next();
});

// SECURITY: Anti-CSRF via custom header for state-changing requests
app.use((req, res, next) => {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
  if (!req.path.startsWith("/api/")) return next();
  if (req.headers["x-gitdock"] !== "1") {
    return res.status(403).json({ error: "Missing security header" });
  }
  next();
});

// SECURITY: Serve only the dashboard file, not the entire directory
app.get("/", (req, res) => {
  const workspace = require("./workspace");
  if (isPkg && !workspace.isWorkspaceConfigured()) {
    return res.sendFile(path.join(APP_DIR, "workspace-setup.html"));
  }
  res.sendFile(path.join(APP_DIR, "dashboard.html"));
});

// Workspace setup API
app.get("/api/workspace/status", (req, res) => {
  const workspace = require("./workspace");
  const ws = workspace.loadWorkspace();
  res.json({
    configured: !!ws,
    path: ws,
    defaultPath: workspace.getDefaultWorkspacePath(),
  });
});
app.post("/api/workspace/setup", (req, res) => {
  const workspace = require("./workspace");
  const { path: dirPath } = req.body;
  if (!dirPath || typeof dirPath !== "string" || dirPath.trim().length < 3) {
    return res.status(400).json({ success: false, error: "Invalid directory path" });
  }
  const resolvedPath = path.resolve(dirPath.trim());
  const homeDir = os.homedir();
  if (!isPathInsideDir(homeDir, resolvedPath)) {
    return res.status(400).json({ success: false, error: "Workspace must be within your home directory" });
  }
  if (resolvedPath === path.parse(resolvedPath).root || resolvedPath === homeDir) {
    return res.status(400).json({ success: false, error: "Workspace cannot be a root directory or your home folder directly" });
  }
  try {
    const resolved = workspace.saveWorkspace(dirPath);
    reloadBaseDirFromWorkspace();
    res.json({ success: true, path: resolved, message: "Workspace configured" });
  } catch (err) {
    console.error("[workspace] Setup error:", err);
    res.status(500).json({ success: false, error: "Failed to configure workspace" });
  }
});

// Full cleanup: clear Hub key, remove SSH keys, remove workspace config
app.post("/api/cleanup", async (req, res) => {
  if (!checkRateLimit("cleanup", 2, 60000)) {
    return res.status(429).json({ success: false, error: "Too many attempts" });
  }
  const workspace = require("./workspace");
  const steps = [];
  try {
    cachedHubApiKey = null;
    const config = loadConfig();
    if (config.hub) {
      delete config.hub.apiKey;
      delete config.hub.apiKeySecure;
      saveConfig(config);
      steps.push("Hub API key cleared from config");
    }

    try {
      const sshDir = path.join(os.homedir(), ".ssh");
      if (fs.existsSync(sshDir)) {
        const files = fs.readdirSync(sshDir);
        let removed = 0;
        for (const f of files) {
          if (f.startsWith("id_ed25519_") && !f.includes("backup")) {
            fs.unlinkSync(path.join(sshDir, f));
            removed++;
          }
        }
        const configPath = path.join(sshDir, "config");
        if (fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, "utf8");
          const cleaned = content.replace(/# GitDock[^\n]*\nHost github\.com-[^\n]*\n(\s+[^\n]*\n)*/gi, "").trim();
          if (cleaned !== content.trim()) {
            fs.writeFileSync(configPath, cleaned ? cleaned + "\n" : "", "utf8");
          }
        }
        steps.push("SSH keys removed (" + removed + " files)");
      }
    } catch (e) { steps.push("SSH cleanup skipped: " + e.message); }

    try {
      if (fs.existsSync(workspace.WORKSPACE_PATH)) {
        fs.unlinkSync(workspace.WORKSPACE_PATH);
      }
      steps.push("Workspace config removed");
    } catch (e) { steps.push("Workspace cleanup skipped: " + e.message); }

    res.json({ success: true, steps });
  } catch (err) {
    console.error("[cleanup] Error:", err);
    res.status(500).json({ success: false, error: "Cleanup failed", steps });
  }
});
// App version
app.get("/api/version", (req, res) => {
  try {
    const pkg = require("./package.json");
    res.json({ version: pkg.version || "1.0.0" });
  } catch (e) {
    res.json({ version: "1.0.0" });
  }
});
// Static assets (no config files, no node_modules)
// GitDock logo
app.get("/gitdock-logo.png", (req, res) => {
  const file = path.join(APP_DIR, "hub", "gitdock-logo.png");
  if (fs.existsSync(file)) res.sendFile(file);
  else res.status(404).send("Not found");
});
// GitDock logo without background
app.get("/gitdock-logo-nobg.png", (req, res) => {
  const logo = path.join(APP_DIR, "site", "gitdock-logo-removebg-preview.png");
  if (fs.existsSync(logo)) res.sendFile(logo);
  else res.status(404).send("Not found");
});
// SECURITY: Never serve config.json
app.get("/config.json", (req, res) => res.status(404).send("Not found"));

// --- Helpers ---

function sanitizeAccountName(name) {
  if (!name || typeof name !== "string") return null;
  const clean = name.trim().toLowerCase().replace(/[^a-z0-9\-]/g, "");
  if (clean.length === 0 || clean.length > 64) return null;
  return clean;
}

function sanitizeRepoName(name) {
  // Only allow alphanumeric, hyphens, underscores, dots
  if (!name || typeof name !== "string") return null;
  const clean = name.replace(/[^a-zA-Z0-9\-_.]/g, "");
  if (clean !== name || clean.length === 0 || clean.includes("..")) return null;
  return clean;
}

function sanitizeOwnerName(name) {
  // GitHub owners: user/org. Keep same safety rules as repo name.
  if (!name || typeof name !== "string") return null;
  const clean = name.replace(/[^a-zA-Z0-9\-_.]/g, "");
  if (clean !== name || clean.length === 0 || clean.includes("..")) return null;
  return clean;
}

function sanitizeSshHostAlias(host) {
  // SSH host alias is used as "git@{alias}" and as "Host {alias}" in ssh config.
  // Restrict strictly to avoid surprising behavior and shell injection risk.
  if (!host || typeof host !== "string") return null;
  const trimmed = host.trim();
  if (trimmed.length === 0 || trimmed.length > 128) return null;
  if (!/^[a-zA-Z0-9._-]+$/.test(trimmed)) return null;
  return trimmed;
}

function parseGitHubRepoUrl(input) {
  if (!input || typeof input !== "string") return null;
  const raw = input.trim();
  if (!raw || raw.length > 2048) return null;

  // Accept common forms:
  // - https://github.com/OWNER/REPO(.git)
  // - git@github.com:OWNER/REPO(.git)
  // - git@github.com-<alias>:OWNER/REPO(.git)
  // - github.com/OWNER/REPO(.git)
  let s = raw;
  if (!/^https?:\/\//i.test(s) && /^github\.com\//i.test(s)) {
    s = "https://" + s;
  }

  // https URL
  try {
    if (/^https?:\/\//i.test(s)) {
      const u = new URL(s);
      if (!/^github\.com$/i.test(u.hostname)) return null;
      const parts = u.pathname.replace(/^\/+|\/+$/g, "").split("/");
      if (parts.length < 2) return null;
      const owner = sanitizeOwnerName(parts[0]);
      const repo = sanitizeRepoName(String(parts[1]).replace(/\.git$/i, ""));
      if (!owner || !repo) return null;
      return { owner, repo };
    }
  } catch (e) {
    // fall through to SSH parsing
  }

  // SSH forms
  const sshMatch = s.match(/^git@github\.com(?:-[a-zA-Z0-9_-]+)?:([^\/\s]+)\/([^\/\s]+?)(?:\.git)?$/);
  if (sshMatch) {
    const owner = sanitizeOwnerName(sshMatch[1]);
    const repo = sanitizeRepoName(sshMatch[2]);
    if (!owner || !repo) return null;
    return { owner, repo };
  }

  return null;
}

function parseGitHubOwnerRepoFromRemote(remoteUrl) {
  const parsed = parseGitHubRepoUrl(remoteUrl);
  if (parsed) return parsed;

  // Also accept plain git@<alias>:OWNER/REPO.git that isn't github.com-* (rare)
  if (!remoteUrl || typeof remoteUrl !== "string") return null;
  const m = remoteUrl.trim().match(/^git@[^:]+:([^\/\s]+)\/([^\/\s]+?)(?:\.git)?$/);
  if (!m) return null;
  const owner = sanitizeOwnerName(m[1]);
  const repo = sanitizeRepoName(m[2]);
  if (!owner || !repo) return null;
  return { owner, repo };
}

function getRepoPath(accountName, repoName) {
  const account = validateAccount(accountName);
  if (!account) return null;
  const safeName = sanitizeRepoName(repoName);
  if (!safeName) return null;
  const repoPath = path.join(account.localDir, safeName);
  // SECURITY: Ensure path is within the expected directory (prefix-safe, Windows case-insensitive)
  if (!isPathInsideDir(account.localDir, repoPath)) return null;
  return repoPath;
}

function isPathInsideDir(baseDir, candidatePath) {
  // Ensure candidatePath is within baseDir (prefix-safe).
  // Use case-insensitive comparison on Windows.
  const base = path.resolve(baseDir);
  const cand = path.resolve(candidatePath);
  const baseNorm = isWindows ? base.toLowerCase() : base;
  const candNorm = isWindows ? cand.toLowerCase() : cand;
  const baseWithSep = baseNorm.endsWith(path.sep) ? baseNorm : baseNorm + path.sep;
  return candNorm === baseNorm || candNorm.startsWith(baseWithSep);
}

function makeUniqueLocalRepoName({ accountName, desiredName, fallbackHint }) {
  // Ensures we don't overwrite an existing folder.
  // Returns a sanitized folder name that does not exist yet.
  const safeDesired = sanitizeRepoName(desiredName);
  if (!safeDesired) return null;

  let candidate = safeDesired;
  let candidatePath = getRepoPath(accountName, candidate);
  if (!candidatePath) return null;

  if (!fs.existsSync(candidatePath)) return candidate;

  // If desired name already exists, try with hint first (owner, etc.)
  if (fallbackHint) {
    const hinted = sanitizeRepoName(`${safeDesired}--${fallbackHint}`);
    if (hinted) {
      const hintedPath = getRepoPath(accountName, hinted);
      if (hintedPath && !fs.existsSync(hintedPath)) return hinted;
      candidate = hinted || candidate;
    }
  }

  // Finally add a numeric suffix
  for (let i = 2; i <= 999; i += 1) {
    const suffixed = sanitizeRepoName(`${candidate}-${i}`);
    if (!suffixed) continue;
    const p = getRepoPath(accountName, suffixed);
    if (p && !fs.existsSync(p)) return suffixed;
  }

  return null;
}

function sanitizeBranchName(name) {
  if (!name || typeof name !== "string") return null;
  const clean = name.trim().replace(/[^a-zA-Z0-9\-_.\/]/g, "");
  if (clean.length === 0 || clean.length > 200) return null;
  if (clean.includes("..")) return null;
  return clean;
}

function sanitizeCommitMessage(msg) {
  if (!msg || typeof msg !== "string") return "";
  const trimmed = msg.trim().slice(0, 2048);
  return trimmed.replace(/\r\n/g, "\n").replace(/\n{3,}/g, "\n\n");
}

function sanitizeCommitHash(hash) {
  if (!hash || typeof hash !== "string") return "";
  const trimmed = hash.trim().toLowerCase();
  if (!/^[a-f0-9]+$/.test(trimmed)) return "";
  if (trimmed.length < 7 || trimmed.length > 40) return "";
  return trimmed;
}

function sanitizeStashRef(ref) {
  if (!ref || typeof ref !== "string") return null;
  const trimmed = ref.trim();
  if (!/^stash@\{\d+\}$/.test(trimmed)) return null;
  return trimmed;
}

function runCommand(cmd, cwd = BASE_DIR, timeoutMs = 60000) {
  try {
    const result = execSync(cmd, {
      cwd,
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { success: true, output: result.trim() };
  } catch (err) {
    return {
      success: false,
      output: (err.stdout || "") + (err.stderr || ""),
      error: err.message,
    };
  }
}

// SECURITY: Shell-free command execution for git operations
// Uses execFileSync with array args — no shell interpretation
function runGit(args, cwd = BASE_DIR, timeoutMs = 60000) {
  try {
    const result = execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { success: true, output: result.trim() };
  } catch (err) {
    return {
      success: false,
      output: (err.stdout || "") + (err.stderr || ""),
      error: err.message,
    };
  }
}

// =============================================================================
// GitHub REST API helpers (official)
// =============================================================================
function parseLinkHeader(linkHeader) {
  if (!linkHeader || typeof linkHeader !== "string") return {};
  const out = {};
  const parts = linkHeader.split(",").map((p) => p.trim()).filter(Boolean);
  for (const part of parts) {
    const m = part.match(/^<([^>]+)>\s*;\s*rel="([^"]+)"$/i);
    if (m) out[m[2]] = m[1];
  }
  return out;
}

function githubRequestJson({ method = "GET", url, token, body, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(url);
      const data = body ? JSON.stringify(body) : null;
      const headers = {
        "User-Agent": "GitDock",
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      };
      if (token) headers.Authorization = `Bearer ${token}`;
      if (data) headers["Content-Type"] = "application/json";
      if (data) headers["Content-Length"] = Buffer.byteLength(data);

      const req = https.request(
        {
          method,
          hostname: u.hostname,
          path: u.pathname + u.search,
          headers,
        },
        (res) => {
          let raw = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => { raw += chunk; });
          res.on("end", () => {
            let json = null;
            try { json = raw ? JSON.parse(raw) : null; } catch (e) { json = null; }
            resolve({
              ok: res.statusCode >= 200 && res.statusCode < 300,
              status: res.statusCode,
              headers: res.headers || {},
              json,
              raw,
            });
          });
        }
      );
      req.on("error", reject);
      req.setTimeout(timeoutMs, () => req.destroy(new Error("GitHub request timeout")));
      if (data) req.write(data);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

async function githubListAllPages({ initialUrl, token, maxPages = 50 }) {
  const all = [];
  let url = initialUrl;
  for (let i = 0; i < maxPages; i += 1) {
    const r = await githubRequestJson({ url, token, timeoutMs: 20000 });
    if (!r.ok) return { ok: false, status: r.status, json: r.json, raw: r.raw, items: all };
    if (Array.isArray(r.json)) all.push(...r.json);
    const links = parseLinkHeader(r.headers && r.headers.link);
    if (!links.next) break;
    url = links.next;
  }
  return { ok: true, status: 200, items: all };
}

// Helper: fetch a GitHub API endpoint using token (preferred) or gh CLI (fallback).
// Returns { ok, json, raw } — always resolves, never throws.
async function githubApiForAccount(accountName, apiPath, opts = {}) {
  const account = validateAccount(accountName);
  if (!account) return { ok: false, raw: "Account not found" };
  const token = await getAccountToken(accountName);
  if (token) {
    try {
      const url = `https://api.github.com/${apiPath.replace(/^\//, "")}`;
      const r = await githubRequestJson({ method: opts.method || "GET", url, token, body: opts.body, timeoutMs: opts.timeoutMs || 15000 });
      if (r.ok) return { ok: true, json: r.json, raw: r.raw, source: "token" };
    } catch (e) { /* fall through to gh CLI */ }
  }
  // Fallback: gh CLI
  try {
    const jqArg = opts.jq ? ` --jq "${opts.jq}"` : "";
    const methodArg = opts.method && opts.method !== "GET" ? ` --method ${opts.method}` : "";
    const bodyArgs = opts.ghBodyArgs || "";
    const result = await enqueueGh(account.githubUser, () =>
      runCommand(`gh api${methodArg} "${apiPath}"${bodyArgs}${jqArg}`, BASE_DIR, opts.timeoutMs || 15000)
    );
    if (result.success && result.output) {
      let json = null;
      try { json = JSON.parse(result.output); } catch (e) { /* raw output */ }
      return { ok: true, json, raw: result.output, source: "gh" };
    }
    return { ok: false, raw: result.output || "gh api failed" };
  } catch (e) {
    return { ok: false, raw: e.message };
  }
}

// =============================================================================
// Per-account token storage (no terminal required)
// =============================================================================
async function getAccountToken(accountName) {
  return sessionTokens.get(accountName) || null;
}

async function setAccountToken(accountName, token, remember) {
  sessionTokens.delete(accountName);
  tokenCache.delete(accountName);
  sessionTokens.set(accountName, token);
  return { stored: "session" };
}

async function deleteAccountToken(accountName) {
  sessionTokens.delete(accountName);
  tokenCache.delete(accountName);
}

async function validateAccountToken(accountName, account, token) {
  if (!token) return { ok: false, reason: "missing" };
  const cached = tokenCache.get(accountName);
  const now = Date.now();
  if (cached && (now - cached.checkedAtMs) < TOKEN_CACHE_TTL_MS) return cached;

  const r = await githubRequestJson({ url: "https://api.github.com/user", token, timeoutMs: 15000 });
  if (!r.ok || !r.json || !r.json.login) {
    const res = { ok: false, reason: "invalid", checkedAtMs: now, login: null };
    tokenCache.set(accountName, res);
    return res;
  }
  const login = String(r.json.login);
  const expected = String(account.githubUser || "");
  const ok = login.toLowerCase() === expected.toLowerCase();
  const res = { ok, reason: ok ? "ok" : "mismatch", checkedAtMs: now, login };
  tokenCache.set(accountName, res);
  return res;
}

function switchGHAccount(githubUser) {
  const safe = String(githubUser).replace(/[^a-zA-Z0-9\-_]/g, "");
  // SECURITY: Use execFileSync with array args to avoid shell injection
  try {
    execFileSync("gh", ["auth", "switch", "--user", safe], {
      encoding: "utf8",
      timeout: 15000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return true;
  } catch (err) {
    console.warn(`[gh] Failed to switch to ${safe}: ${(err.message || "").slice(0, 120)}`);
    return false;
  }
}

// Serialize all gh CLI operations so one request cannot switch account while another uses it
let ghQueue = Promise.resolve();
function enqueueGh(githubUser, fn) {
  const p = ghQueue
    .then(() => {
      switchGHAccount(githubUser);
      return fn();
    })
    .catch((err) => {
      throw err;
    });
  ghQueue = p.catch(() => {}); // so queue continues after failure
  return p;
}

function broadcastSSE(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    client.write(msg);
  }
}

// Parse git status --porcelain lines into file list + summary counts (staged/unstaged/untracked/conflict)
function parseStatusPorcelain(output) {
  const lines = output ? output.split("\n").filter(Boolean) : [];
  const files = [];
  let stagedCount = 0, unstagedCount = 0, untrackedCount = 0, conflictCount = 0;
  for (const line of lines) {
    const xy = line.slice(0, 2);
    const x = xy[0], y = xy[1];
    const filePath = line.slice(3).trim().replace(/^["']|["']$/g, "");
    if (filePath) {
      let status = "modified";
      if (xy === "??") status = "untracked";
      else if (x === "A" || x === "M" || x === "D" || x === "R" || x === "C") status = "added";
      else if (y === "M" || y === "D") status = "modified";
      else if (x === "D" || y === "D") status = "deleted";
      else if (x === "U" || y === "U") status = "unmerged";
      files.push({ path: filePath, status });
    }
    if (xy === "??") {
      untrackedCount += 1;
    } else {
      if (x !== " " && x !== "?") stagedCount += 1;
      if (y !== " " && y !== "?") unstagedCount += 1;
      if (x === "U" || y === "U") conflictCount += 1;
    }
  }
  return { files, summary: { stagedCount, unstagedCount, untrackedCount, conflictCount } };
}

// Detect merge or rebase in progress
function getRepoOperation(repoPath) {
  const gitDir = path.join(repoPath, ".git");
  const isMerging = fs.existsSync(path.join(gitDir, "MERGE_HEAD"));
  const isRebasing = fs.existsSync(path.join(gitDir, "rebase-merge")) || fs.existsSync(path.join(gitDir, "rebase-apply"));
  return { isMerging: !!isMerging, isRebasing: !!isRebasing };
}

// Parse "git status -sb" first line for branch, upstream, ahead, behind
function parseStatusBranchLine(line) {
  if (!line || !line.startsWith("## ")) return { branch: "unknown", hasUpstream: false, ahead: 0, behind: 0, upstreamRef: null };
  const rest = line.slice(3).trim();
  const branchMatch = rest.match(/^([^\s.]+)(?:\.\.\.(\S+))?(?:\s+\[(.*)\])?/);
  const branch = branchMatch ? branchMatch[1] : "unknown";
  const upstreamRef = branchMatch && branchMatch[2] ? branchMatch[2] : null;
  const bracket = branchMatch && branchMatch[3] ? branchMatch[3] : "";
  let ahead = 0, behind = 0;
  const aheadM = bracket.match(/ahead\s+(\d+)/);
  const behindM = bracket.match(/behind\s+(\d+)/);
  if (aheadM) ahead = parseInt(aheadM[1], 10) || 0;
  if (behindM) behind = parseInt(behindM[1], 10) || 0;
  return { branch, hasUpstream: !!upstreamRef, ahead, behind, upstreamRef };
}

function getRepoStatus(repoPath) {
  if (!fs.existsSync(repoPath)) return null;

  const statusPorcelain = runCommand("git status --porcelain", repoPath);
  const statusSb = runCommand("git status -sb", repoPath);
  const firstLine = statusSb.success && statusSb.output ? statusSb.output.split("\n")[0] : "";
  const { branch, hasUpstream, ahead, behind, upstreamRef } = parseStatusBranchLine(firstLine);

  const { files: changedFilesList, summary } = parseStatusPorcelain(statusPorcelain.output);
  const operation = getRepoOperation(repoPath);
  const lastCommit = runCommand(
    'git log -1 --format="%ar|||%s|||%an|||%aI"',
    repoPath
  );

  let lastCommitData = {};
  if (lastCommit.success && lastCommit.output) {
    const parts = lastCommit.output.split("|||");
    lastCommitData = {
      timeAgo: parts[0] || "",
      message: parts[1] || "",
      author: parts[2] || "",
      date: parts[3] || "",
    };
  }

  const isClean = changedFilesList.length === 0 && !operation.isMerging && !operation.isRebasing;

  let localStatus = "clean";
  if (operation.isMerging || operation.isRebasing) localStatus = "dirty";
  else if (changedFilesList.length > 0) localStatus = "dirty";
  else if (ahead > 0) localStatus = "ahead";
  else if (behind > 0) localStatus = "behind";

  return {
    branch: branch.trim() || "unknown",
    localStatus,
    isClean,
    ahead,
    behind,
    lastCommit: lastCommitData,
    changedFiles: changedFilesList.map((f) => (f.status + " " + f.path).trim()),
    summary: summary || { stagedCount: 0, unstagedCount: 0, untrackedCount: 0, conflictCount: 0 },
    operation,
    upstream: { hasUpstream, upstreamRef, ahead, behind },
  };
}

// =============================================================================
// API ROUTES
// =============================================================================

// --- Account CRUD ---
app.get("/api/accounts", (req, res) => {
  try {
    const config = loadConfig();
    const list = Object.entries(config.accounts || {}).map(([name, acc]) => ({
      name,
      githubUser: acc.githubUser,
      sshHost: acc.sshHost || `github.com-${name}`,
      label: acc.label || name,
      email: acc.email || "",
    }));
    return res.json({ accounts: list });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post("/api/accounts", (req, res) => {
  try {
    const { name: rawName, githubUser, label, email, sshHost } = req.body || {};
    const name = sanitizeAccountName(String(rawName || "").trim());
    if (!name) return res.status(400).json({ error: "Invalid account name (use alphanumeric and hyphens only)" });
    const config = loadConfig();
    if (config.accounts[name]) return res.status(409).json({ error: "Account already exists" });
    const safeUser = sanitizeOwnerName(githubUser);
    if (!safeUser) return res.status(400).json({ error: "Invalid GitHub username" });
    const safeSshHost =
      sshHost === undefined || sshHost === null || String(sshHost).trim() === ""
        ? `github.com-${name}`
        : sanitizeSshHostAlias(String(sshHost));
    if (!safeSshHost) return res.status(400).json({ error: "Invalid SSH host alias" });
    config.accounts[name] = {
      githubUser: safeUser,
      sshHost: safeSshHost,
      label: (label && String(label).trim().replace(/[\x00-\x1f]/g, "").slice(0, 128)) || name,
      email: (email && String(email).trim().replace(/[\x00-\x1f]/g, "").slice(0, 256)) || "",
    };
    saveConfig(config);
    writeGitconfigForAccount(name);
    syncManagedSshConfigToAccounts();
    return res.json({ ok: true, account: config.accounts[name] });
  } catch (e) {
    console.error("[accounts] Create error:", e);
    return res.status(500).json({ error: "Failed to create account" });
  }
});

app.put("/api/accounts/:name", (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ error: "Invalid account name" });
    const config = loadConfig();
    if (!config.accounts[name]) return res.status(404).json({ error: "Account not found" });
    const { githubUser, label, email, sshHost } = req.body || {};
    if (githubUser !== undefined) {
      const safe = sanitizeOwnerName(githubUser);
      if (!safe) return res.status(400).json({ error: "Invalid GitHub username" });
      config.accounts[name].githubUser = safe;
    }
    if (label !== undefined) config.accounts[name].label = String(label).trim().replace(/[\x00-\x1f]/g, "").slice(0, 128);
    if (email !== undefined) config.accounts[name].email = String(email).trim().replace(/[\x00-\x1f]/g, "").slice(0, 256);
    if (sshHost !== undefined) {
      const safeSshHost =
        sshHost === null || String(sshHost).trim() === ""
          ? `github.com-${name}`
          : sanitizeSshHostAlias(String(sshHost));
      if (!safeSshHost) return res.status(400).json({ error: "Invalid SSH host alias" });
      config.accounts[name].sshHost = safeSshHost;
    }
    saveConfig(config);
    writeGitconfigForAccount(name);
    syncManagedSshConfigToAccounts();
    return res.json({ ok: true, account: config.accounts[name] });
  } catch (e) {
    console.error("[accounts] Update error:", e);
    return res.status(500).json({ error: "Failed to update account" });
  }
});

app.delete("/api/accounts/:name", async (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ error: "Account not found" });

    // Always remove stored token for this account (keychain/session).
    await deleteAccountToken(name);

    // Remove per-account gitconfig file (safe, auto-generated).
    try {
      const gitconfigPath = path.join(BASE_DIR, `.gitconfig-${name}`);
      if (fs.existsSync(gitconfigPath)) fs.unlinkSync(gitconfigPath);
    } catch (e) { /* ignore */ }

    if (!fs.existsSync(account.localDir)) {
      const config = loadConfig();
      delete config.accounts[name];
      saveConfig(config);

      // Rewrite managed SSH config block to avoid stale Host entries.
      try {
        const accountsWithDirs = {};
        for (const [n, acc] of Object.entries(config.accounts || {})) {
          accountsWithDirs[n] = { ...acc, localDir: path.join(BASE_DIR, n) };
        }
        writeSSHConfigBlock(accountsWithDirs);
      } catch (e) { /* ignore */ }

      return res.json({ ok: true });
    }
    const dirs = fs.readdirSync(account.localDir, { withFileTypes: true });
    const subdirs = dirs.filter((d) => d.isDirectory() && !d.name.startsWith("."));
    if (subdirs.length > 0) {
      const force = req.query.force === "true" || req.query.force === "1";
      if (!force) {
        return res.status(400).json({
          error: "Account has cloned repositories. Remove them first or use ?force=true",
          repoCount: subdirs.length,
        });
      }
    }
    const config = loadConfig();
    delete config.accounts[name];
    saveConfig(config);

    // Rewrite managed SSH config block to avoid stale Host entries.
    try {
      const accountsWithDirs = {};
      for (const [n, acc] of Object.entries(config.accounts || {})) {
        accountsWithDirs[n] = { ...acc, localDir: path.join(BASE_DIR, n) };
      }
      writeSSHConfigBlock(accountsWithDirs);
    } catch (e) { /* ignore */ }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// --- Account Auth (GitHub REST API token; session storage) ---
app.post("/api/accounts/:name/auth/token", async (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ ok: false, error: "Account not found" });

    const token = String((req.body && req.body.token) || "").trim();
    const remember = !!(req.body && req.body.remember);
    if (!token || token.length < 10) return res.status(400).json({ ok: false, error: "Token is required" });

    const validation = await validateAccountToken(name, account, token);
    if (!validation.ok) {
      if (validation.reason === "mismatch") {
        return res.status(400).json({ ok: false, error: `Token belongs to ${validation.login}, expected ${account.githubUser}` });
      }
      return res.status(401).json({ ok: false, error: "Invalid token" });
    }

    const stored = await setAccountToken(name, token, remember);
    return res.json({ ok: true, login: validation.login, stored: stored.stored });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.delete("/api/accounts/:name/auth/token", async (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ ok: false, error: "Account not found" });
    await deleteAccountToken(name);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/accounts/:name/auth/status", async (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ ok: false, error: "Account not found" });
    const token = await getAccountToken(name);
    if (!token) return res.json({ ok: true, connected: false });
    const validation = await validateAccountToken(name, account, token);
    return res.json({ ok: true, connected: !!validation.ok, login: validation.login || null, reason: validation.reason });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/accounts/:name/status", async (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ error: "Account not found" });

    // Ensure SSH config is up-to-date before checking (fixes stale state after manual key adds)
    syncManagedSshConfigToAccounts();

    const sshDir = getSSHDir();
    const keyFile = path.join(sshDir, `id_ed25519_${name}`);
    const sshConfigPath = path.join(sshDir, "config");
    const gitconfigPath = path.join(BASE_DIR, `.gitconfig-${name}`);

    const sshKeyExists = fs.existsSync(keyFile);
    let sshConfigured = false;
    if (fs.existsSync(sshConfigPath)) {
      const configContent = fs.readFileSync(sshConfigPath, "utf8");
      const host = sanitizeSshHostAlias(account.sshHost) || `github.com-${name}`;
      // Windows SSH config commonly uses backslashes in IdentityFile; normalize and parse the Host block
      // so we don't false-negative a valid configuration.
      const lines = configContent.split(/\r?\n/);
      const keyBasename = path.basename(keyFile);
      let inTargetHost = false;
      let hostFound = false;
      let identityMatches = false;
      for (const rawLine of lines) {
        const trimmed = String(rawLine || "").trim();
        if (!trimmed) continue;
        const hostMatch = trimmed.match(/^Host\s+(.+)$/i);
        if (hostMatch) {
          const hosts = hostMatch[1].trim().split(/\s+/).filter(Boolean);
          inTargetHost = hosts.includes(host);
          if (inTargetHost) hostFound = true;
          continue;
        }
        if (!inTargetHost) continue;
        const idMatch = trimmed.match(/^IdentityFile\s+(.+)$/i);
        if (idMatch) {
          const val = idMatch[1].trim();
          const normVal = val.replace(/\\/g, "/");
          const normKey = keyFile.replace(/\\/g, "/");
          if (
            normVal === normKey ||
            normVal.endsWith("/" + keyBasename) ||
            normVal.includes(keyBasename)
          ) {
            identityMatches = true;
          }
        }
      }
      sshConfigured = hostFound && identityMatches;
    }

    let sshConnects = false;
    if (sshKeyExists && sshConfigured) {
      const host = sanitizeSshHostAlias(account.sshHost) || `github.com-${name}`;
      // IMPORTANT: ssh -T exits with code 1 even on successful auth (GitHub message),
      // so we must not treat non-zero as failure by itself.
      const r = spawnSync("ssh", ["-T", `git@${host}`], { cwd: BASE_DIR, encoding: "utf8", timeout: 10000 });
      const out = String((r.stdout || "") + (r.stderr || "")).trim();
      sshConnects = out.includes("successfully authenticated");
    }

    let ghAuthenticated = false;
    let ghActive = false;
    try {
      // Use JSON output to avoid format/regEx drift across gh versions.
      // gh supports multiple logged-in accounts; only one is active at a time.
      const gh = runCommand("gh auth status --json hosts", BASE_DIR, 7000);
      if (gh.success && gh.output) {
        const parsed = JSON.parse(gh.output);
        const hostEntries = parsed && parsed.hosts && parsed.hosts["github.com"];
        if (Array.isArray(hostEntries)) {
          const match = hostEntries.find((e) => e && e.login === account.githubUser);
          ghAuthenticated = !!(match && match.state === "success");
          ghActive = !!(match && match.active === true);
        }
      }
    } catch (e) { /* ignore */ }

    // Token-based auth (preferred when available; no terminal required)
    let tokenAuthenticated = false;
    let tokenLogin = null;
    try {
      const token = await getAccountToken(name);
      if (token) {
        const validation = await validateAccountToken(name, account, token);
        tokenAuthenticated = !!validation.ok;
        tokenLogin = validation.login || null;
      }
    } catch (e) { /* ignore */ }

    const gitconfigExists = fs.existsSync(gitconfigPath);
    const hasAuth = Boolean(tokenAuthenticated || ghAuthenticated);
    const ready = Boolean(sshKeyExists && sshConfigured && sshConnects && hasAuth && gitconfigExists);

    res.set("Cache-Control", "no-store, no-cache, must-revalidate");
    return res.json({
      accountName: name,
      sshKeyExists,
      sshConfigured,
      sshConnects,
      ghAuthenticated,
      ghActive,
      tokenAuthenticated,
      tokenLogin,
      gitconfigExists,
      ready,
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

function ensureSSHDir() {
  const sshDir = getSSHDir();
  if (!fs.existsSync(sshDir)) fs.mkdirSync(sshDir, { recursive: true });
  return sshDir;
}

function writeSSHConfigBlock(accounts) {
  const sshDir = getSSHDir();
  const configPath = path.join(sshDir, "config");
  let existing = "";
  if (fs.existsSync(configPath)) existing = fs.readFileSync(configPath, "utf8");
  const marker = SSH_MARKER;
  const markerEnd = SSH_MARKER_END;
  // Remove any existing managed blocks to avoid duplicates/stale hosts.
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const reCurrent = new RegExp(`${escapeRe(marker)}[\\s\\S]*?${escapeRe(markerEnd)}`, "g");
  const cleaned = existing.replace(reCurrent, "").trimEnd();
  const lines = [""];
  lines.push(marker);
  for (const [accName, acc] of Object.entries(accounts)) {
    const keyPath = path.join(sshDir, `id_ed25519_${accName}`);
    const host = sanitizeSshHostAlias(acc.sshHost) || `github.com-${accName}`;
    lines.push("");
    lines.push(`Host ${host}`);
    lines.push("    HostName github.com");
    lines.push("    User git");
    lines.push(`    IdentityFile ${keyPath.replace(/\\/g, "/")}`);
    lines.push("    IdentitiesOnly yes");
  }
  lines.push("");
  lines.push(markerEnd);
  lines.push("");
  const block = lines.join("\n");
  fs.writeFileSync(configPath, cleaned + block, "utf8");
}

function cleanupOrphanedGitconfigs() {
  try {
    const config = loadConfig();
    const keep = new Set(Object.keys(config.accounts || {}));
    const files = fs.readdirSync(BASE_DIR);
    for (const file of files) {
      if (!file.startsWith(".gitconfig-")) continue;
      const accountName = file.slice(".gitconfig-".length);
      if (!accountName || keep.has(accountName)) continue;
      const full = path.join(BASE_DIR, file);
      try {
        const content = fs.readFileSync(full, "utf8");
        // Only delete files that look auto-generated by GitDock.
        if (content.includes("This file is auto-included when working inside the") && content.startsWith("# Git config for")) {
          fs.unlinkSync(full);
        }
      } catch (e) { /* ignore */ }
    }
  } catch (e) { /* ignore */ }
}

function syncManagedSshConfigToAccounts() {
  try {
    const config = loadConfig();
    const accountsWithDirs = {};
    for (const [n, acc] of Object.entries(config.accounts || {})) {
      accountsWithDirs[n] = { ...acc, localDir: path.join(BASE_DIR, n) };
    }
    writeSSHConfigBlock(accountsWithDirs);
  } catch (e) { /* ignore */ }
}

app.post("/api/accounts/:name/setup-ssh", (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ error: "Account not found" });

    const sshDir = ensureSSHDir();
    const keyFile = path.join(sshDir, `id_ed25519_${name}`);
    const comment = `${account.githubUser}@github-${name}`;

    if (!fs.existsSync(keyFile)) {
      execFileSync(
        "ssh-keygen",
        ["-t", "ed25519", "-C", comment, "-f", keyFile, "-N", ""],
        { encoding: "utf8", timeout: 30000 }
      );
    }

    const config = loadConfig();
    const accountsWithDirs = {};
    for (const [n, acc] of Object.entries(config.accounts || {})) {
      accountsWithDirs[n] = { ...acc, localDir: path.join(BASE_DIR, n) };
    }
    writeSSHConfigBlock(accountsWithDirs);

    const pubPath = `${keyFile}.pub`;
    const publicKey = fs.existsSync(pubPath) ? fs.readFileSync(pubPath, "utf8").trim() : "";
    return res.json({ ok: true, publicKey });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// --- GET /api/accounts/:name/ssh/public-key - Return SSH public key for this account (safe to display) ---
app.get("/api/accounts/:name/ssh/public-key", (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ ok: false, error: "Account not found" });

    const sshDir = getSSHDir();
    const pubPath = path.join(sshDir, `id_ed25519_${name}.pub`);
    if (!fs.existsSync(pubPath)) return res.json({ ok: true, exists: false, publicKey: "" });

    const publicKey = fs.readFileSync(pubPath, "utf8").trim();
    res.set("Cache-Control", "no-store, no-cache, must-revalidate");
    return res.json({ ok: true, exists: !!publicKey, publicKey });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// --- POST /api/accounts/:name/github/ssh-key - Upload SSH key via GitHub REST API (no terminal) ---
app.post("/api/accounts/:name/github/ssh-key", async (req, res) => {
  try {
    const name = sanitizeAccountName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "Invalid account name" });
    const account = validateAccount(name);
    if (!account) return res.status(404).json({ ok: false, error: "Account not found" });

    const token = await getAccountToken(name);
    if (!token) return res.status(401).json({ ok: false, error: "Account not connected. Add a GitHub token first." });
    const v = await validateAccountToken(name, account, token);
    if (!v.ok) return res.status(401).json({ ok: false, error: "Invalid token for this account" });

    const sshDir = getSSHDir();
    const keyFile = path.join(sshDir, `id_ed25519_${name}`);
    const pubPath = `${keyFile}.pub`;
    if (!fs.existsSync(pubPath)) return res.status(400).json({ ok: false, error: "Public key not found. Generate SSH key first." });
    const publicKey = fs.readFileSync(pubPath, "utf8").trim();
    if (!publicKey) return res.status(400).json({ ok: false, error: "Public key is empty" });

    const title = String((req.body && req.body.title) || `GitDock (${os.hostname()}) - ${name}`).slice(0, 200);

    const create = await githubRequestJson({
      method: "POST",
      url: "https://api.github.com/user/keys",
      token,
      body: { title, key: publicKey },
      timeoutMs: 20000,
    });

    if (create.ok) return res.json({ ok: true, created: true });

    // If 422, key may already exist. Verify by listing keys and matching the exact key string.
    if (create.status === 422) {
      const list = await githubListAllPages({ initialUrl: "https://api.github.com/user/keys?per_page=100&page=1", token });
      if (list.ok) {
        const exists = list.items.some((k) => k && String(k.key || "").trim() === publicKey);
        if (exists) return res.json({ ok: true, created: false, alreadyExists: true });
      }
    }

    return res.status(400).json({ ok: false, error: "Failed to upload SSH key", status: create.status });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// --- GET /api/repos - List all repos from both accounts ---
// (Does not use gh queue so list does not block README; README uses queue for correct account)
app.get("/api/repos", async (req, res) => {
  try {
    const allRepos = [];
    const seen = new Set(); // key: account/name
    const accountErrors = {}; // track per-account issues for the frontend

    // Determine which GitHub users are authenticated in gh CLI (and which is active).
    // This is the only reliable way to know if private repos can be listed for a given user.
    const ghAuthedLogins = new Set();
    try {
      const gh = runCommand("gh auth status --json hosts", BASE_DIR, 7000);
      if (gh.success && gh.output) {
        const parsed = JSON.parse(gh.output);
        const hostEntries = parsed && parsed.hosts && parsed.hosts["github.com"];
        if (Array.isArray(hostEntries)) {
          for (const e of hostEntries) {
            if (e && e.state === "success" && e.login) ghAuthedLogins.add(String(e.login));
          }
        }
      }
    } catch (e) {
      // ignore; we'll fall back to public API
    }

    const mapRestRepoToGhLike = (r) => ({
      name: r.name,
      description: r.description || "",
      isPrivate: !!r.private,
      primaryLanguage: r.language ? { name: r.language } : null,
      updatedAt: r.updated_at || "",
      url: r.html_url || "",
      stargazerCount: r.stargazers_count || 0,
      forkCount: r.forks_count || 0,
      diskUsage: r.size || 0,
    });

    for (const [accountName, account] of Object.entries(getAccounts())) {
      let repos = [];
      const safeUser = String(account.githubUser).replace(/[^a-zA-Z0-9\-_]/g, "");

      // 1) Prefer token-based auth (no terminal required; includes private repos).
      const token = await getAccountToken(accountName);
      if (token) {
        try {
          const v = await validateAccountToken(accountName, account, token);
          if (v.ok) {
            const url = "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner&page=1";
            const result = await githubListAllPages({ initialUrl: url, token });
            if (result.ok) {
              repos = result.items
                .filter((r) => r && r.owner && String(r.owner.login || "").toLowerCase() === safeUser.toLowerCase())
                .map(mapRestRepoToGhLike);
            } else {
              accountErrors[accountName] = "token_failed";
            }
          } else {
            accountErrors[accountName] = v.reason === "mismatch" ? "token_mismatch" : "token_invalid";
          }
        } catch (e) {
          accountErrors[accountName] = "token_failed";
        }
      }

      // 2) If no token repos, try gh CLI if authenticated (includes private repos).
      if (repos.length === 0) {
        const isGhAuthed = ghAuthedLogins.has(safeUser);
        if (isGhAuthed) {
          try {
            const result = await enqueueGh(safeUser, () =>
              runCommand(
                `gh repo list ${safeUser} --json name,description,isPrivate,primaryLanguage,updatedAt,url,stargazerCount,forkCount,diskUsage --limit 100`,
                BASE_DIR,
                20000
              )
            );
            if (result.success) {
              const parsed = JSON.parse(result.output || "[]");
              repos = Array.isArray(parsed) ? parsed : [];
            } else {
              accountErrors[accountName] = accountErrors[accountName] || "gh_failed";
            }
          } catch (e) {
            accountErrors[accountName] = accountErrors[accountName] || "gh_failed";
          }
        } else if (!accountErrors[accountName]) {
          accountErrors[accountName] = "auth_required";
        }
      }

      // No public fallback — repos only load with proper authentication (token or gh CLI).
      // This keeps the flow clean: no auth = no repos.

      for (const repo of repos) {
        const localPath = path.join(account.localDir, repo.name);
        const isCloned = fs.existsSync(localPath) && fs.existsSync(path.join(localPath, ".git"));
        let localInfo = null;

        if (isCloned) {
          localInfo = getRepoStatus(localPath);
        }

        const entry = {
          name: repo.name,
          account: accountName,
          githubUser: account.githubUser,
          description: repo.description || "",
          language: repo.primaryLanguage?.name || "",
          visibility: repo.isPrivate ? "private" : "public",
          url: repo.url || `https://github.com/${account.githubUser}/${repo.name}`,
          stars: repo.stargazerCount || 0,
          forks: repo.forkCount || 0,
          updatedAt: repo.updatedAt || "",
          diskUsage: repo.diskUsage || 0,
          isCloned,
          ...(isCloned ? { localPath: path.resolve(localPath) } : {}),
          ...(localInfo || {
            localStatus: "not_cloned",
            branch: "",
            ahead: 0,
            behind: 0,
            lastCommit: {},
          }),
        };

        allRepos.push(entry);
        seen.add(`${accountName}/${repo.name}`);
      }
    }

    // Include any locally cloned repos that are NOT owned by the accounts (e.g. external/public repos).
    // These won't appear in gh repo list, but users still want them on the dashboard once cloned.
    for (const [accountName, account] of Object.entries(getAccounts())) {
      if (!fs.existsSync(account.localDir)) continue;
      const dirs = fs.readdirSync(account.localDir, { withFileTypes: true });
      for (const dir of dirs) {
        if (!dir.isDirectory()) continue;
        // SECURITY: prevent directory traversal via folder names like ".."
        if (!dir.name || dir.name.includes("..")) continue;
        const repoPath = path.join(account.localDir, dir.name);
        if (!isPathInsideDir(account.localDir, repoPath)) continue;
        if (!fs.existsSync(path.join(repoPath, ".git"))) continue;
        const key = `${accountName}/${dir.name}`;
        if (seen.has(key)) continue;

        const status = getRepoStatus(repoPath) || {};
        const origin = runCommand("git config --get remote.origin.url", repoPath, 5000);
        const remoteUrl = origin.success ? String(origin.output || "").trim() : "";
        const parsed = parseGitHubOwnerRepoFromRemote(remoteUrl);
        const owner = parsed ? parsed.owner : account.githubUser;
        const remoteRepo = parsed ? parsed.repo : dir.name;

        let meta = null;
        if (parsed) {
          try {
            const metaResult = await enqueueGh(account.githubUser, () =>
              runCommand(
                `gh repo view ${owner}/${remoteRepo} --json name,description,isPrivate,primaryLanguage,updatedAt,url,stargazerCount,forkCount,diskUsage`,
                BASE_DIR,
                15000
              )
            );
            if (metaResult.success && metaResult.output) {
              meta = JSON.parse(metaResult.output);
            }
          } catch (e) {
            meta = null;
          }
        }

        allRepos.push({
          name: dir.name,
          account: accountName,
          githubUser: owner,
          description: (meta && meta.description) ? meta.description : "",
          language: meta && meta.primaryLanguage ? (meta.primaryLanguage.name || "") : "",
          visibility: meta ? (meta.isPrivate ? "private" : "public") : "public",
          url: (meta && meta.url) ? meta.url : (parsed ? `https://github.com/${owner}/${remoteRepo}` : ""),
          stars: (meta && meta.stargazerCount) ? meta.stargazerCount : 0,
          forks: (meta && meta.forkCount) ? meta.forkCount : 0,
          updatedAt: (meta && meta.updatedAt) ? meta.updatedAt : ((status.lastCommit && status.lastCommit.date) ? status.lastCommit.date : ""),
          diskUsage: (meta && meta.diskUsage) ? meta.diskUsage : 0,
          isCloned: true,
          localPath: path.resolve(repoPath),
          localStatus: status.localStatus || "clean",
          branch: status.branch || "",
          ahead: status.ahead || 0,
          behind: status.behind || 0,
          lastCommit: status.lastCommit || {},
          changedFiles: status.changedFiles || [],
          summary: status.summary || { stagedCount: 0, unstagedCount: 0, untrackedCount: 0, conflictCount: 0 },
          operation: status.operation || { isMerging: false, isRebasing: false },
          upstream: status.upstream || { hasUpstream: false, upstreamRef: null, ahead: status.ahead || 0, behind: status.behind || 0 },
        });
        seen.add(key);
      }
    }

    res.json({
      success: true,
      repos: allRepos,
      accountErrors: Object.keys(accountErrors).length > 0 ? accountErrors : undefined,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- GET /api/repos/local - List only locally cloned repos ---
app.get("/api/repos/local", (req, res) => {
  try {
    const localRepos = [];

    for (const [accountName, account] of Object.entries(getAccounts())) {
      if (!fs.existsSync(account.localDir)) continue;

      const dirs = fs.readdirSync(account.localDir, { withFileTypes: true });
      for (const dir of dirs) {
        if (!dir.isDirectory()) continue;
        // SECURITY: prevent directory traversal via folder names like ".."
        if (!dir.name || dir.name.includes("..")) continue;
        const repoPath = path.join(account.localDir, dir.name);
        if (!isPathInsideDir(account.localDir, repoPath)) continue;
        if (!fs.existsSync(path.join(repoPath, ".git"))) continue;

        const status = getRepoStatus(repoPath);
        localRepos.push({
          name: dir.name,
          account: accountName,
          githubUser: account.githubUser,
          path: repoPath,
          ...status,
        });
      }
    }

    res.json({ success: true, repos: localRepos });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- POST /api/repos/clone - Clone a repo ---
app.post("/api/repos/clone", (req, res) => {
  const { account: accountName, repoName } = req.body;
  const account = validateAccount(accountName);
  const safeName = sanitizeRepoName(repoName);

  if (!account || !safeName) {
    return res.status(400).json({ success: false, error: "Invalid account or repo name" });
  }

  const targetPath = getRepoPath(accountName, safeName);
  if (!targetPath) {
    return res.status(400).json({ success: false, error: "Invalid path" });
  }

  if (fs.existsSync(targetPath)) {
    return res.status(409).json({ success: false, error: "Repo already cloned locally" });
  }

  const cloneUrl = `git@${account.sshHost}:${account.githubUser}/${safeName}.git`;
  const opId = `clone-${safeName}-${Date.now()}`;

  activeOperations.set(opId, { type: "clone", repo: safeName, status: "running" });
  broadcastSSE({ type: "operation_start", opId, operation: "clone", repo: safeName });

  // Run clone in background
  const child = spawn("git", ["clone", cloneUrl, targetPath], {
    cwd: BASE_DIR,
    stdio: ["pipe", "pipe", "pipe"],
  });

  let output = "";

  child.stdout.on("data", (data) => {
    output += data.toString();
    broadcastSSE({ type: "operation_progress", opId, data: data.toString() });
  });

  child.stderr.on("data", (data) => {
    output += data.toString();
    broadcastSSE({ type: "operation_progress", opId, data: data.toString() });
  });

  child.on("close", (code) => {
    const success = code === 0;
    broadcastSSE({
      type: "operation_complete",
      opId,
      success,
      repo: safeName,
      operation: "clone",
    });
    // Cleanup: remove from active operations after a short delay
    setTimeout(() => { activeOperations.delete(opId); }, 30000);
    if (activeOperations.size > MAX_ACTIVE_OPS) {
      const oldest = activeOperations.keys().next().value;
      if (oldest) activeOperations.delete(oldest);
    }
  });

  res.json({ success: true, opId, message: `Cloning ${safeName}...` });
});

// --- POST /api/repos/clone-url - Clone any GitHub repo by URL into chosen account folder ---
app.post("/api/repos/clone-url", (req, res) => {
  const { account: accountName, url, folderName } = req.body || {};
  const account = validateAccount(accountName);
  if (!account) return res.status(400).json({ success: false, error: "Invalid account" });

  const parsed = parseGitHubRepoUrl(url);
  if (!parsed) {
    return res.status(400).json({ success: false, error: "Invalid GitHub repository URL" });
  }

  const owner = parsed.owner;
  const repo = parsed.repo;
  const safeRepoName = sanitizeRepoName(repo);
  if (!safeRepoName) return res.status(400).json({ success: false, error: "Invalid repo name" });

  let desiredFolder = safeRepoName;
  let usedCustomFolder = false;
  if (folderName != null && String(folderName).trim().length > 0) {
    const safeFolder = sanitizeRepoName(String(folderName).trim());
    if (!safeFolder) return res.status(400).json({ success: false, error: "Invalid local folder name" });
    desiredFolder = safeFolder;
    usedCustomFolder = true;
  }

  // Ensure account folder exists
  try {
    fs.mkdirSync(account.localDir, { recursive: true });
  } catch (e) {
    return res.status(500).json({ success: false, error: "Failed to create account directory" });
  }

  const uniqueFolder = makeUniqueLocalRepoName({
    accountName,
    desiredName: desiredFolder,
    fallbackHint: usedCustomFolder ? null : owner,
  });
  if (!uniqueFolder) {
    return res.status(500).json({ success: false, error: "Failed to allocate a unique local folder name" });
  }

  const targetPath = getRepoPath(accountName, uniqueFolder);
  if (!targetPath) {
    return res.status(400).json({ success: false, error: "Invalid target path" });
  }
  // (Should be unique already, but keep a safety check)
  if (fs.existsSync(targetPath)) return res.status(409).json({ success: false, error: "Target folder already exists" });

  // Force cloning via the account SSH host alias to ensure the right key is used
  const cloneUrl = `git@${account.sshHost}:${owner}/${safeRepoName}.git`;
  const opId = `clone-url-${uniqueFolder}-${Date.now()}`;

  activeOperations.set(opId, { type: "clone-url", repo: uniqueFolder, status: "running" });
  broadcastSSE({ type: "operation_start", opId, operation: "clone-url", repo: uniqueFolder });

  const child = spawn("git", ["clone", cloneUrl, targetPath], {
    cwd: BASE_DIR,
    stdio: ["pipe", "pipe", "pipe"],
  });

  let output = "";
  child.stdout.on("data", (data) => {
    output += data.toString();
    broadcastSSE({ type: "operation_progress", opId, data: data.toString() });
  });
  child.stderr.on("data", (data) => {
    output += data.toString();
    broadcastSSE({ type: "operation_progress", opId, data: data.toString() });
  });
  child.on("close", (code) => {
    const success = code === 0;
    broadcastSSE({ type: "operation_complete", opId, success, repo: uniqueFolder, operation: "clone-url" });
    setTimeout(() => { activeOperations.delete(opId); }, 30000);
  });

  res.json({
    success: true,
    opId,
    repo: uniqueFolder,
    desiredFolder,
    usedFolder: uniqueFolder,
    message: `Cloning ${owner}/${safeRepoName} into ${uniqueFolder}...`,
  });
});

// --- POST /api/repos/pull - Pull updates for a repo ---
app.post("/api/repos/pull", (req, res) => {
  const { account: accountName, repoName } = req.body;
  const repoPath = getRepoPath(accountName, repoName);

  if (!repoPath || !fs.existsSync(repoPath)) {
    return res.status(400).json({ success: false, error: "Repo not found locally" });
  }

  // Check for uncommitted changes
  const status = getRepoStatus(repoPath);
  if (!status.isClean) {
    return res.status(409).json({
      success: false,
      error: "Repo has uncommitted changes. Commit or stash first.",
      changedFiles: status.changedFiles,
    });
  }

  const fetchResult = runCommand("git fetch --all", repoPath);
  const pullResult = runCommand("git pull", repoPath);

  res.json({
    success: pullResult.success,
    output: pullResult.output,
    fetchOutput: fetchResult.output,
  });
});

// --- POST /api/repos/fetch - Fetch updates (no merge) ---
app.post("/api/repos/fetch", (req, res) => {
  const { account: accountName, repoName } = req.body;
  const repoPath = getRepoPath(accountName, repoName);

  if (!repoPath || !fs.existsSync(repoPath)) {
    return res.status(400).json({ success: false, error: "Repo not found locally" });
  }

  const result = runCommand("git fetch --all", repoPath);
  const status = getRepoStatus(repoPath);

  res.json({ success: result.success, status });
});

// --- POST /api/repos/remove - Remove local clone safely ---
app.post("/api/repos/remove", (req, res) => {
  const { account: accountName, repoName, force } = req.body;
  const repoPath = getRepoPath(accountName, repoName);

  if (!repoPath || !fs.existsSync(repoPath)) {
    return res.status(400).json({ success: false, error: "Repo not found locally" });
  }

  // Safety check
  runCommand("git fetch --quiet", repoPath);
  const status = getRepoStatus(repoPath);

  if (!status.isClean && !force) {
    return res.status(409).json({
      success: false,
      error: "Repo has uncommitted changes",
      requiresForce: true,
      changedFiles: status.changedFiles,
    });
  }

  if (status.ahead > 0 && !force) {
    return res.status(409).json({
      success: false,
      error: `Repo has ${status.ahead} unpushed commit(s)`,
      requiresForce: true,
    });
  }

  try {
    fs.rmSync(repoPath, { recursive: true, force: true });
    broadcastSSE({
      type: "operation_complete",
      success: true,
      repo: repoName,
      operation: "remove",
    });
    res.json({ success: true, message: `${repoName} removed from local. Still safe on GitHub.` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- POST /api/repos/pull-all - Pull all local repos ---
app.post("/api/repos/pull-all", (req, res) => {
  const results = [];

  for (const [accountName, account] of Object.entries(getAccounts())) {
    if (!fs.existsSync(account.localDir)) continue;

    const dirs = fs.readdirSync(account.localDir, { withFileTypes: true });
    for (const dir of dirs) {
      if (!dir.isDirectory()) continue;
      const repoPath = path.join(account.localDir, dir.name);
      if (!fs.existsSync(path.join(repoPath, ".git"))) continue;

      const status = getRepoStatus(repoPath);

      if (!status.isClean) {
        results.push({ name: dir.name, account: accountName, success: false, reason: "uncommitted changes" });
        continue;
      }

      runCommand("git fetch --all", repoPath);
      const pull = runCommand("git pull", repoPath);
      results.push({ name: dir.name, account: accountName, success: pull.success, output: pull.output });
    }
  }

  res.json({ success: true, results });
});

// --- POST /api/repos/migrate - Migrate existing repo into structure ---
app.post("/api/repos/migrate", (req, res) => {
  const { sourcePath, account: accountName, repoName } = req.body;

  const account = validateAccount(accountName);
  if (!account) {
    return res.status(400).json({ success: false, error: "Invalid account" });
  }

  const safeName = sanitizeRepoName(repoName);
  if (!safeName) {
    return res.status(400).json({ success: false, error: "Invalid repo name" });
  }

  // SECURITY: Validate source path
  if (!sourcePath || typeof sourcePath !== "string") {
    return res.status(400).json({ success: false, error: "Invalid source path" });
  }

  // Normalize and validate: must be under user's home directory or common dev paths
  const normalizedSource = path.resolve(sourcePath);
  const userHome = os.homedir();
  if (!isPathInsideDir(userHome, normalizedSource)) {
    return res.status(403).json({ success: false, error: "Source path must be within your user directory" });
  }

  // Block system/sensitive directories (platform-specific)
  const normalizedLower = isWindows ? normalizedSource.toLowerCase() : normalizedSource;
  const blockedPaths = isWindows
    ? [
        ".ssh",
        ".gnupg",
        "appdata\\roaming\\microsoft\\credentials",
        "appdata\\local\\microsoft\\credentials",
        "appdata\\local\\packages",
        "appdata\\roaming\\npm",
        "appdata\\local\\npm-cache",
        "node_modules",
      ]
    : [".ssh", "Library", ".Trash", "node_modules"];
  if (blockedPaths.some((bp) => normalizedLower.includes(isWindows ? bp : bp))) {
    return res.status(403).json({ success: false, error: "Cannot migrate from protected directory" });
  }

  if (!fs.existsSync(normalizedSource)) {
    return res.status(400).json({ success: false, error: "Source path not found" });
  }

  if (!fs.existsSync(path.join(normalizedSource, ".git"))) {
    return res.status(400).json({ success: false, error: "Source is not a git repository" });
  }

  const targetPath = getRepoPath(accountName, safeName);
  if (!targetPath) {
    return res.status(400).json({ success: false, error: "Invalid target path" });
  }

  if (fs.existsSync(targetPath)) {
    return res.status(409).json({ success: false, error: "Target already exists" });
  }

  // Check status before migration
  const status = getRepoStatus(sourcePath);

  try {
    // Move directory
    fs.renameSync(normalizedSource, targetPath);

    // Update remote URL to use SSH host alias
    const newRemoteUrl = `git@${account.sshHost}:${account.githubUser}/${safeName}.git`;
    runGit(["remote", "set-url", "origin", newRemoteUrl], targetPath);

    broadcastSSE({
      type: "operation_complete",
      success: true,
      repo: safeName,
      operation: "migrate",
    });

    res.json({
      success: true,
      message: `Migrated to ${accountName}/${safeName}`,
      newRemoteUrl,
      hadUncommittedChanges: !status.isClean,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- POST /api/repos/transfer - Transfer repo between GitHub accounts ---
app.post("/api/repos/transfer", async (req, res) => {
  const { repoName, fromAccount, toAccount } = req.body;

  const source = validateAccount(fromAccount);
  const dest = validateAccount(toAccount);
  const safeName = sanitizeRepoName(repoName);

  if (!source || !dest || !safeName || fromAccount === toAccount) {
    return res.status(400).json({ success: false, error: "Invalid parameters" });
  }

  // GitHub CLI has no "gh repo transfer"; use REST API via gh api
  const result = await enqueueGh(source.githubUser, () =>
    runCommand(
      `gh api --method POST "/repos/${source.githubUser}/${safeName}/transfer" -f "new_owner=${dest.githubUser}"`
    )
  );

  if (!result.success) {
    return res.status(500).json({ success: false, error: result.output || result.error });
  }

  // --- Transfer is ASYNCHRONOUS for personal accounts ---
  // The new owner must accept via email. We do NOT move the local clone yet.
  // Instead, we verify if the repo already appeared in the destination account.
  let movedLocally = false;
  let transferComplete = false;

  // Give GitHub a moment, then check if repo exists in destination
  await new Promise((r) => setTimeout(r, 3000));

  const verifyResult = await enqueueGh(dest.githubUser, () =>
    runCommand(`gh api "/repos/${dest.githubUser}/${safeName}" --jq ".full_name"`)
  );

  if (verifyResult.success && verifyResult.output.includes(dest.githubUser)) {
    transferComplete = true;

    // Safe to move local clone now
    const oldPath = path.join(source.localDir, safeName);
    const newPath = path.join(dest.localDir, safeName);

    if (fs.existsSync(oldPath) && !fs.existsSync(newPath)) {
      try {
        fs.renameSync(oldPath, newPath);
        const newRemoteUrl = `git@${dest.sshHost}:${dest.githubUser}/${safeName}.git`;
        runGit(["remote", "set-url", "origin", newRemoteUrl], newPath);
        movedLocally = true;
      } catch (err) {
        // Log but don't fail — GitHub transfer succeeded
        console.error(`[transfer] Local move failed for ${safeName}:`, err.message);
      }
    }
  }

  broadcastSSE({
    type: "operation_complete",
    success: true,
    repo: safeName,
    operation: "transfer",
  });

  const pendingMsg = transferComplete
    ? `Transferred ${safeName} to ${dest.githubUser}` + (movedLocally ? " (local clone moved)" : "")
    : `Transfer initiated for ${safeName}. The new owner (${dest.githubUser}) must accept via email. Local clone will stay in place until accepted.`;

  res.json({
    success: true,
    transferComplete,
    movedLocally,
    message: pendingMsg,
    newUrl: `https://github.com/${dest.githubUser}/${safeName}`,
  });
});

// --- POST /api/open-editor - Open editor in new window at path ---
app.post("/api/open-editor", (req, res) => {
  const { path: targetPath, editor } = req.body;
  if (!targetPath || typeof targetPath !== "string") {
    return res.status(400).json({ success: false, error: "Invalid path" });
  }
  const allowed = ["cursor", "code"];
  if (!editor || !allowed.includes(editor)) {
    return res.status(400).json({ success: false, error: "Invalid editor" });
  }
  const norm = path.normalize(targetPath);
  if (!isPathInsideDir(BASE_DIR, norm)) {
    return res.status(403).json({ success: false, error: "Path not allowed" });
  }
  if (!fs.existsSync(norm)) {
    return res.status(404).json({ success: false, error: "Path not found" });
  }
  try {
    const spawnOpts = { detached: true, stdio: "ignore" };
    if (isWindows) spawnOpts.shell = true; // Windows needs shell to find cursor.cmd / code.cmd
    const child = spawn(editor, ["--new-window", norm], spawnOpts);
    child.on("error", (err) => {
      console.error(`[open-editor] Failed to launch "${editor}": ${err.message}`);
    });
    child.unref();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- POST /api/open-terminal - Open terminal at path ---
app.post("/api/open-terminal", (req, res) => {
  const { path: targetPath } = req.body;
  if (!targetPath || typeof targetPath !== "string") {
    return res.status(400).json({ success: false, error: "Invalid path" });
  }
  // SECURITY: only allow paths under our base directory
  const norm = path.normalize(targetPath);
  if (!isPathInsideDir(BASE_DIR, norm)) {
    return res.status(403).json({ success: false, error: "Path not allowed" });
  }
  if (!fs.existsSync(norm)) {
    return res.status(404).json({ success: false, error: "Path not found" });
  }
  try {
    let child;
    if (isWindows) {
      // SECURITY: avoid passing the path inside a shell command string
      // Using cwd ensures the new shell starts in the desired directory.
      child = spawn("cmd.exe", ["/c", "start", "powershell", "-NoExit"], {
        detached: true,
        stdio: "ignore",
        cwd: norm,
      });
    } else if (isDarwin) {
      const escapedPath = norm.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      const script = `tell application "Terminal" to do script "cd \\"${escapedPath}\\" && exec \\$SHELL"`;
      child = spawn("osascript", ["-e", script], { detached: true, stdio: "ignore" });
    } else {
      // Linux: try xdg-open or gnome-terminal
      child = spawn("xdg-open", [norm], { detached: true, stdio: "ignore" });
    }
    child.on("error", (err) => {
      console.error(`[open-terminal] Failed to launch terminal: ${err.message}`);
    });
    child.unref();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- GET /api/repos/:account/:name/status - Detailed repo status ---
app.get("/api/repos/:account/:name/status", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);

  if (!repoPath || !fs.existsSync(repoPath)) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const status = getRepoStatus(repoPath);
  res.json({ success: true, ...status });
});

// --- GET /api/repos/:account/:name/readme - README content (local or GitHub API) ---
app.get("/api/repos/:account/:name/readme", async (req, res) => {
  const account = validateAccount(req.params.account);
  const safeName = sanitizeRepoName(req.params.name);
  if (!account || !safeName) {
    return res.status(400).json({ success: false, error: "Invalid account or repo name" });
  }

  const repoPath = path.join(account.localDir, safeName);

  // 1) Prefer local clone if it exists
  if (fs.existsSync(repoPath) && fs.existsSync(path.join(repoPath, ".git"))) {
    const readmeNames = ["README.md", "readme.md", "README.MD", "Readme.md", "README"];
    for (const name of readmeNames) {
      const filePath = path.join(repoPath, name);
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        try {
          const content = fs.readFileSync(filePath, "utf8");
          return res.json({ success: true, content, source: "local" });
        } catch (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
      }
    }
  }

  // 2) Fetch from GitHub API (token preferred, gh CLI fallback)
  try {
    const apiPath = `repos/${account.githubUser}/${safeName}/readme`;
    const r = await githubApiForAccount(req.params.account, apiPath);
    if (!r.ok) {
      return res.status(404).json({ success: false, error: "No README found" });
    }
    let content = "";
    if (r.json && r.json.content) {
      content = Buffer.from(String(r.json.content).replace(/\s/g, ""), "base64").toString("utf8");
    } else if (r.raw) {
      // gh CLI with --jq returns raw base64
      const raw = String(r.raw).replace(/\s/g, "").replace(/^"|"$/g, "");
      content = Buffer.from(raw, "base64").toString("utf8");
    }
    return res.json({ success: true, content, source: r.source || "remote" });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message || "Failed to fetch README" });
  }
});

// --- GET /api/repos/:account/:name/commits - Recent commits from GitHub (works without local clone) ---
app.get("/api/repos/:account/:name/commits", async (req, res) => {
  const account = validateAccount(req.params.account);
  const safeName = sanitizeRepoName(req.params.name);
  if (!account || !safeName) {
    return res.status(400).json({ success: false, error: "Invalid account or repo name" });
  }

  const perPage = Math.min(parseInt(req.query.per_page, 10) || 5, 15);
  try {
    const apiPath = `repos/${account.githubUser}/${safeName}/commits?per_page=${perPage}`;
    const r = await githubApiForAccount(req.params.account, apiPath);
    if (!r.ok) {
      return res.status(404).json({ success: false, error: "No commits" });
    }
    let commits = [];
    if (r.json && Array.isArray(r.json)) {
      commits = r.json.map((c) => ({
        hash: c.sha ? c.sha.slice(0, 7) : "",
        subject: String((c.commit && c.commit.message) || "").replace(/\r\n/g, "\n").split("\n")[0].trim().slice(0, 120),
        author: (c.commit && c.commit.author && c.commit.author.name) || "",
        date: (c.commit && c.commit.author && c.commit.author.date) ? formatCommitDate(c.commit.author.date) : "",
      }));
    } else if (r.raw) {
      // gh CLI with --jq returns pre-formatted JSON
      const parsed = JSON.parse(r.raw);
      commits = parsed.map((c) => ({
        hash: (c.hash || "").trim(),
        subject: String(c.message || "").replace(/\r\n/g, "\n").split("\n")[0].trim().slice(0, 120),
        author: c.author || "",
        date: c.date ? formatCommitDate(c.date) : "",
      }));
    }
    return res.json({ success: true, recentCommits: commits });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

function formatCommitDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now - d;
  const diffM = Math.floor(diffMs / 60000);
  const diffH = Math.floor(diffMs / 3600000);
  const diffD = Math.floor(diffMs / 86400000);
  if (diffM < 60) return diffM + " min ago";
  if (diffH < 24) return diffH + " hours ago";
  if (diffD < 30) return diffD + " days ago";
  return d.toLocaleDateString();
}

// --- GET /api/repos/:account/:name/git-status - Branch list + changed files + summary + operation + upstream ---
app.get("/api/repos/:account/:name/git-status", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const repoStatus = getRepoStatus(repoPath);
  if (!repoStatus) {
    return res.status(500).json({ success: false, error: "Failed to get repo status" });
  }

  const statusPorcelain = runCommand("git status --porcelain", repoPath);
  const { files: statusFiles } = parseStatusPorcelain(statusPorcelain.output);

  const currentBranch = repoStatus.branch;
  const branchesResult = runCommand("git branch -a", repoPath);
  const logResult = runCommand('git log -10 --format="%h|||%s|||%an|||%ar"', repoPath);
  const stashResult = runCommand("git stash list", repoPath);
  const stashList = [];
  if (stashResult.success && stashResult.output) {
    stashResult.output.split("\n").filter(Boolean).forEach((line) => {
      const match = line.match(/^(stash@\{\d+\}):\s*(.*)$/);
      if (match) stashList.push({ ref: match[1], message: match[2].trim() });
    });
  }

  let unpushedHashes = [];
  if (currentBranch && currentBranch !== "unknown" && currentBranch !== "HEAD") {
    const safeBranch = currentBranch.replace(/[^a-zA-Z0-9/_.-]/g, "");
    if (repoStatus.upstream.hasUpstream) {
      const unpushedResult = runCommand(
        `git rev-list origin/${safeBranch}..HEAD --format="%h"`,
        repoPath
      );
      if (unpushedResult.success && unpushedResult.output) {
        unpushedResult.output
          .split("\n")
          .map((s) => s.trim())
          .filter((s) => s && /^[a-f0-9]{7,40}$/.test(s))
          .forEach((h) => unpushedHashes.push(h));
      }
    } else {
      const countResult = runCommand("git rev-list --count HEAD", repoPath);
      const hashResult = runCommand("git log -10 --format=%h", repoPath);
      if (hashResult.success && hashResult.output) {
        unpushedHashes = hashResult.output
          .split(/\s+/)
          .map((s) => s.trim())
          .filter((s) => s && /^[a-f0-9]{7,40}$/.test(s));
      }
      if (countResult.success && countResult.output) {
        repoStatus.upstream.ahead = parseInt(countResult.output.trim(), 10) || 0;
      }
    }
  }
  const unpushedCount = repoStatus.upstream.ahead;

  const branches = [];
  if (branchesResult.success && branchesResult.output) {
    branchesResult.output.split("\n").forEach((line) => {
      const trimmed = line.trim().replace(/^\*\s*/, "");
      if (!trimmed) return;
      const remote = trimmed.startsWith("remotes/");
      const name = remote ? trimmed.replace(/^remotes\/[^/]+\//, "") : trimmed;
      if (name && name !== "HEAD") {
        branches.push({ name, remote });
      }
    });
  }
  const seen = new Set();
  const branchList = branches.filter((b) => {
    if (seen.has(b.name)) return false;
    seen.add(b.name);
    return true;
  });

  const recentCommits = [];
  if (logResult.success && logResult.output) {
    logResult.output.split("\n").filter(Boolean).forEach((line) => {
      const parts = line.split("|||");
      if (parts.length >= 4) {
        recentCommits.push({
          hash: parts[0].trim(),
          subject: parts[1].trim(),
          author: parts[2].trim(),
          date: parts[3].trim(),
        });
      }
    });
  }

  res.json({
    success: true,
    currentBranch,
    branches: branchList,
    files: statusFiles,
    recentCommits,
    unpushedHashes,
    unpushedCount,
    summary: repoStatus.summary,
    operation: repoStatus.operation,
    upstream: repoStatus.upstream,
    stashList,
  });
});

// --- GET /api/repos/:account/:name/git/diff - Unified diff for one file (worktree or staged) ---
const DIFF_OUTPUT_MAX_LENGTH = 256 * 1024; // 256KB

app.get("/api/repos/:account/:name/git/diff", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const filePath = req.query.path;
  const mode = (req.query.mode || "worktree").toLowerCase();
  if (!filePath || typeof filePath !== "string") {
    return res.status(400).json({ success: false, error: "path query is required" });
  }
  if (mode !== "worktree" && mode !== "staged") {
    return res.status(400).json({ success: false, error: "mode must be worktree or staged" });
  }

  const resolved = path.resolve(repoPath, filePath);
  if (!isPathInsideDir(repoPath, resolved)) {
    return res.status(400).json({ success: false, error: "Invalid file path" });
  }

  const args = mode === "staged" ? ["diff", "--staged", "--", filePath] : ["diff", "--", filePath];
  try {
    const out = execFileSync("git", args, {
      cwd: repoPath,
      encoding: "utf8",
      timeout: 10000,
      maxBuffer: DIFF_OUTPUT_MAX_LENGTH + 8192,
    });
    let diff = (out || "").trim();
    const truncated = diff.length > DIFF_OUTPUT_MAX_LENGTH;
    if (truncated) diff = diff.slice(0, DIFF_OUTPUT_MAX_LENGTH) + "\n\n... (truncated)";
    res.json({ success: true, diff, truncated });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    if (output.includes("binary") || /Binary files/.test(output)) {
      return res.json({ success: true, diff: "", binary: true, truncated: false });
    }
    return res.status(400).json({ success: false, output });
  }
});

// --- POST /api/repos/:account/:name/git/discard-file ---
app.post("/api/repos/:account/:name/git/discard-file", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { path: filePath, includeStaged: includeStagedParam, allowUntracked } = req.body || {};
  if (!filePath || typeof filePath !== "string") {
    return res.status(400).json({ success: false, error: "path is required" });
  }
  const resolved = path.resolve(repoPath, filePath);
  if (!isPathInsideDir(repoPath, resolved)) {
    return res.status(400).json({ success: false, error: "Invalid file path" });
  }

  const includeStaged = !!includeStagedParam;

  try {
    if (includeStaged) {
      execFileSync("git", ["restore", "--staged", "--worktree", "--", filePath], {
        cwd: repoPath,
        encoding: "utf8",
        timeout: 10000,
      });
    } else {
      execFileSync("git", ["restore", "--worktree", "--", filePath], {
        cwd: repoPath,
        encoding: "utf8",
        timeout: 10000,
      });
    }
    res.json({ success: true });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    if (output && /did not match any file\(s\)/.test(output) && allowUntracked) {
      try {
        execFileSync("git", ["clean", "-f", "--", filePath], {
          cwd: repoPath,
          encoding: "utf8",
          timeout: 10000,
        });
        return res.json({ success: true });
      } catch (cleanErr) {
        return res.status(400).json({ success: false, output: (cleanErr.stderr || "").trim() });
      }
    }
    return res.status(400).json({ success: false, output });
  }
});

// --- POST /api/repos/:account/:name/git/discard-all ---
const DISCARD_CONFIRM_PHRASE = "DISCARD";

app.post("/api/repos/:account/:name/git/discard-all", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { includeUntracked, confirm: confirmPhrase } = req.body || {};
  if (confirmPhrase !== DISCARD_CONFIRM_PHRASE) {
    return res.status(400).json({ success: false, error: "Confirmation phrase required. Type DISCARD to confirm." });
  }

  try {
    execFileSync("git", ["restore", "--staged", "."], { cwd: repoPath, encoding: "utf8", timeout: 10000 });
    execFileSync("git", ["restore", "."], { cwd: repoPath, encoding: "utf8", timeout: 10000 });
    if (includeUntracked) {
      execFileSync("git", ["clean", "-fd"], { cwd: repoPath, encoding: "utf8", timeout: 10000 });
    }
    res.json({ success: true });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    return res.status(400).json({ success: false, output });
  }
});

// --- POST /api/repos/:account/:name/git/commit ---
app.post("/api/repos/:account/:name/git/commit", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { message, files: filesToAdd } = req.body || {};
  const safeMessage = sanitizeCommitMessage(message);
  if (!safeMessage) {
    return res.status(400).json({ success: false, error: "Commit message is required" });
  }

  if (filesToAdd && Array.isArray(filesToAdd) && filesToAdd.length > 0) {
    const safePaths = [];
    for (const f of filesToAdd) {
      if (typeof f !== "string") continue;
      const resolved = path.resolve(repoPath, f);
      if (!isPathInsideDir(repoPath, resolved)) {
        return res.status(400).json({ success: false, error: "Invalid file path" });
      }
      safePaths.push(f);
    }
    try {
      execFileSync("git", ["add", ...safePaths], { cwd: repoPath, encoding: "utf8", timeout: 10000 });
    } catch (err) {
      const output = (err.stdout || "") + (err.stderr || "");
      return res.status(500).json({ success: false, output: output.trim() });
    }
  } else {
    try {
      execFileSync("git", ["add", "-A"], { cwd: repoPath, encoding: "utf8", timeout: 10000 });
    } catch (err) {
      const output = (err.stdout || "") + (err.stderr || "");
      return res.status(500).json({ success: false, output: output.trim() });
    }
  }

  try {
    const out = execFileSync("git", ["commit", "-m", safeMessage], {
      cwd: repoPath,
      encoding: "utf8",
      timeout: 10000,
    });
    res.json({ success: true, output: out.trim() });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "");
    return res.status(400).json({ success: false, output: output.trim() });
  }
});

// --- POST /api/repos/:account/:name/git/push ---
app.post("/api/repos/:account/:name/git/push", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { branch } = req.body || {};
  const args = ["push"];
  if (branch) {
    const safeBranch = sanitizeBranchName(branch);
    if (!safeBranch) return res.status(400).json({ success: false, error: "Invalid branch name" });
    args.push("-u", "origin", safeBranch);
  }
  try {
    const out = execFileSync("git", args, { cwd: repoPath, encoding: "utf8", timeout: 60000 });
    res.json({ success: true, output: out.trim() });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    res.status(400).json({ success: false, output });
  }
});

// --- POST /api/repos/:account/:name/git/pull - Pull with optional rebase ---
app.post("/api/repos/:account/:name/git/pull", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const status = getRepoStatus(repoPath);
  if (!status.isClean || status.operation.isMerging || status.operation.isRebasing) {
    return res.status(409).json({
      success: false,
      error: "Repo has uncommitted changes or merge/rebase in progress. Commit or stash first.",
      changedFiles: status.changedFiles,
    });
  }

  const useRebase = !!(req.body && req.body.rebase);
  runCommand("git fetch --all", repoPath);
  const pullArgs = useRebase ? ["pull", "--rebase"] : ["pull"];
  try {
    const out = execFileSync("git", pullArgs, { cwd: repoPath, encoding: "utf8", timeout: 120000 });
    res.json({ success: true, output: out.trim() });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    res.status(400).json({ success: false, output });
  }
});

// --- GET /api/repos/:account/:name/git/stash/list ---
app.get("/api/repos/:account/:name/git/stash/list", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const result = runCommand("git stash list", repoPath);
  const list = [];
  if (result.success && result.output) {
    result.output.split("\n").filter(Boolean).forEach((line) => {
      const match = line.match(/^(stash@\{\d+\}):\s*(.*)$/);
      if (match) {
        list.push({ ref: match[1], message: match[2].trim(), date: "" });
      }
    });
  }
  res.json({ success: true, list });
});

// --- POST /api/repos/:account/:name/git/stash/push ---
app.post("/api/repos/:account/:name/git/stash/push", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { message, includeUntracked } = req.body || {};
  const args = ["stash", "push"];
  if (message && typeof message === "string" && message.trim().length > 0) {
    const safeMsg = message.trim().slice(0, 500).replace(/\r\n/g, "\n");
    args.push("-m", safeMsg);
  }
  if (includeUntracked) args.push("--include-untracked");

  try {
    const out = execFileSync("git", args, { cwd: repoPath, encoding: "utf8", timeout: 15000 });
    res.json({ success: true, output: out.trim() });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    return res.status(400).json({ success: false, output });
  }
});

// --- POST /api/repos/:account/:name/git/stash/apply ---
app.post("/api/repos/:account/:name/git/stash/apply", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { ref } = req.body || {};
  const safeRef = sanitizeStashRef(ref);
  if (!safeRef) return res.status(400).json({ success: false, error: "Valid stash ref required (e.g. stash@{0})" });

  try {
    const out = execFileSync("git", ["stash", "apply", safeRef], { cwd: repoPath, encoding: "utf8", timeout: 15000 });
    res.json({ success: true, output: out.trim() });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    return res.status(400).json({ success: false, output });
  }
});

// --- POST /api/repos/:account/:name/git/stash/pop ---
app.post("/api/repos/:account/:name/git/stash/pop", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { ref } = req.body || {};
  const safeRef = sanitizeStashRef(ref);
  if (!safeRef) return res.status(400).json({ success: false, error: "Valid stash ref required (e.g. stash@{0})" });

  try {
    const out = execFileSync("git", ["stash", "pop", safeRef], { cwd: repoPath, encoding: "utf8", timeout: 15000 });
    res.json({ success: true, output: out.trim() });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    return res.status(400).json({ success: false, output });
  }
});

// --- POST /api/repos/:account/:name/git/revert ---
app.post("/api/repos/:account/:name/git/revert", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { commit } = req.body || {};
  const safeHash = sanitizeCommitHash(commit);
  if (!safeHash) {
    return res.status(400).json({ success: false, error: "Valid commit hash is required (7–40 hex chars)" });
  }

  try {
    const out = execFileSync("git", ["revert", safeHash, "--no-edit"], {
      cwd: repoPath,
      encoding: "utf8",
      timeout: 15000,
    });
    res.json({ success: true, output: out.trim() });
  } catch (err) {
    const output = (err.stdout || "") + (err.stderr || "").trim();
    return res.status(400).json({ success: false, output: output || err.message });
  }
});

// --- POST /api/repos/:account/:name/git/checkout ---
app.post("/api/repos/:account/:name/git/checkout", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { branch } = req.body || {};
  const safeBranch = sanitizeBranchName(branch);
  if (!safeBranch) return res.status(400).json({ success: false, error: "Invalid branch name" });

  const result = runGit(["checkout", safeBranch], repoPath);
  if (!result.success) {
    return res.status(400).json({ success: false, output: result.output });
  }
  res.json({ success: true, output: result.output });
});

// --- POST /api/repos/:account/:name/git/branch ---
app.post("/api/repos/:account/:name/git/branch", (req, res) => {
  const repoPath = getRepoPath(req.params.account, req.params.name);
  if (!repoPath || !fs.existsSync(repoPath) || !fs.existsSync(path.join(repoPath, ".git"))) {
    return res.status(404).json({ success: false, error: "Repo not found locally" });
  }

  const { name } = req.body || {};
  const safeName = sanitizeBranchName(name);
  if (!safeName) return res.status(400).json({ success: false, error: "Invalid branch name" });

  const result = runGit(["checkout", "-b", safeName], repoPath);
  if (!result.success) {
    return res.status(400).json({ success: false, output: result.output });
  }
  res.json({ success: true, output: result.output });
});

// --- GET /api/events - Server-Sent Events for real-time updates ---
app.get("/api/events", (req, res) => {
  if (sseClients.size >= MAX_SSE_CLIENTS) {
    return res.status(429).json({ error: "Too many SSE connections" });
  }
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  sseClients.add(res);

  // Send heartbeat every 30s
  const heartbeat = setInterval(() => {
    res.write("data: {\"type\":\"heartbeat\"}\n\n");
  }, 30000);

  req.on("close", () => {
    sseClients.delete(res);
    clearInterval(heartbeat);
  });
});

// --- POST /api/repos/extras - Fetch PR/Issue counts via GraphQL (batch) ---
app.post("/api/repos/extras", async (req, res) => {
  const { repos } = req.body;
  if (!Array.isArray(repos) || repos.length === 0) {
    return res.status(400).json({ success: false, error: "Invalid repos list" });
  }

  const extras = {};

  // Group repos by account
  const byAccount = {};
  for (const r of repos) {
    const account = validateAccount(r.account);
    const safeName = sanitizeRepoName(r.name);
    if (!account || !safeName) continue;
    if (!byAccount[r.account]) byAccount[r.account] = [];
    byAccount[r.account].push(safeName);
  }

  for (const [accountName, repoNames] of Object.entries(byAccount)) {
    const account = validateAccount(accountName);
    if (!account) continue;

    // Build GraphQL query - batch all repos for this account
    const fields = repoNames
      .map((name, i) => {
        const escapedName = name.replace(/"/g, '\\"');
        return `repo_${i}: repository(owner: "${account.githubUser}", name: "${escapedName}") { issues(states: OPEN) { totalCount } pullRequests(states: OPEN) { totalCount } }`;
      })
      .join(" ");

    const query = `{ ${fields} }`;
    const gqlBody = { query };

    try {
      // Prefer token-based GraphQL request
      const token = await getAccountToken(accountName);
      let data = null;
      if (token) {
        try {
          const r = await githubRequestJson({
            method: "POST",
            url: "https://api.github.com/graphql",
            token,
            body: gqlBody,
            timeoutMs: 30000,
          });
          if (r.ok && r.json && r.json.data) data = r.json;
        } catch (e) { /* fall through to gh CLI */ }
      }

      // Fallback: gh CLI
      if (!data) {
        const tmpFile = path.join(os.tmpdir(), `gh-gql-${Date.now()}-${accountName}.json`);
        try {
          const result = await enqueueGh(account.githubUser, () => {
            fs.writeFileSync(tmpFile, JSON.stringify(gqlBody));
            return runCommand(`gh api graphql --input "${tmpFile}"`, BASE_DIR, 30000);
          });
          if (result.success) data = JSON.parse(result.output);
        } finally {
          try { fs.unlinkSync(tmpFile); } catch (e) { /* ignore */ }
        }
      }

      if (data && data.data) {
        repoNames.forEach((name, i) => {
          const alias = `repo_${i}`;
          if (data.data[alias]) {
            extras[`${accountName}/${name}`] = {
              prs: data.data[alias].pullRequests.totalCount,
              issues: data.data[alias].issues.totalCount,
            };
          }
        });
      }
    } catch (err) {
      console.error(`[extras] GraphQL error for ${accountName}:`, err.message);
    }
  }

  res.json({ success: true, extras });
});

// --- GET /api/health - Health check ---
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// --- Hub API key storage (config.json) ---
async function getHubApiKey() {
  if (cachedHubApiKey) return cachedHubApiKey;
  const config = loadConfig();
  const key = (config.hub && typeof config.hub.apiKey === "string") ? config.hub.apiKey.trim() : "";
  if (key) cachedHubApiKey = key;
  return key;
}

async function setHubApiKey(key) {
  cachedHubApiKey = key;
  const config = loadConfig();
  if (!config.hub) config.hub = {};
  config.hub.apiKey = key;
  saveConfig(config);
}

async function deleteHubApiKey() {
  cachedHubApiKey = null;
  const config = loadConfig();
  if (config.hub) {
    delete config.hub.apiKey;
    delete config.hub.apiKeySecure;
    saveConfig(config);
  }
}

// --- Hub (multi-machine) status and config (localhost only) ---
app.get("/api/hub/status", async (req, res) => {
  try {
    const config = loadConfig();
    const hub = config.hub || {};
    const machine = config.machine || {};
    const hubKey = await getHubApiKey();
    const configured = !!(hub.url && hubKey);
    res.json({
      configured,
      url: configured ? hub.url : undefined,
      machineName: machine.name || (configured ? os.hostname() : undefined),
      intervalMinutes: hub.intervalMinutes || 3,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/hub/config", async (req, res) => {
  try {
    const { url, apiKey, intervalMinutes, machineName } = req.body || {};
    const config = loadConfig();
    if (url !== undefined) {
      const trimmed = String(url).trim();
      if (trimmed.length > 0 && trimmed.length < 2048) {
        try {
          const parsedUrl = new URL(trimmed);
          // SECURITY: Enforce HTTPS for Hub communication
          if (parsedUrl.protocol !== "https:") {
            return res.status(400).json({ error: "Hub URL must use HTTPS for secure communication" });
          }
          if (!config.hub) config.hub = {};
          config.hub.url = trimmed;
        } catch (e) {
          return res.status(400).json({ error: "Invalid hub URL" });
        }
      } else {
        if (config.hub) delete config.hub.url;
      }
    }
    if (apiKey !== undefined) {
      const key = String(apiKey).trim();
      if (key.length > 0 && key.length < 512) {
        await setHubApiKey(key);
      } else {
        await deleteHubApiKey();
      }
    }
    if (intervalMinutes !== undefined) {
      const n = parseInt(intervalMinutes, 10);
      if (n >= 1 && n <= 60) {
        if (!config.hub) config.hub = {};
        config.hub.intervalMinutes = n;
      }
    }
    if (machineName !== undefined) {
      const name = String(machineName).trim().slice(0, 128);
      if (!config.machine) config.machine = { id: require("crypto").randomUUID(), name: name || os.hostname() };
      else config.machine.name = name || config.machine.name || os.hostname();
    }
    ensureMachineId(config);
    saveConfig(config);
    const hubKey = await getHubApiKey();
    if (config.hub && config.hub.url && hubKey) {
      setImmediate(sendHubSnapshot);
    }
    res.json({ success: true });
  } catch (e) {
    console.error("[hub] Config error:", e);
    res.status(500).json({ error: "Failed to save hub configuration" });
  }
});

// =============================================================================
// Start Server
// =============================================================================

function openBrowser(url) {
  try {
    const { exec } = require("child_process");
    if (isWindows) exec(`start "" "${url}"`);
    else if (isDarwin) exec(`open "${url}"`);
    else exec(`xdg-open "${url}"`);
  } catch (e) {
    console.log(`[startup] Could not open browser automatically. Visit: ${url}`);
  }
}

function logServerInfo(port) {
  console.log("");
  console.log("============================================================");
  console.log("  GitDock - Local Dashboard");
  console.log("============================================================");
  console.log("  Dashboard: http://" + HOST + ":" + port);
  console.log("  API:       http://" + HOST + ":" + port + "/api");
  console.log("  Security:  Localhost only (127.0.0.1)");
  if (isPkg) console.log("  Mode:      Packaged executable");
  console.log("============================================================");
  console.log("");
  console.log("  Press Ctrl+C to stop the server.");
  console.log("");
  openBrowser("http://" + HOST + ":" + port);
}

function startServer(port, remainingTries = 10) {
  const server = app.listen(port, HOST, () => logServerInfo(port));
  server.on("error", (err) => {
    if (err && err.code === "EADDRINUSE" && remainingTries > 0) {
      const nextPort = port + 1;
      console.warn(`[startup] Port ${port} in use. Trying ${nextPort}...`);
      try {
        server.close(() => startServer(nextPort, remainingTries - 1));
      } catch (e) {
        startServer(nextPort, remainingTries - 1);
      }
      return;
    }
    console.error("[startup] Server failed to start:", err && err.message ? err.message : String(err));
    process.exitCode = 1;
  });
}

// =============================================================================
// Hub Agent Mode (optional) - send git status snapshots to remote Hub
// =============================================================================
function collectHubSnapshot() {
  const config = loadConfig();
  const repos = [];
  for (const [accountName, account] of Object.entries(getAccounts())) {
    if (!fs.existsSync(account.localDir)) continue;
    const dirs = fs.readdirSync(account.localDir, { withFileTypes: true });
    for (const dir of dirs) {
      if (!dir.isDirectory() || !dir.name || dir.name.includes("..")) continue;
      const repoPath = path.join(account.localDir, dir.name);
      if (!fs.existsSync(path.join(repoPath, ".git"))) continue;
      const status = getRepoStatus(repoPath);
      if (!status) continue;
      repos.push({
        name: dir.name,
        account: accountName,
        githubUser: account.githubUser,
        branch: status.branch,
        localStatus: status.localStatus,
        isCloned: true,
        ahead: status.ahead || 0,
        behind: status.behind || 0,
        lastCommit: status.lastCommit || {},
        summary: status.summary || { stagedCount: 0, unstagedCount: 0, untrackedCount: 0, conflictCount: 0 },
      });
    }
  }
  return {
    machineId: config.machine && config.machine.id,
    machineName: (config.machine && config.machine.name) || os.hostname(),
    platform: process.platform,
    timestamp: new Date().toISOString(),
    repos,
  };
}

async function sendHubSnapshot() {
  const config = loadConfig();
  const hub = config.hub;
  if (!hub || !hub.url) return;
  const apiKey = await getHubApiKey();
  if (!apiKey) return;
  const snapshot = collectHubSnapshot();
  if (!snapshot.machineId) return;
  lastHubSnapshotTime = Date.now();
  try {
    const u = new URL(hub.url);
    const isHttps = u.protocol === "https:";
    const lib = isHttps ? https : http;
    const body = JSON.stringify(snapshot);
    const req = lib.request(
      {
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: (u.pathname || "/").replace(/\/?$/, "") + "/api/agent/snapshot",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          Authorization: "Bearer " + apiKey,
        },
        timeout: 15000,
      },
      (res) => {
        let raw = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => { raw += chunk; });
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            console.log("[hub] Snapshot sent successfully");
          } else {
            console.warn("[hub] Snapshot rejected:", res.statusCode, raw.slice(0, 200));
          }
        });
      }
    );
    req.on("error", (err) => {
      console.warn("[hub] Snapshot send failed:", err.message);
    });
    req.on("timeout", () => {
      req.destroy();
      console.warn("[hub] Snapshot send timeout");
    });
    req.write(body);
    req.end();
  } catch (err) {
    console.warn("[hub] Snapshot error:", err.message);
  }
}

let lastHubSnapshotTime = 0;
const HUB_AGENT_CHECK_MS = 60 * 1000;

async function startHubAgent() {
  setInterval(async () => {
    const config = loadConfig();
    const hub = config.hub;
    if (!hub || !hub.url) return;
    const hubKey = await getHubApiKey();
    if (!hubKey) return;
    const intervalMs = Math.max(1, Math.min(60, parseInt(hub.intervalMinutes, 10) || 3)) * 60 * 1000;
    if (Date.now() - lastHubSnapshotTime >= intervalMs) {
      sendHubSnapshot();
    }
  }, HUB_AGENT_CHECK_MS);
  const config = loadConfig();
  const hub = config.hub;
  const hubKey = await getHubApiKey();
  if (hub && hub.url && hubKey) {
    const intervalMinutes = Math.max(1, Math.min(60, parseInt(hub.intervalMinutes, 10) || 3));
    console.log(`[hub] Agent enabled: sending snapshot every ${intervalMinutes} min to ${hub.url}`);
    sendHubSnapshot();
  }
}

// Best-effort housekeeping (safe; does not delete SSH keys)
cleanupOrphanedGitconfigs();
syncManagedSshConfigToAccounts();

startServer(PORT);
startHubAgent();
