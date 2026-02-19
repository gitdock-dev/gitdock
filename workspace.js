// =============================================================================
// workspace.js - Workspace path management for GitDock (open source)
// =============================================================================
// User data directory is chosen on first run (packaged) or uses project dir (dev).
// Stored in ~/.gitdock/workspace.json
// =============================================================================

const fs = require("fs");
const path = require("path");
const os = require("os");

const GITDOCK_DIR = path.join(os.homedir(), ".gitdock");
const WORKSPACE_PATH = path.join(GITDOCK_DIR, "workspace.json");

function ensureGitDockDir() {
  if (!fs.existsSync(GITDOCK_DIR)) {
    fs.mkdirSync(GITDOCK_DIR, { recursive: true });
  }
}

function getDefaultWorkspacePath() {
  return path.join(os.homedir(), "GitDock");
}

function loadWorkspace() {
  try {
    if (fs.existsSync(WORKSPACE_PATH)) {
      const raw = fs.readFileSync(WORKSPACE_PATH, "utf8");
      const data = JSON.parse(raw);
      if (data && typeof data.path === "string" && data.path.trim()) {
        return data.path.trim();
      }
    }
  } catch (e) {
    console.warn("[workspace] Could not load workspace:", e.message);
  }
  return null;
}

function saveWorkspace(dirPath) {
  ensureGitDockDir();
  const resolved = path.resolve(dirPath.trim());
  if (!fs.existsSync(resolved)) {
    fs.mkdirSync(resolved, { recursive: true });
  }
  const data = { path: resolved, createdAt: new Date().toISOString() };
  fs.writeFileSync(WORKSPACE_PATH, JSON.stringify(data, null, 2), "utf8");
  console.log("[workspace] Workspace set to: " + resolved);

  const configPath = path.join(resolved, "config.json");
  if (!fs.existsSync(configPath)) {
    const emptyConfig = { accounts: {} };
    fs.writeFileSync(configPath, JSON.stringify(emptyConfig, null, 2), "utf8");
    console.log("[workspace] Created empty config.json");
  }
  return resolved;
}

function isWorkspaceConfigured() {
  const ws = loadWorkspace();
  return ws !== null && fs.existsSync(ws);
}

module.exports = {
  GITDOCK_DIR,
  WORKSPACE_PATH,
  ensureGitDockDir,
  getDefaultWorkspacePath,
  loadWorkspace,
  saveWorkspace,
  isWorkspaceConfigured,
};
