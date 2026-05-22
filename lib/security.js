/**
 * Security helpers and input validation (shared by server and tests).
 */
const path = require("path");

const isWindows = process.platform === "win32";

function sanitizeAccountName(name) {
  if (!name || typeof name !== "string") return null;
  const trimmed = name.trim();
  const normalized = trimmed.toLowerCase();
  const clean = normalized.replace(/[^a-z0-9\-]/g, "");
  if (clean !== normalized || clean.length === 0 || clean.length > 64) return null;
  return clean;
}

function sanitizeRepoName(name) {
  if (!name || typeof name !== "string") return null;
  const clean = name.replace(/[^a-zA-Z0-9\-_.]/g, "");
  if (clean !== name || clean.length === 0 || clean.includes("..")) return null;
  return clean;
}

function sanitizeOwnerName(name) {
  if (!name || typeof name !== "string") return null;
  const clean = name.replace(/[^a-zA-Z0-9\-_.]/g, "");
  if (clean !== name || clean.length === 0 || clean.includes("..")) return null;
  return clean;
}

function sanitizeSshHostAlias(host) {
  if (!host || typeof host !== "string") return null;
  const trimmed = host.trim();
  if (trimmed.length === 0 || trimmed.length > 128) return null;
  if (!/^[a-zA-Z0-9._-]+$/.test(trimmed)) return null;
  return trimmed;
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

function isPathInsideDir(baseDir, candidatePath) {
  const base = path.resolve(baseDir);
  const cand = path.resolve(candidatePath);
  const baseNorm = isWindows ? base.toLowerCase() : base;
  const candNorm = isWindows ? cand.toLowerCase() : cand;
  const baseWithSep = baseNorm.endsWith(path.sep) ? baseNorm : baseNorm + path.sep;
  return candNorm === baseNorm || candNorm.startsWith(baseWithSep);
}

function parseGitHubRepoUrl(input) {
  if (!input || typeof input !== "string") return null;
  const raw = input.trim();
  if (!raw || raw.length > 2048) return null;

  let s = raw;
  if (!/^https?:\/\//i.test(s) && /^github\.com\//i.test(s)) {
    s = "https://" + s;
  }

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
    // fall through
  }

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
  if (!remoteUrl || typeof remoteUrl !== "string") return null;
  const m = remoteUrl.trim().match(/^git@[^:]+:([^\/\s]+)\/([^\/\s]+?)(?:\.git)?$/);
  if (!m) return null;
  const owner = sanitizeOwnerName(m[1]);
  const repo = sanitizeRepoName(m[2]);
  if (!owner || !repo) return null;
  return { owner, repo };
}

const GITHUB_KNOWN_HOSTS_MARKER = "# --- GitHub host keys (managed by GitDock) ---";
const GITHUB_KNOWN_HOSTS_END = "# --- End GitHub host keys ---";
const GITHUB_OFFICIAL_KNOWN_HOSTS_LINES = [
  "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
  "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
  "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
];

function githubOfficialKeysInKnownHosts(content) {
  if (!content || typeof content !== "string") return false;
  return GITHUB_OFFICIAL_KNOWN_HOSTS_LINES.every((line) => content.includes(line));
}

function checkRateLimit(buckets, bucketKey, maxRequests, windowMs) {
  const now = Date.now();
  const entry = buckets.get(bucketKey);
  if (!entry || now > entry.resetAt) {
    buckets.set(bucketKey, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= maxRequests) return false;
  entry.count++;
  return true;
}

function configJsonHasNoTokenFields(config) {
  const raw = JSON.stringify(config || {});
  return !/\btoken\b/i.test(raw) && !/\bapiKey\b/i.test(raw) && !/\bpat\b/i.test(raw);
}

module.exports = {
  sanitizeAccountName,
  sanitizeRepoName,
  sanitizeOwnerName,
  sanitizeSshHostAlias,
  sanitizeBranchName,
  sanitizeCommitMessage,
  sanitizeCommitHash,
  sanitizeStashRef,
  isPathInsideDir,
  parseGitHubRepoUrl,
  parseGitHubOwnerRepoFromRemote,
  GITHUB_KNOWN_HOSTS_MARKER,
  GITHUB_KNOWN_HOSTS_END,
  GITHUB_OFFICIAL_KNOWN_HOSTS_LINES,
  githubOfficialKeysInKnownHosts,
  checkRateLimit,
  configJsonHasNoTokenFields,
};
