const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const os = require("os");
const security = require("../lib/security");

describe("security sanitization", () => {
  it("accepts valid account and repo names", () => {
    assert.equal(security.sanitizeAccountName("work"), "work");
    assert.equal(security.sanitizeRepoName("my-app"), "my-app");
    assert.equal(security.sanitizeOwnerName("Tam-Leal"), "Tam-Leal");
  });

  it("rejects path traversal in repo names", () => {
    assert.equal(security.sanitizeRepoName("../etc"), null);
    assert.equal(security.sanitizeRepoName("foo..bar"), null);
  });

  it("rejects shell-like account names", () => {
    assert.equal(security.sanitizeAccountName("work;rm"), null);
    assert.equal(security.sanitizeAccountName(""), null);
    assert.equal(security.sanitizeAccountName("bad name!"), null);
    assert.equal(security.sanitizeAccountName("a".repeat(65)), null);
  });

  it("normalizes case but keeps hyphens", () => {
    assert.equal(security.sanitizeAccountName("Work-Dev"), "work-dev");
  });

  it("restricts SSH host aliases", () => {
    assert.equal(security.sanitizeSshHostAlias("github.com-work"), "github.com-work");
    assert.equal(security.sanitizeSshHostAlias("host$(whoami)"), null);
  });

  it("validates commit hash and stash ref", () => {
    assert.equal(security.sanitizeCommitHash("abc1234"), "abc1234");
    assert.equal(security.sanitizeCommitHash("not-a-hash"), "");
    assert.equal(security.sanitizeStashRef("stash@{0}"), "stash@{0}");
    assert.equal(security.sanitizeStashRef("stash@0"), null);
  });

  it("sanitizes branch names and blocks traversal", () => {
    assert.equal(security.sanitizeBranchName("feature/login"), "feature/login");
    assert.equal(security.sanitizeBranchName("../../../main"), null);
    assert.equal(security.sanitizeBranchName(""), null);
  });

  it("normalizes commit messages", () => {
    assert.equal(security.sanitizeCommitMessage("  fix: typo  "), "fix: typo");
    const long = "a".repeat(3000);
    assert.equal(security.sanitizeCommitMessage(long).length, 2048);
    assert.equal(
      security.sanitizeCommitMessage("line1\r\n\r\n\r\n\r\nline2"),
      "line1\n\nline2"
    );
  });
});

describe("parseGitHubRepoUrl", () => {
  it("parses https and ssh github URLs", () => {
    assert.deepEqual(security.parseGitHubRepoUrl("https://github.com/octo/Hello-World"), {
      owner: "octo",
      repo: "Hello-World",
    });
    assert.deepEqual(security.parseGitHubRepoUrl("git@github.com-work:octo/Hello-World.git"), {
      owner: "octo",
      repo: "Hello-World",
    });
  });

  it("rejects non-github hosts", () => {
    assert.equal(security.parseGitHubRepoUrl("https://gitlab.com/a/b"), null);
  });

  it("parses github.com/owner/repo without scheme", () => {
    assert.deepEqual(security.parseGitHubRepoUrl("github.com/octo/Hello-World.git"), {
      owner: "octo",
      repo: "Hello-World",
    });
  });
});

describe("parseGitHubOwnerRepoFromRemote", () => {
  it("parses generic git@host remotes", () => {
    assert.deepEqual(security.parseGitHubOwnerRepoFromRemote("git@gitlab.com:octo/Hello-World.git"), {
      owner: "octo",
      repo: "Hello-World",
    });
  });

  it("prefers GitHub URL rules when host is github.com", () => {
    assert.deepEqual(
      security.parseGitHubOwnerRepoFromRemote("https://github.com/octo/Hello-World"),
      { owner: "octo", repo: "Hello-World" }
    );
  });

  it("returns null for malformed remotes", () => {
    assert.equal(security.parseGitHubOwnerRepoFromRemote("not-a-remote"), null);
  });
});

describe("isPathInsideDir", () => {
  it("blocks escaping the workspace base", () => {
    const base = path.join(os.tmpdir(), "gitdock-path-test");
    const inside = path.join(base, "work", "repo");
    const outside = path.join(base, "..", "outside");
    assert.equal(security.isPathInsideDir(base, inside), true);
    assert.equal(security.isPathInsideDir(base, outside), false);
  });
});

describe("github known_hosts fingerprints", () => {
  it("includes all official GitHub lines", () => {
    const content = security.GITHUB_OFFICIAL_KNOWN_HOSTS_LINES.join("\n");
    assert.equal(security.githubOfficialKeysInKnownHosts(content), true);
    assert.equal(security.githubOfficialKeysInKnownHosts("github.com ssh-ed25519 AAA"), false);
  });

  it("expects three key types per GitHub documentation", () => {
    assert.equal(security.GITHUB_OFFICIAL_KNOWN_HOSTS_LINES.length, 3);
    assert.ok(security.GITHUB_OFFICIAL_KNOWN_HOSTS_LINES.every((l) => l.startsWith("github.com ")));
  });
});

describe("checkRateLimit", () => {
  it("allows burst then blocks within window", () => {
    const buckets = new Map();
    assert.equal(security.checkRateLimit(buckets, "test", 2, 60_000), true);
    assert.equal(security.checkRateLimit(buckets, "test", 2, 60_000), true);
    assert.equal(security.checkRateLimit(buckets, "test", 2, 60_000), false);
  });
});

describe("configJsonHasNoTokenFields", () => {
  it("flags configs that would store secrets on disk", () => {
    assert.equal(
      security.configJsonHasNoTokenFields({ accounts: { work: { githubUser: "u" } } }),
      true
    );
    assert.equal(
      security.configJsonHasNoTokenFields({ accounts: { work: { token: "ghp_x" } } }),
      false
    );
  });
});
