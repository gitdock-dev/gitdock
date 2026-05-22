/**
 * HTTP integration tests (Express app in GITDOCK_TEST mode).
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { describe, it, before } = require("node:test");
const assert = require("node:assert/strict");

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gitdock-api-"));
process.env.GITDOCK_TEST = "1";
process.env.GITDOCK_TEST_ROOT = testRoot;

const { app } = require("../server");
const security = require("../lib/security");
const { api } = require("./helpers/http");

describe("API security middleware", () => {
  it("serves health without CSRF header", async () => {
    const res = await api(app).get("/api/health");
    assert.equal(res.status, 200);
    assert.equal(res.body.status, "ok");
  });

  it("blocks POST without x-gitdock header", async () => {
    const request = require("supertest");
    const res = await request(app)
      .post("/api/accounts")
      .set("Host", "127.0.0.1")
      .send({ name: "work", githubUser: "octo" });
    assert.equal(res.status, 403);
    assert.match(res.body.error, /security header/i);
  });

  it("does not expose config.json", async () => {
    const res = await api(app).get("/config.json");
    assert.equal(res.status, 404);
  });
});

describe("API version and workspace", () => {
  it("returns package version", async () => {
    const res = await api(app).get("/api/version");
    assert.equal(res.status, 200);
    assert.match(res.body.version, /^\d+\.\d+\.\d+$/);
  });

  it("reports workspace status for test root", async () => {
    const res = await api(app).get("/api/workspace/status");
    assert.equal(res.status, 200);
    assert.equal(res.body.configured, true);
    assert.equal(res.body.path, testRoot);
  });
});

describe("Account CRUD", () => {
  it("creates, lists, updates, and deletes an account", async () => {
    const create = await api(app).post("/api/accounts", {
      name: "work",
      githubUser: "octocat",
      label: "Work",
      email: "dev@example.com",
    });
    assert.equal(create.status, 200);
    assert.equal(create.body.ok, true);

    const raw = JSON.parse(fs.readFileSync(path.join(testRoot, "config.json"), "utf8"));
    assert.equal(security.configJsonHasNoTokenFields(raw), true);
    assert.equal(raw.accounts.work.githubUser, "octocat");

    const list = await api(app).get("/api/accounts");
    assert.equal(list.status, 200);
    assert.ok(list.body.accounts.some((a) => a.name === "work"));

    const update = await api(app).put("/api/accounts/work", { label: "Work updated" });
    assert.equal(update.status, 200);

    const del = await api(app).del("/api/accounts/work");
    assert.equal(del.status, 200);
  });

  it("rejects invalid account names", async () => {
    const res = await api(app).post("/api/accounts", {
      name: "bad name!",
      githubUser: "octocat",
    });
    assert.equal(res.status, 400);
  });

  it("rejects duplicate account names", async () => {
    const first = await api(app).post("/api/accounts", {
      name: "dup",
      githubUser: "octocat",
    });
    assert.equal(first.status, 200);
    const second = await api(app).post("/api/accounts", {
      name: "dup",
      githubUser: "octocat",
    });
    assert.equal(second.status, 409);
    await api(app).del("/api/accounts/dup");
  });

  it("rejects invalid GitHub usernames", async () => {
    const res = await api(app).post("/api/accounts", {
      name: "valid",
      githubUser: "bad user!",
    });
    assert.equal(res.status, 400);
  });
});

describe("Missing account handling", () => {
  it("returns 404 for unknown account routes", async () => {
    const missing = "no-such-account";
    const put = await api(app).put(`/api/accounts/${missing}`, { label: "x" });
    assert.equal(put.status, 404);

    const del = await api(app).del(`/api/accounts/${missing}`);
    assert.equal(del.status, 404);

    const status = await api(app).get(`/api/accounts/${missing}/status`);
    assert.equal(status.status, 404);

    const auth = await api(app).get(`/api/accounts/${missing}/auth/status`);
    assert.equal(auth.status, 404);

    const token = await api(app).post(`/api/accounts/${missing}/auth/token`, {
      token: "ghp_1234567890",
      remember: false,
    });
    assert.equal(token.status, 404);
  });
});

describe("Repo guards", () => {
  before(async () => {
    await api(app).post("/api/accounts", {
      name: "dev",
      githubUser: "octocat",
      label: "Dev",
    });
  });

  it("rejects clone with invalid repo name", async () => {
    const res = await api(app).post("/api/repos/clone", {
      account: "dev",
      repoName: "../escape",
    });
    assert.ok(res.status >= 400);
  });

  it("rejects clone-url for non-github URL", async () => {
    const res = await api(app).post("/api/repos/clone-url", {
      account: "dev",
      url: "https://example.com/a/b",
    });
    assert.ok(res.status >= 400);
  });
});

describe("Auth token endpoint validation", () => {
  before(async () => {
    const names = Object.keys(JSON.parse(fs.readFileSync(path.join(testRoot, "config.json"), "utf8")).accounts || {});
    if (!names.includes("dev")) {
      await api(app).post("/api/accounts", { name: "dev", githubUser: "octocat" });
    }
  });

  it("rejects short tokens without storing", async () => {
    const res = await api(app).post("/api/accounts/dev/auth/token", {
      token: "short",
      remember: false,
    });
    assert.equal(res.status, 400);
  });
});
