/**
 * Interpolated gh/git commands must reach the child as literal argv.
 * No network and no real gh binary: the child is the current Node process.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gitdock-execfile-"));
process.env.GITDOCK_TEST = "1";
process.env.GITDOCK_TEST_ROOT = testRoot;

const {
  runExecFile,
  ghApiArgs,
  ghRepoListArgs,
  ghRepoViewArgs,
  ghRepoTransferArgs,
  ghRepoFullNameArgs,
  gitRevListUnpushedArgs,
  ghGraphqlInputArgs,
} = require("../server");

const marker = path.join(testRoot, "pwned-by-shell.txt");
const payload = `legit; echo PWNED && echo X | cat $(touch ${marker}) \`touch ${marker}\` "dq" 'sq'`;

function assertChildArgv(args) {
  const script = path.join(testRoot, "print-argv.js");
  const result = runExecFile(process.execPath, [script, ...args], testRoot, 15000);
  assert.equal(result.success, true, result.error || result.output);
  assert.deepEqual(JSON.parse(result.output), args);
  assert.equal(fs.existsSync(marker), false);
}

describe("execFileSync literal arguments", () => {
  before(() => {
    fs.writeFileSync(
      path.join(testRoot, "print-argv.js"),
      "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n"
    );
  });

  after(() => {
    fs.rmSync(testRoot, { recursive: true, force: true });
  });

  it("passes shell metacharacters to the child as one argument", () => {
    assertChildArgv([payload]);
  });

  it("inherits GH_TOKEN and uses the given cwd", () => {
    const previous = process.env.GH_TOKEN;
    process.env.GH_TOKEN = "gh-test-token";
    const envScript = path.join(testRoot, "print-env.js");
    const cwdMarker = "cwd-marker.txt";
    fs.writeFileSync(
      envScript,
      [
        "const fs = require('fs');",
        `fs.writeFileSync(${JSON.stringify(cwdMarker)}, process.env.GH_TOKEN || '');`,
        "process.stdout.write(process.env.GH_TOKEN || '');",
        "",
      ].join("\n")
    );
    try {
      const result = runExecFile(process.execPath, [envScript], testRoot, 15000);
      assert.equal(result.success, true, result.error || result.output);
      assert.equal(result.output, "gh-test-token");
      assert.equal(fs.readFileSync(path.join(testRoot, cwdMarker), "utf8"), "gh-test-token");
    } finally {
      if (previous === undefined) delete process.env.GH_TOKEN;
      else process.env.GH_TOKEN = previous;
    }
  });

  it("keeps a hostile githubApiForAccount path, method, and jq as single arguments", () => {
    assert.deepEqual(ghApiArgs("repos/octo/hello/readme"), ["api", "repos/octo/hello/readme"]);
    assert.deepEqual(ghApiArgs("repos/octo/hello/commits?per_page=5"), [
      "api",
      "repos/octo/hello/commits?per_page=5",
    ]);
    const args = ghApiArgs(payload, {
      method: "POST",
      jq: payload,
    });
    assert.deepEqual(args, ["api", "--method", "POST", payload, "--jq", payload]);
    assertChildArgv(args);
  });

  it("keeps gh repo list and gh repo view values as one argument", () => {
    const listArgs = ghRepoListArgs(payload);
    assert.equal(listArgs[0], "repo");
    assert.equal(listArgs[1], "list");
    assert.equal(listArgs[2], payload);
    assert.equal(listArgs.filter((part) => part === payload).length, 1);
    assertChildArgv(listArgs);

    const viewArgs = ghRepoViewArgs(payload, "hello");
    assert.equal(viewArgs[2], `${payload}/hello`);
    assertChildArgv(viewArgs);
  });

  it("keeps repository transfer fields as literal gh api arguments", () => {
    const transferArgs = ghRepoTransferArgs(payload, "app", "bob");
    assert.deepEqual(transferArgs, [
      "api",
      "--method",
      "POST",
      `/repos/${payload}/app/transfer`,
      "-f",
      "new_owner=bob",
    ]);
    assertChildArgv(transferArgs);

    const lookupArgs = ghRepoFullNameArgs("bob", payload);
    assert.deepEqual(lookupArgs, ["api", `/repos/bob/${payload}`, "--jq", ".full_name"]);
    assertChildArgv(lookupArgs);
  });

  it("passes the rev-list range as one argument and drops shell quotes around %h", () => {
    const args = gitRevListUnpushedArgs(payload);
    assert.deepEqual(args, ["rev-list", `origin/${payload}..HEAD`, "--format=%h"]);
    assertChildArgv(args);
  });

  it("passes a graphql --input path with spaces and shell characters as one argument", () => {
    const inputFile = path.join(testRoot, `query ${payload}.json`);
    const args = ghGraphqlInputArgs(inputFile);
    assert.deepEqual(args, ["api", "graphql", "--input", inputFile]);
    assertChildArgv(args);
  });
});
