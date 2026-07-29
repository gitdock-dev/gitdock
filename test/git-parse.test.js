const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const gitParse = require("../lib/git-parse");

describe("parseStatusPorcelain", () => {
  it("counts staged, unstaged, untracked, and conflicts", () => {
    const out = [
      "M  file.txt",
      " M other.txt",
      "?? new.txt",
      "UU conflict.txt",
    ].join("\n");
    const r = gitParse.parseStatusPorcelain(out);
    assert.equal(r.files.length, 4);
    assert.equal(r.summary.untrackedCount, 1);
    assert.equal(r.summary.conflictCount, 1);
    assert.ok(r.summary.stagedCount >= 1);
    assert.ok(r.summary.unstagedCount >= 1);
  });

  it("parses quoted file paths from porcelain output", () => {
    const out = ' M "path with spaces.txt"\n';
    const { files, summary } = gitParse.parseStatusPorcelain(out);
    assert.equal(files[0].path, "path with spaces.txt");
    assert.equal(summary.unstagedCount, 1);
  });

  it("keeps unstaged-only lines as unstaged (leading space must be preserved)", () => {
    const out = " M README.md\n";
    const { files, summary } = gitParse.parseStatusPorcelain(out);
    assert.equal(files[0].path, "README.md");
    assert.equal(summary.stagedCount, 0);
    assert.equal(summary.unstagedCount, 1);
    // Regression: full .trim() on porcelain turns " M README.md" into "M README.md"
    const broken = gitParse.parseStatusPorcelain(out.trim());
    assert.equal(broken.summary.stagedCount, 1);
    assert.equal(broken.summary.unstagedCount, 0);
  });

  it("returns empty summary for clean tree", () => {
    const r = gitParse.parseStatusPorcelain("");
    assert.deepEqual(r.summary, {
      stagedCount: 0,
      unstagedCount: 0,
      untrackedCount: 0,
      conflictCount: 0,
    });
  });
});

describe("parseStatusBranchLine", () => {
  it("parses branch with ahead/behind", () => {
    const r = gitParse.parseStatusBranchLine("## main...origin/main [ahead 2, behind 1]");
    assert.equal(r.branch, "main");
    assert.equal(r.hasUpstream, true);
    assert.equal(r.ahead, 2);
    assert.equal(r.behind, 1);
  });

  it("handles detached or missing upstream", () => {
    const r = gitParse.parseStatusBranchLine("## feature");
    assert.equal(r.branch, "feature");
    assert.equal(r.hasUpstream, false);
  });
});
