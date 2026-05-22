const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const dormant = require("../lib/dormant");

describe("dormant repo detection", () => {
  const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();

  it("uses last local commit when cloned", () => {
    const repo = {
      isCloned: true,
      lastCommit: { date: daysAgo(120) },
      updatedAt: daysAgo(1),
    };
    assert.equal(dormant.isDormant(repo, 90), true);
    assert.equal(dormant.isDormant(repo, 180), false);
  });

  it("uses GitHub updatedAt when not cloned", () => {
    const repo = {
      isCloned: false,
      updatedAt: daysAgo(40),
    };
    assert.equal(dormant.isDormant(repo, 30), true);
    assert.equal(dormant.isDormant(repo, 90), false);
  });

  it("treats repo as dormant only after threshold days", () => {
    const tenDaysAgo = new Date(Date.now() - 10 * 86400000).toISOString();
    const repo = { isCloned: false, updatedAt: tenDaysAgo };
    assert.equal(dormant.isDormant(repo, 7), true);
    assert.equal(dormant.isDormant(repo, 10), false);
    assert.equal(dormant.isDormant(repo, 11), false);
  });

  it("returns false without a reference date", () => {
    assert.equal(dormant.isDormant({ isCloned: false }, 90), false);
  });
});

describe("dormantPeriodLabel", () => {
  it("maps thresholds to human labels", () => {
    assert.equal(dormant.dormantPeriodLabel(30), "1 month");
    assert.equal(dormant.dormantPeriodLabel(90), "3 months");
    assert.equal(dormant.dormantPeriodLabel(365), "1 year");
  });
});
