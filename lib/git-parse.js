/**
 * Pure parsers for git command output (used by server and tests).
 */

function parseStatusPorcelain(output) {
  const lines = output ? output.split("\n").filter(Boolean) : [];
  const files = [];
  let stagedCount = 0;
  let unstagedCount = 0;
  let untrackedCount = 0;
  let conflictCount = 0;
  for (const line of lines) {
    const xy = line.slice(0, 2);
    const x = xy[0];
    const y = xy[1];
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

/** Parse "git status -sb" first line for branch, upstream, ahead, behind */
function parseStatusBranchLine(line) {
  if (!line || !line.startsWith("## ")) {
    return { branch: "unknown", hasUpstream: false, ahead: 0, behind: 0, upstreamRef: null };
  }
  const rest = line.slice(3).trim();
  const branchMatch = rest.match(/^([^\s.]+)(?:\.\.\.(\S+))?(?:\s+\[(.*)\])?/);
  const branch = branchMatch ? branchMatch[1] : "unknown";
  const upstreamRef = branchMatch && branchMatch[2] ? branchMatch[2] : null;
  const bracket = branchMatch && branchMatch[3] ? branchMatch[3] : "";
  let ahead = 0;
  let behind = 0;
  const aheadM = bracket.match(/ahead\s+(\d+)/);
  const behindM = bracket.match(/behind\s+(\d+)/);
  if (aheadM) ahead = parseInt(aheadM[1], 10) || 0;
  if (behindM) behind = parseInt(behindM[1], 10) || 0;
  return { branch, hasUpstream: !!upstreamRef, ahead, behind, upstreamRef };
}

module.exports = {
  parseStatusPorcelain,
  parseStatusBranchLine,
};
