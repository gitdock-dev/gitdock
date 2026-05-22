/**
 * Dormant repo detection (mirrors dashboard logic for tests and docs).
 */

function isDormant(repo, dormantDays) {
  const days = Number(dormantDays);
  if (!Number.isFinite(days) || days < 1) return false;
  const refDate =
    repo.isCloned && repo.lastCommit && repo.lastCommit.date
      ? repo.lastCommit.date
      : repo.updatedAt;
  if (!refDate) return false;
  const elapsed = Math.floor((Date.now() - new Date(refDate)) / 86400000);
  return elapsed > days;
}

function dormantPeriodLabel(dormantDays) {
  const d = Number(dormantDays);
  if (d <= 30) return "1 month";
  if (d <= 90) return "3 months";
  if (d <= 180) return "6 months";
  return "1 year";
}

module.exports = {
  isDormant,
  dormantPeriodLabel,
};
