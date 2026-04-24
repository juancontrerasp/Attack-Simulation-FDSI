'use strict';
const fs = require('fs');
const path = require('path');

const REPORT_PATH = path.resolve(__dirname, '../../security/trend-report.json');

function addSnapshot(registry) {
  const counts = { open: 0, mitigated: 0, accepted: 0, reopened: 0 };
  const byCategory = {};

  for (const entry of registry) {
    const s = entry.status;
    counts[s] = (counts[s] || 0) + 1;

    const cat = entry.category;
    if (!byCategory[cat]) byCategory[cat] = { open: 0, mitigated: 0, accepted: 0, reopened: 0 };
    byCategory[cat][s] = (byCategory[cat][s] || 0) + 1;
  }

  const snapshot = {
    date: new Date().toISOString(),
    total_open: counts.open || 0,
    total_mitigated: counts.mitigated || 0,
    total_accepted: counts.accepted || 0,
    total_reopened: counts.reopened || 0,
    by_category: byCategory
  };

  let report = [];
  if (fs.existsSync(REPORT_PATH)) {
    try { report = JSON.parse(fs.readFileSync(REPORT_PATH, 'utf-8')); } catch { report = []; }
  }

  report.push(snapshot);

  const dir = path.dirname(REPORT_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = REPORT_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(report, null, 2), 'utf-8');
  fs.renameSync(tmp, REPORT_PATH);

  console.log(`[trend] Snapshot #${report.length}: open=${snapshot.total_open}, mitigated=${snapshot.total_mitigated}, accepted=${snapshot.total_accepted}, reopened=${snapshot.total_reopened}`);
  return snapshot;
}

module.exports = { addSnapshot };
