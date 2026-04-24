'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REGISTRY_PATH = path.resolve(__dirname, '../../security/threat-registry.json');

function makeThreatId(threat) {
  const key = (threat.category || '') + ':' +
    (threat.component || '').toLowerCase() + ':' +
    (threat.description || '').slice(0, 80).toLowerCase();
  return crypto.createHash('md5').update(key).digest('hex');
}

function loadRegistry() {
  if (!fs.existsSync(REGISTRY_PATH)) return [];
  try {
    return JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf-8'));
  } catch {
    return [];
  }
}

function saveRegistry(registry) {
  const dir = path.dirname(REGISTRY_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = REGISTRY_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(registry, null, 2), 'utf-8');
  fs.renameSync(tmp, REGISTRY_PATH);
}

function updateFromAnalysis(threatsOutput) {
  const now = new Date().toISOString();
  const registry = loadRegistry();
  const registryMap = new Map(registry.map(e => [e.id, e]));

  const incoming = [];
  const threatsObj = threatsOutput.threats || {};
  for (const cat of Object.keys(threatsObj)) {
    for (const t of (threatsObj[cat] || [])) {
      incoming.push(t);
    }
  }

  const incomingIds = new Set(incoming.map(makeThreatId));

  for (const threat of incoming) {
    const id = makeThreatId(threat);
    const existing = registryMap.get(id);

    if (!existing) {
      registryMap.set(id, {
        id,
        category: threat.category,
        component: threat.component,
        description: threat.description,
        severity: threat.severity,
        status: 'open',
        created_at: now,
        updated_at: now,
        history: [{ status: 'open', changed_by: 'system', changed_at: now, reason: 'Detected in analysis' }]
      });
    } else if (existing.status === 'mitigated') {
      existing.status = 'reopened';
      existing.updated_at = now;
      existing.history.push({ status: 'reopened', changed_by: 'system', changed_at: now, reason: 'Threat reappeared in new analysis' });
    }
    // open, accepted, reopened → no automatic status change
  }

  // Auto-mitigate threats that were open and are no longer detected
  for (const [id, entry] of registryMap) {
    if (entry.status === 'open' && !incomingIds.has(id)) {
      entry.status = 'mitigated';
      entry.updated_at = now;
      entry.history.push({ status: 'mitigated', changed_by: 'system', changed_at: now, reason: 'Threat not found in latest analysis' });
    }
  }

  const updated = Array.from(registryMap.values());
  saveRegistry(updated);

  const counts = { open: 0, mitigated: 0, accepted: 0, reopened: 0 };
  for (const e of updated) counts[e.status] = (counts[e.status] || 0) + 1;
  console.log(`[registry] ${updated.length} threats tracked (open=${counts.open}, mitigated=${counts.mitigated}, accepted=${counts.accepted}, reopened=${counts.reopened})`);

  return updated;
}

module.exports = { loadRegistry, saveRegistry, updateFromAnalysis, makeThreatId };
