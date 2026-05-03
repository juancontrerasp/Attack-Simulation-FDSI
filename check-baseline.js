#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execSync } = require('child_process');

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};
const color = (c, text) => `${c}${text}${C.reset}`;

const BASELINE_PATH = path.resolve('security/baseline.json');

const CATEGORY_ALIASES = {
  spoofing: 'Spoofing',
  tampering: 'Tampering',
  repudiation: 'Repudiation',
  informationdisclosure: 'InformationDisclosure',
  'information disclosure': 'InformationDisclosure',
  denialofservice: 'DenialOfService',
  'denial of service': 'DenialOfService',
  elevationofprivilege: 'ElevationOfPrivilege',
  'elevation of privilege': 'ElevationOfPrivilege'
};

function normalizeCategory(category) {
  const raw = String(category || '').trim();
  const compact = raw.toLowerCase().replace(/\s+/g, '');
  return CATEGORY_ALIASES[compact] || CATEGORY_ALIASES[raw.toLowerCase()] || raw || 'UnknownCategory';
}

function normalizeSeverity(severity) {
  const s = String(severity || '').trim().toLowerCase();
  if (s === 'alta') return 'Alta';
  if (s === 'media') return 'Media';
  if (s === 'baja') return 'Baja';
  return 'Media';
}

function baselineKey(entry) {
  return `${normalizeCategory(entry.category).toLowerCase()}|${String(entry.component || '').trim().toLowerCase()}`;
}

function loadJSON(filePath) {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) return null;
  try {
    return JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (error) {
    console.error(color(C.red, `❌ No se pudo parsear ${filePath}: ${error.message}`));
    return null;
  }
}

function extractThreats(data) {
  if (!data) return [];

  if (Array.isArray(data.combined_threats)) return data.combined_threats;
  if (Array.isArray(data.threats)) return data.threats;

  const groupedThreats = data.threats && typeof data.threats === 'object' ? data.threats : null;
  if (groupedThreats) {
    return Object.entries(groupedThreats).flatMap(([category, list]) => {
      if (!Array.isArray(list)) return [];
      return list.map((item) => ({ ...item, category: item.category || category }));
    });
  }

  const stride = data.stride_analysis || {};
  return Object.entries(stride).flatMap(([category, list]) => {
    if (!Array.isArray(list)) return [];
    return list.map((item) => ({ ...item, category: item.category || category }));
  });
}

function loadThreatsFromFile() {
  const threatsOutput = loadJSON('threats-output.json');
  if (threatsOutput) {
    return { source: 'threats-output.json', threats: extractThreats(threatsOutput) };
  }

  const combinedReport = loadJSON('combined-report.json');
  if (combinedReport) {
    return { source: 'combined-report.json', threats: extractThreats(combinedReport) };
  }

  return null;
}

function loadBaselineEntries() {
  const baseline = loadJSON(BASELINE_PATH);
  if (baseline === null) return null;

  if (Array.isArray(baseline)) return baseline;
  if (Array.isArray(baseline.approved_threats)) {
    return baseline.approved_threats.map((item) => ({
      category: item.category,
      component: item.component,
      accepted_by: item.accepted_by || 'security-team',
      acceptance_date: item.acceptance_date || item.approved_date || new Date().toISOString().slice(0, 10),
      reason: item.reason || 'Migrated from legacy baseline format'
    }));
  }

  return [];
}

function normalizeThreat(threat) {
  return {
    category: normalizeCategory(threat.category),
    component: String(threat.component || '').trim() || 'UnknownComponent',
    severity: normalizeSeverity(threat.severity),
    description: String(threat.description || '').trim(),
    mitigation: String(threat.mitigation || '').trim()
  };
}

function computeDiff(threats, baselineEntries) {
  const baselineSet = new Set(baselineEntries.map(baselineKey));
  const normalizedThreats = threats.map(normalizeThreat);
  const newThreats = normalizedThreats.filter((t) => !baselineSet.has(baselineKey(t)));
  const newHighThreats = newThreats.filter((t) => t.severity === 'Alta');
  const knownThreats = normalizedThreats.filter((t) => baselineSet.has(baselineKey(t)));

  return {
    normalizedThreats,
    knownThreats,
    newThreats,
    newHighThreats
  };
}


function appendGithubSummary(result) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;

  const lines = [
    '## STRIDE Baseline Check',
    '',
    `- Total detectadas: ${result.total}`,
    `- Conocidas (en baseline): ${result.known}`,
    `- Nuevas: ${result.newCount}`,
    `- Nuevas Alta: ${result.newHigh}`,
    '',
    `${result.known} amenazas conocidas, ${result.newCount} nuevas`
  ];

  if (result.newHigh > 0 && result.newHighList.length > 0) {
    lines.push('', '### Nuevas de severidad Alta');
    for (const t of result.newHighList) {
      lines.push(`- ${t.category} / ${t.component}`);
    }
  }

  fs.appendFileSync(summaryPath, lines.join('\n') + '\n');
}

function runCheckMode() {
  console.log(color(C.bold, '\n🔒 STRIDE Baseline Check'));
  console.log(color(C.gray, '─'.repeat(60)));

  const threatData = loadThreatsFromFile();
  if (!threatData) {
    console.error(color(C.red, '❌ No se encontró threats-output.json ni combined-report.json'));
    process.exit(1);
  }

  const baselineEntries = loadBaselineEntries();
  if (baselineEntries === null) {
    console.error(color(C.red, '❌ No se encontró security/baseline.json'));
    process.exit(1);
  }

  const diff = computeDiff(threatData.threats, baselineEntries);

  console.log(`📂 Fuente de amenazas: ${color(C.cyan, threatData.source)}`);
  console.log(`📊 Amenazas totales: ${color(C.cyan, String(diff.normalizedThreats.length))}`);
  console.log(`📋 Amenazas conocidas: ${color(C.cyan, String(diff.knownThreats.length))}`);
  console.log(`🆕 Amenazas nuevas: ${color(C.yellow, String(diff.newThreats.length))}`);

  const newMediumOrLow = diff.newThreats.filter((t) => t.severity !== 'Alta');
  if (newMediumOrLow.length > 0) {
    console.warn(color(C.yellow, `\n⚠️ ${newMediumOrLow.length} amenaza(s) nuevas Media/Baja (no bloquean build):`));
    for (const t of newMediumOrLow) {
      console.warn(`   - [${t.severity}] ${t.category} / ${t.component}`);
    }
  }

  const summary = {
    total: diff.normalizedThreats.length,
    known: diff.knownThreats.length,
    newCount: diff.newThreats.length,
    newHigh: diff.newHighThreats.length,
    newHighList: diff.newHighThreats
  };
  appendGithubSummary(summary);

  if (diff.newHighThreats.length > 0) {
    console.error(color(C.red, `\n❌ ${diff.newHighThreats.length} amenaza nueva de severidad Alta detectada:`));
    for (const t of diff.newHighThreats) {
      console.error(`   - ${t.category} / ${t.component}`);
      if (t.description) console.error(`     desc: ${t.description}`);
      if (t.mitigation) console.error(`     mitig: ${t.mitigation}`);
    }
    console.error(color(C.gray, '\nEjecuta: npm run update-baseline (o node check-baseline.js --update) para registrar amenazas aceptadas.'));
    process.exit(1);
  }

  console.log(color(C.green, '\n✅ Baseline check OK: no hay amenazas nuevas de severidad Alta.'));
  process.exit(0);
}

function askQuestion(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => resolve(answer.trim()));
  });
}

function saveBaseline(entries) {
  const sorted = [...entries].sort((a, b) => {
    const ka = baselineKey(a);
    const kb = baselineKey(b);
    return ka.localeCompare(kb);
  });
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(sorted, null, 2) + '\n', 'utf8');
}

function tryCommit(category, component) {
  const msg = `security: accept known threat [STRIDE-${category}/${component}]`;
  try {
    execSync('git add security/baseline.json', { stdio: 'ignore' });
    execSync(`git commit -m "${msg.replace(/"/g, '\\"')}"`, { stdio: 'ignore' });
    return { committed: true, message: msg };
  } catch {
    return { committed: false, message: msg };
  }
}

async function runUpdateMode() {
  console.log(color(C.bold, '\n📝 Baseline update interactivo'));
  console.log(color(C.gray, '─'.repeat(60)));

  const threatData = loadThreatsFromFile();
  if (!threatData) {
    console.error(color(C.red, '❌ No se encontró threats-output.json ni combined-report.json'));
    process.exit(1);
  }

  const baselineEntries = loadBaselineEntries();
  if (baselineEntries === null) {
    console.error(color(C.red, '❌ No se encontró security/baseline.json'));
    process.exit(1);
  }

  const diff = computeDiff(threatData.threats, baselineEntries);
  if (diff.newThreats.length === 0) {
    console.log(color(C.green, '✅ No hay amenazas nuevas para agregar al baseline.'));
    process.exit(0);
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  let accepted = 0;
  for (const threat of diff.newThreats) {
    console.log(`\n- [${threat.severity}] ${threat.category} / ${threat.component}`);
    if (threat.description) console.log(`  desc: ${threat.description}`);
    if (threat.mitigation) console.log(`  mitig: ${threat.mitigation}`);

    const decision = (await askQuestion(rl, '  ¿Aceptar en baseline? (Y/n): ')).toLowerCase();
    if (decision === 'n' || decision === 'no') {
      continue;
    }

    let reason = '';
    while (!reason) {
      reason = await askQuestion(rl, '  Razón de aceptación (obligatoria): ');
      reason = reason.trim();
      if (!reason) console.log(color(C.yellow, '  Debes indicar una razón explícita.'));
    }

    const acceptedBy = await askQuestion(rl, '  Aceptado por (default: security-team): ');
    const entry = {
      category: threat.category,
      component: threat.component,
      accepted_by: acceptedBy || 'security-team',
      acceptance_date: new Date().toISOString().slice(0, 10),
      reason
    };

    baselineEntries.push(entry);
    saveBaseline(baselineEntries);

    const commitResult = tryCommit(threat.category, threat.component);
    if (commitResult.committed) {
      console.log(color(C.green, `  ✔ Agregada y commiteada: ${commitResult.message}`));
    } else {
      console.log(color(C.yellow, '  ⚠ Agregada al baseline, pero no se pudo hacer commit automático.'));
    }
    accepted += 1;
  }

  rl.close();
  console.log(`\nResultado: ${accepted} amenaza(s) aceptadas y registradas en baseline.`);
}

if (process.argv.includes('--update')) {
  runUpdateMode().catch((error) => {
    console.error(color(C.red, `❌ Error en update-baseline: ${error.message}`));
    process.exit(1);
  });
} else {
  runCheckMode();
}
