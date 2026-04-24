#!/usr/bin/env node
/**
 * compare.js (US-08)
 * Compares manual STRIDE analysis against automated analysis.
 * Calculates: Precision, Recall, F1, STRIDE coverage, TP, FP, FN.
 * Generates metrics-report.json and metrics-report.html.
 *
 * Usage:
 *   node compare.js
 */

"use strict";

const fs = require("fs");
const path = require("path");

// ── ANSI colours ─────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
  gray: "\x1b[90m",
};
const col = (c, t) => `${c}${t}${C.reset}`;

// ── Helpers ───────────────────────────────────────────────────────────────────

function loadJSON(filePath) {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) {
    console.error(col(C.red, `❌ File not found: ${filePath}`));
    process.exit(1);
  }
  try {
    return JSON.parse(fs.readFileSync(abs, "utf8"));
  } catch (e) {
    console.error(col(C.red, `❌ Failed to parse ${filePath}: ${e.message}`));
    process.exit(1);
  }
}

/** Normalised key: "category|component|severity" */
function key(t) {
  return [
    (t.category || "").trim().toLowerCase(),
    (t.component || "").trim().toLowerCase(),
    (t.severity || "").trim().toLowerCase(),
  ].join("|");
}

/** Extract threat list from various JSON formats */
function extractThreats(data) {
  if (Array.isArray(data.threats)) return data.threats;
  if (Array.isArray(data.combined_threats)) return data.combined_threats;
  const stride = data.stride_analysis || {};
  const threats = [];
  Object.values(stride).forEach((arr) => {
    if (Array.isArray(arr)) threats.push(...arr);
  });
  return threats;
}

/** Safe division – returns 0 when denominator is 0 */
function div(a, b) {
  return b === 0 ? 0 : a / b;
}

const STRIDE_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "InformationDisclosure",
  "DenialOfService",
  "ElevationOfPrivilege",
];

// Aliases used in combined-report.json
const CATEGORY_ALIASES = {
  "information disclosure": "InformationDisclosure",
  informationdisclosure: "InformationDisclosure",
  "denial of service": "DenialOfService",
  denialofservice: "DenialOfService",
  "elevation of privilege": "ElevationOfPrivilege",
  elevationofprivilege: "ElevationOfPrivilege",
  spoofing: "Spoofing",
  tampering: "Tampering",
  repudiation: "Repudiation",
};

function normaliseCategory(cat) {
  const lower = (cat || "").trim().toLowerCase().replace(/\s+/g, "");
  return CATEGORY_ALIASES[lower] || cat;
}

// ── Core calculation ──────────────────────────────────────────────────────────

function computeMetrics(manualThreats, automatedThreats) {
  const autoKeys = new Set(
    automatedThreats.map((t) => key({ ...t, category: normaliseCategory(t.category) }))
  );
  const manualKeys = new Set(
    manualThreats.map((t) => key({ ...t, category: normaliseCategory(t.category) }))
  );

  // Annotate manual threats
  const annotated = manualThreats.map((t) => {
    const normCat = normaliseCategory(t.category);
    const k = key({ ...t, category: normCat });
    return { ...t, category: normCat, _key: k, _matched: autoKeys.has(k) };
  });

  const tp = annotated.filter((t) => t._matched).length;
  const fn = annotated.filter((t) => !t._matched).length;

  // FP: automated threats not in manual set
  const fpThreats = automatedThreats.filter((t) => {
    const normCat = normaliseCategory(t.category);
    return !manualKeys.has(key({ ...t, category: normCat }));
  });
  const fp = fpThreats.length;

  const precision = div(tp, tp + fp);
  const recall = div(tp, tp + fn);
  const f1 = div(2 * precision * recall, precision + recall);

  // STRIDE coverage: % of STRIDE categories represented in automated output
  const automatedCategories = new Set(
    automatedThreats.map((t) => normaliseCategory(t.category))
  );
  const coveredCategories = STRIDE_CATEGORIES.filter((c) =>
    automatedCategories.has(c)
  );
  const strideCoverage = div(coveredCategories.length, STRIDE_CATEGORIES.length) * 100;

  // Per-category breakdown
  const perCategory = {};
  STRIDE_CATEGORIES.forEach((cat) => {
    const manInCat = annotated.filter((t) => t.category === cat);
    const autoInCat = automatedThreats.filter(
      (t) => normaliseCategory(t.category) === cat
    );
    const tpCat = manInCat.filter((t) => t._matched).length;
    const fnCat = manInCat.filter((t) => !t._matched).length;
    const manKeysInCat = new Set(manInCat.map((t) => t._key));
    const fpCat = autoInCat.filter(
      (t) => !manKeysInCat.has(key({ ...t, category: normaliseCategory(t.category) }))
    ).length;
    const pCat = div(tpCat, tpCat + fpCat);
    const rCat = div(tpCat, tpCat + fnCat);
    const f1Cat = div(2 * pCat * rCat, pCat + rCat);
    perCategory[cat] = {
      tp: tpCat,
      fp: fpCat,
      fn: fnCat,
      precision: pCat,
      recall: rCat,
      f1: f1Cat,
      covered: autoInCat.length > 0,
    };
  });

  // Per-severity breakdown
  const severities = ["Alta", "Media", "Baja"];
  const perSeverity = {};
  severities.forEach((sev) => {
    const manInSev = annotated.filter(
      (t) => (t.severity || "").toLowerCase() === sev.toLowerCase()
    );
    const autoInSev = automatedThreats.filter(
      (t) => (t.severity || "").toLowerCase() === sev.toLowerCase()
    );
    const tpSev = manInSev.filter((t) => t._matched).length;
    const fnSev = manInSev.filter((t) => !t._matched).length;
    const manKeysInSev = new Set(manInSev.map((t) => t._key));
    const fpSev = autoInSev.filter(
      (t) =>
        !manKeysInSev.has(
          key({ ...t, category: normaliseCategory(t.category) })
        )
    ).length;
    perSeverity[sev] = { tp: tpSev, fp: fpSev, fn: fnSev };
  });

  return {
    summary: { tp, fp, fn, precision, recall, f1, strideCoverage, coveredCategories },
    perCategory,
    perSeverity,
    annotatedManual: annotated,
    fpThreats,
  };
}

// ── HTML generation ────────────────────────────────────────────────────────────

function pct(v) {
  return (v * 100).toFixed(1) + "%";
}
function round2(v) {
  return Math.round(v * 100) / 100;
}

function barColor(v) {
  if (v >= 0.75) return "#4ade80";
  if (v >= 0.5) return "#facc15";
  return "#f87171";
}

function generateHTML(report) {
  const { summary, perCategory, perSeverity, annotatedManual, fpThreats } = report.metrics;

  const tpRows = annotatedManual
    .filter((t) => t._matched)
    .map(
      (t) =>
        `<tr class="tp"><td>✅ TP</td><td>${t.category}</td><td>${t.component}</td><td>${t.severity}</td></tr>`
    )
    .join("\n");

  const fnRows = annotatedManual
    .filter((t) => !t._matched)
    .map(
      (t) =>
        `<tr class="fn"><td>❌ FN</td><td>${t.category}</td><td>${t.component}</td><td>${t.severity}</td></tr>`
    )
    .join("\n");

  const fpRows = fpThreats
    .map(
      (t) =>
        `<tr class="fp"><td>⚠️ FP</td><td>${t.category}</td><td>${t.component}</td><td>${t.severity}</td></tr>`
    )
    .join("\n");

  const catRows = STRIDE_CATEGORIES.map((cat) => {
    const m = perCategory[cat];
    const covBadge = m.covered
      ? '<span class="badge green">✓</span>'
      : '<span class="badge red">✗</span>';
    return `<tr>
      <td>${cat}</td>
      <td class="num">${m.tp}</td>
      <td class="num">${m.fp}</td>
      <td class="num">${m.fn}</td>
      <td class="num">${pct(m.precision)}</td>
      <td class="num">${pct(m.recall)}</td>
      <td class="num">${pct(m.f1)}</td>
      <td>${covBadge}</td>
    </tr>`;
  }).join("\n");

  const severityRows = Object.entries(perSeverity)
    .map(
      ([sev, m]) =>
        `<tr><td>${sev}</td><td class="num">${m.tp}</td><td class="num">${m.fp}</td><td class="num">${m.fn}</td></tr>`
    )
    .join("\n");

  // Radar chart data
  const radarLabels = STRIDE_CATEGORIES.map((c) => `"${c}"`).join(",");
  const radarRecall = STRIDE_CATEGORIES.map((c) =>
    round2(perCategory[c].recall * 100)
  ).join(",");
  const radarPrecision = STRIDE_CATEGORIES.map((c) =>
    round2(perCategory[c].precision * 100)
  ).join(",");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>STRIDE Metrics Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d0d1a; color: #e2e8f0; min-height: 100vh; padding: 24px; }
    h1 { font-size: 1.8rem; color: #fff; margin-bottom: 4px; }
    .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 32px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .card { background: #1a1a2e; border: 1px solid #2d2d44; border-radius: 8px; padding: 20px; text-align: center; }
    .card .label { font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
    .card .value { font-size: 2rem; font-weight: 700; }
    .card .value.green { color: #4ade80; }
    .card .value.yellow { color: #facc15; }
    .card .value.red { color: #f87171; }
    .card .value.cyan { color: #22d3ee; }
    section { background: #1a1a2e; border: 1px solid #2d2d44; border-radius: 8px; padding: 24px; margin-bottom: 24px; }
    section h2 { font-size: 1.1rem; color: #fff; margin-bottom: 16px; border-bottom: 1px solid #2d2d44; padding-bottom: 8px; }
    .chart-wrap { max-width: 500px; margin: 0 auto; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { text-align: left; padding: 10px 12px; color: #888; font-weight: 600; border-bottom: 1px solid #2d2d44; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; }
    td { padding: 10px 12px; border-bottom: 1px solid #1e1e30; }
    td.num { text-align: right; font-variant-numeric: tabular-nums; }
    tr.tp td:first-child { color: #4ade80; }
    tr.fn td:first-child { color: #f87171; }
    tr.fp td:first-child { color: #facc15; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8rem; font-weight: 600; }
    .badge.green { background: rgba(74,222,128,.15); color: #4ade80; border: 1px solid #4ade80; }
    .badge.red { background: rgba(248,113,113,.15); color: #f87171; border: 1px solid #f87171; }
    .progress-bar { background: #2d2d44; border-radius: 4px; height: 8px; overflow: hidden; margin-top: 4px; }
    .progress-fill { height: 100%; border-radius: 4px; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }
    .ts { color: #555; font-size: 0.78rem; margin-top: 4px; }
  </style>
</head>
<body>
  <h1>🔒 STRIDE Metrics Report</h1>
  <p class="subtitle">Manual vs Automated Analysis Comparison &nbsp;·&nbsp; Generated ${new Date().toISOString()}</p>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card">
      <div class="label">Precision</div>
      <div class="value ${summary.precision >= 0.75 ? "green" : summary.precision >= 0.5 ? "yellow" : "red"}">${pct(summary.precision)}</div>
    </div>
    <div class="card">
      <div class="label">Recall</div>
      <div class="value ${summary.recall >= 0.75 ? "green" : summary.recall >= 0.5 ? "yellow" : "red"}">${pct(summary.recall)}</div>
    </div>
    <div class="card">
      <div class="label">F1 Score</div>
      <div class="value ${summary.f1 >= 0.75 ? "green" : summary.f1 >= 0.5 ? "yellow" : "red"}">${pct(summary.f1)}</div>
    </div>
    <div class="card">
      <div class="label">STRIDE Coverage</div>
      <div class="value cyan">${summary.strideCoverage.toFixed(0)}%</div>
    </div>
    <div class="card">
      <div class="label">True Positives</div>
      <div class="value green">${summary.tp}</div>
    </div>
    <div class="card">
      <div class="label">False Positives</div>
      <div class="value yellow">${summary.fp}</div>
    </div>
    <div class="card">
      <div class="label">False Negatives</div>
      <div class="value red">${summary.fn}</div>
    </div>
  </div>

  <div class="two-col">
    <!-- Radar Chart -->
    <section>
      <h2>📡 STRIDE Recall per Category</h2>
      <div class="chart-wrap">
        <canvas id="radarChart"></canvas>
      </div>
    </section>

    <!-- Per-Severity -->
    <section>
      <h2>🎯 Results by Severity</h2>
      <table>
        <thead><tr><th>Severity</th><th>TP</th><th>FP</th><th>FN</th></tr></thead>
        <tbody>${severityRows}</tbody>
      </table>

      <br>
      <h2>🔗 STRIDE Coverage</h2>
      ${STRIDE_CATEGORIES.map((cat) => {
        const covered = perCategory[cat].covered;
        return `<div style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;font-size:.85rem">
            <span>${cat}</span>
            <span style="color:${covered ? "#4ade80" : "#f87171"}">${covered ? "✓ Covered" : "✗ Missing"}</span>
          </div>
        </div>`;
      }).join("")}
    </section>
  </div>

  <!-- Per-Category table -->
  <section>
    <h2>📊 Per-Category Metrics</h2>
    <table>
      <thead>
        <tr><th>Category</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th><th>Covered</th></tr>
      </thead>
      <tbody>${catRows}</tbody>
    </table>
  </section>

  <!-- TP / FN / FP detail -->
  <section>
    <h2>🔍 Threat-level Classification</h2>
    <table>
      <thead><tr><th>Result</th><th>Category</th><th>Component</th><th>Severity</th></tr></thead>
      <tbody>
        ${tpRows}
        ${fnRows}
        ${fpRows}
      </tbody>
    </table>
  </section>

  <script>
    const ctx = document.getElementById('radarChart').getContext('2d');
    new Chart(ctx, {
      type: 'radar',
      data: {
        labels: [${radarLabels}],
        datasets: [
          {
            label: 'Recall (%)',
            data: [${radarRecall}],
            backgroundColor: 'rgba(34,211,238,0.15)',
            borderColor: '#22d3ee',
            pointBackgroundColor: '#22d3ee',
            borderWidth: 2,
          },
          {
            label: 'Precision (%)',
            data: [${radarPrecision}],
            backgroundColor: 'rgba(74,222,128,0.15)',
            borderColor: '#4ade80',
            pointBackgroundColor: '#4ade80',
            borderWidth: 2,
          }
        ]
      },
      options: {
        scales: {
          r: {
            min: 0,
            max: 100,
            ticks: { color: '#888', stepSize: 25 },
            grid: { color: '#2d2d44' },
            pointLabels: { color: '#ccc', font: { size: 11 } },
            angleLines: { color: '#2d2d44' }
          }
        },
        plugins: { legend: { labels: { color: '#ccc' } } }
      }
    });
  </script>
</body>
</html>`;
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  console.log(col(C.bold, "\n🔍 STRIDE Manual vs Automated Comparison (US-08)"));
  console.log(col(C.gray, "─".repeat(56)));

  // Load manual analyses
  const insecureData = loadJSON("manual-analysis-insecure.json");
  const secureData = loadJSON("manual-analysis-secure.json");

  // Load automated analysis
  let automatedData = null;
  for (const f of ["threats-output.json", "combined-report.json"]) {
    if (fs.existsSync(f)) {
      automatedData = loadJSON(f);
      console.log(`📂 Automated source: ${col(C.cyan, f)}`);
      break;
    }
  }
  if (!automatedData) {
    console.error(col(C.red, "❌ No automated analysis file found"));
    process.exit(1);
  }

  const manualInsecure = extractThreats(insecureData);
  const manualSecure = extractThreats(secureData);
  const manualAll = [...manualInsecure, ...manualSecure];
  const automated = extractThreats(automatedData);

  console.log(`📋 Manual threats (insecure): ${col(C.cyan, String(manualInsecure.length))}`);
  console.log(`📋 Manual threats (secure)  : ${col(C.cyan, String(manualSecure.length))}`);
  console.log(`🤖 Automated threats        : ${col(C.cyan, String(automated.length))}`);
  console.log(col(C.gray, "─".repeat(56)));

  // Compute metrics using insecure manual as ground truth (most comprehensive)
  const metrics = computeMetrics(manualInsecure, automated);
  const { summary } = metrics;

  // ── Console output ──
  console.log(col(C.bold, "\n📊 Overall Metrics:"));
  console.log(`   Precision      : ${col(C.green,  pct(summary.precision))}`);
  console.log(`   Recall         : ${col(C.green,  pct(summary.recall))}`);
  console.log(`   F1 Score       : ${col(C.green,  pct(summary.f1))}`);
  console.log(`   STRIDE Coverage: ${col(C.cyan,   summary.strideCoverage.toFixed(1) + "%")} (${summary.coveredCategories.length}/${STRIDE_CATEGORIES.length} categories)`);
  console.log(`   True Positives : ${col(C.green,  String(summary.tp))}`);
  console.log(`   False Positives: ${col(C.yellow, String(summary.fp))}`);
  console.log(`   False Negatives: ${col(C.red,    String(summary.fn))}`);

  console.log(col(C.bold, "\n📂 Per-Category:"));
  STRIDE_CATEGORIES.forEach((cat) => {
    const m = metrics.perCategory[cat];
    const cov = m.covered ? col(C.green, "✓") : col(C.red, "✗");
    console.log(
      `   ${cov} ${cat.padEnd(22)} P=${pct(m.precision).padStart(6)} R=${pct(m.recall).padStart(6)} F1=${pct(m.f1).padStart(6)} TP=${m.tp} FP=${m.fp} FN=${m.fn}`
    );
  });

  // ── Build report object ──
  const report = {
    generated_at: new Date().toISOString(),
    sources: {
      manual_insecure: "manual-analysis-insecure.json",
      manual_secure: "manual-analysis-secure.json",
      automated: automatedData ? "combined-report.json" : "threats-output.json",
    },
    metrics: {
      summary: {
        ...summary,
        strideCoverage: round2(summary.strideCoverage),
        precision: round2(summary.precision),
        recall: round2(summary.recall),
        f1: round2(summary.f1),
      },
      perCategory: Object.fromEntries(
        Object.entries(metrics.perCategory).map(([cat, m]) => [
          cat,
          {
            ...m,
            precision: round2(m.precision),
            recall: round2(m.recall),
            f1: round2(m.f1),
          },
        ])
      ),
      perSeverity: metrics.perSeverity,
      annotatedManual: metrics.annotatedManual.map(({ _key, ...rest }) => rest),
      fpThreats: metrics.fpThreats,
    },
  };

  // ── Write JSON report ──
  const jsonOut = path.resolve("metrics-report.json");
  fs.writeFileSync(jsonOut, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(col(C.green, `\n✅ metrics-report.json written`));

  // ── Write HTML report ──
  const htmlOut = path.resolve("metrics-report.html");
  fs.writeFileSync(htmlOut, generateHTML(report), "utf8");
  console.log(col(C.green, `✅ metrics-report.html written`));
  console.log(col(C.gray, `\n   Open: file://${htmlOut}\n`));
}

function pct(v) {
  return (v * 100).toFixed(1) + "%";
}
function round2(v) {
  return Math.round(v * 100) / 100;
}

main();
