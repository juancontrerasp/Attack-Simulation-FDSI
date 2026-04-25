#!/usr/bin/env node
/**
 * compare.js (US-08)
 * Compares manual STRIDE analysis against automated analysis.
 *
 * Paper metrics:
 *   - totalCoverage    = automated / manual_insecure * 100
 *   - recall           = TP / (TP + FN)
 *   - precision        = TP / (TP + FP)
 *   - f1               = 2 * P * R / (P + R)
 *   - falsePositiveRate= FP / automated * 100
 *   - strideCoverage   = covered_categories / 6 * 100
 *   - speedupRatio     = manual_time / automated_time
 *   - differentiationRatio = insecure_threats / secure_threats
 *
 * Format comparison: code vs. Mermaid vs. image (optional — graceful when absent).
 *
 * Outputs:
 *   - metrics-report.json    (all metrics, machine-readable)
 *   - metrics-report.html    (standalone, no internet required)
 *   - docs/results-table.tex (IEEE-style LaTeX tables for the paper)
 *
 * Usage:
 *   node compare.js
 */
"use strict";

const fs   = require("fs");
const path = require("path");

// ── ANSI colours ──────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m", bold: "\x1b[1m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  cyan: "\x1b[36m", gray: "\x1b[90m",
};
const col = (c, t) => `${c}${t}${C.reset}`;

// ── Constants ─────────────────────────────────────────────────────────────────
const STRIDE_CATEGORIES = [
  "Spoofing", "Tampering", "Repudiation",
  "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege",
];

const CATEGORY_ALIASES = {
  "information disclosure":  "InformationDisclosure",
  informationdisclosure:     "InformationDisclosure",
  "denial of service":       "DenialOfService",
  denialofservice:           "DenialOfService",
  "elevation of privilege":  "ElevationOfPrivilege",
  elevationofprivilege:      "ElevationOfPrivilege",
  spoofing:                  "Spoofing",
  tampering:                 "Tampering",
  repudiation:               "Repudiation",
};

// ── File helpers ──────────────────────────────────────────────────────────────

function findFile(...candidates) {
  for (const f of candidates) {
    const abs = path.resolve(f);
    if (fs.existsSync(abs)) return abs;
  }
  return null;
}

function loadJSON(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error(col(C.red, `❌ File not found: ${filePath}`));
    process.exit(1);
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (e) {
    console.error(col(C.red, `❌ Failed to parse ${filePath}: ${e.message}`));
    process.exit(1);
  }
}

function tryLoadJSON(...candidates) {
  const f = findFile(...candidates);
  if (!f) return null;
  try {
    return { data: JSON.parse(fs.readFileSync(f, "utf8")), file: f };
  } catch {
    return null;
  }
}

// ── Normalisation ─────────────────────────────────────────────────────────────

function normCat(cat) {
  const lower = (cat || "").trim().toLowerCase().replace(/\s+/g, "");
  return CATEGORY_ALIASES[lower] || cat;
}

function threatKey(t) {
  return [
    normCat(t.category).trim().toLowerCase(),
    (t.component || "").trim().toLowerCase(),
    (t.severity  || "").trim().toLowerCase(),
  ].join("|");
}

function extractThreats(data) {
  if (!data) return [];
  // Flat array
  if (Array.isArray(data.threats)) return data.threats;
  // Combined report
  if (Array.isArray(data.combined_threats)) return data.combined_threats;
  // Nested per-category object (agent output schema)
  const stride = data.stride_analysis || {};
  if (Object.keys(stride).length) {
    const out = [];
    Object.values(stride).forEach(arr => { if (Array.isArray(arr)) out.push(...arr); });
    return out;
  }
  // threats as object with category keys
  if (data.threats && typeof data.threats === "object" && !Array.isArray(data.threats)) {
    const out = [];
    Object.values(data.threats).forEach(arr => { if (Array.isArray(arr)) out.push(...arr); });
    return out;
  }
  return [];
}

function extractMeta(data) {
  return data?.metadata || data?.meta || {};
}

// ── Maths ─────────────────────────────────────────────────────────────────────

const div    = (a, b) => b === 0 ? 0 : a / b;
const pct    = v => (v * 100).toFixed(1) + "%";
const round2 = v => Math.round(v * 100) / 100;

function barColor(v) {
  if (v >= 75) return "#4ade80";
  if (v >= 50) return "#facc15";
  return "#f87171";
}

// ── Core comparison ───────────────────────────────────────────────────────────

function computeMetrics(manualThreats, automatedThreats) {
  const autoKeys   = new Set(automatedThreats.map(t => threatKey({ ...t, category: normCat(t.category) })));
  const manualKeys = new Set(manualThreats.map(t => threatKey({ ...t, category: normCat(t.category) })));

  const annotated = manualThreats.map(t => {
    const nc = normCat(t.category);
    const k  = threatKey({ ...t, category: nc });
    return { ...t, category: nc, _key: k, _matched: autoKeys.has(k) };
  });

  const tp = annotated.filter(t =>  t._matched).length;
  const fn = annotated.filter(t => !t._matched).length;

  const fpThreats = automatedThreats.filter(t =>
    !manualKeys.has(threatKey({ ...t, category: normCat(t.category) }))
  );
  const fp = fpThreats.length;

  const precision = div(tp, tp + fp);
  const recall    = div(tp, tp + fn);
  const f1        = div(2 * precision * recall, precision + recall);

  const automatedCats  = new Set(automatedThreats.map(t => normCat(t.category)));
  const coveredCats    = STRIDE_CATEGORIES.filter(c => automatedCats.has(c));
  const strideCoverage = div(coveredCats.length, STRIDE_CATEGORIES.length) * 100;

  // Per-category breakdown
  const perCategory = {};
  STRIDE_CATEGORIES.forEach(cat => {
    const manInCat  = annotated.filter(t => t.category === cat);
    const autoInCat = automatedThreats.filter(t => normCat(t.category) === cat);
    const tpC = manInCat.filter(t => t._matched).length;
    const fnC = manInCat.filter(t => !t._matched).length;
    const manCatKeys = new Set(manInCat.map(t => t._key));
    const fpC = autoInCat.filter(t =>
      !manCatKeys.has(threatKey({ ...t, category: normCat(t.category) }))
    ).length;
    const pC  = div(tpC, tpC + fpC);
    const rC  = div(tpC, tpC + fnC);
    const f1C = div(2 * pC * rC, pC + rC);
    perCategory[cat] = { tp: tpC, fp: fpC, fn: fnC, precision: pC, recall: rC, f1: f1C, covered: autoInCat.length > 0 };
  });

  // Per-severity breakdown
  const perSeverity = {};
  ["Alta", "Media", "Baja"].forEach(sev => {
    const manInSev  = annotated.filter(t => (t.severity || "").toLowerCase() === sev.toLowerCase());
    const autoInSev = automatedThreats.filter(t => (t.severity || "").toLowerCase() === sev.toLowerCase());
    const tpS = manInSev.filter(t => t._matched).length;
    const fnS = manInSev.filter(t => !t._matched).length;
    const manSevKeys = new Set(manInSev.map(t => t._key));
    const fpS = autoInSev.filter(t =>
      !manSevKeys.has(threatKey({ ...t, category: normCat(t.category) }))
    ).length;
    perSeverity[sev] = { tp: tpS, fp: fpS, fn: fnS };
  });

  return { summary: { tp, fp, fn, precision, recall, f1, strideCoverage, coveredCategories: coveredCats }, perCategory, perSeverity, annotatedManual: annotated, fpThreats };
}

// ── Format comparison ─────────────────────────────────────────────────────────

function computeFormatMetrics(manualThreats, label, ...candidates) {
  const result = tryLoadJSON(...candidates);
  if (!result) return null;
  const autoThreats = extractThreats(result.data);
  if (!autoThreats.length) return null;
  const m = computeMetrics(manualThreats, autoThreats);
  const s = m.summary;
  return {
    label,
    file: path.basename(result.file),
    threatsCount:      autoThreats.length,
    precision:         round2(s.precision),
    recall:            round2(s.recall),
    f1:                round2(s.f1),
    strideCoverage:    round2(s.strideCoverage),
    coveredCategories: s.coveredCategories,
    totalCoverage:     round2(div(autoThreats.length, manualThreats.length) * 100),
  };
}

// ── SVG chart helpers (standalone — no external dependencies) ─────────────────

function svgHBar(categories, values, title, width = 580) {
  const barH = 28, gap = 8;
  const marginL = 190, marginR = 72, marginT = 44, marginB = 16;
  const plotW  = width - marginL - marginR;
  const height = marginT + categories.length * (barH + gap) + marginB;

  const bars = categories.map((cat, i) => {
    const v    = values[i];
    const barW = Math.max(0, (v / 100) * plotW);
    const y    = marginT + i * (barH + gap);
    const fill = barColor(v);
    return `    <text x="${marginL - 8}" y="${(y + barH / 2 + 4).toFixed(1)}" text-anchor="end" font-size="12" fill="#aaa">${cat}</text>
    <rect x="${marginL}" y="${y}" width="${barW.toFixed(1)}" height="${barH}" fill="${fill}" rx="3"/>
    <text x="${(marginL + barW + 7).toFixed(1)}" y="${(y + barH / 2 + 4).toFixed(1)}" font-size="12" fill="#eee">${v.toFixed(1)}%</text>`;
  }).join("\n");

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" style="display:block;background:#1a1a2e;border-radius:8px;width:100%;height:auto">
  <text x="${(width / 2).toFixed(1)}" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#fff">${title}</text>
${bars}
</svg>`;
}

function svgRadar(labels, datasets, size = 380) {
  const cx = size / 2, cy = size / 2, r = size * 0.36;
  const n  = labels.length;
  const ang = i => -Math.PI / 2 + i * (2 * Math.PI / n);
  const px  = (i, f) => (cx + Math.cos(ang(i)) * r * f).toFixed(2);
  const py  = (i, f) => (cy + Math.sin(ang(i)) * r * f).toFixed(2);

  const grids = [0.25, 0.5, 0.75, 1.0].map(lv => {
    const pts = Array.from({ length: n }, (_, i) => `${px(i, lv)},${py(i, lv)}`).join(" ");
    return `<polygon points="${pts}" fill="none" stroke="#2d2d44" stroke-width="1"/>`;
  }).join("\n  ");

  const axes = Array.from({ length: n }, (_, i) =>
    `<line x1="${cx}" y1="${cy}" x2="${px(i, 1)}" y2="${py(i, 1)}" stroke="#2d2d44" stroke-width="1"/>`
  ).join("\n  ");

  const lbls = labels.map((lbl, i) => {
    const lx  = parseFloat(px(i, 1.2));
    const ly  = parseFloat(py(i, 1.2));
    const anc = Math.cos(ang(i)) > 0.15 ? "start" : Math.cos(ang(i)) < -0.15 ? "end" : "middle";
    const shortLabel = lbl.replace("InformationDisclosure", "InfoDisc")
                          .replace("ElevationOfPrivilege", "EoP")
                          .replace("DenialOfService", "DoS");
    return `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anc}" dominant-baseline="middle" font-size="11" fill="#ccc">${shortLabel}</text>`;
  }).join("\n  ");

  const polygons = datasets.map(ds => {
    const pts = Array.from({ length: n }, (_, i) =>
      `${px(i, ds.values[i] / 100)},${py(i, ds.values[i] / 100)}`
    ).join(" ");
    return `<polygon points="${pts}" fill="${ds.fill}" stroke="${ds.stroke}" stroke-width="2" opacity="0.85"/>`;
  }).join("\n  ");

  const legend = datasets.map((ds, i) =>
    `<rect x="${10 + i * 130}" y="${size - 22}" width="13" height="13" fill="${ds.stroke}" rx="3"/>
   <text x="${28 + i * 130}" y="${size - 11}" font-size="11" fill="#ccc">${ds.label}</text>`
  ).join("\n  ");

  const gridLabels = [0.25, 0.5, 0.75].map(lv =>
    `<text x="${(parseFloat(px(0, lv)) + 4).toFixed(1)}" y="${parseFloat(py(0, lv)).toFixed(1)}" font-size="9" fill="#556">${(lv * 100).toFixed(0)}%</text>`
  ).join("\n  ");

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" style="display:block;background:#1a1a2e;border-radius:8px;width:100%;height:auto">
  ${grids}
  ${axes}
  ${polygons}
  ${lbls}
  ${gridLabels}
  ${legend}
</svg>`;
}

// ── HTML generation (fully standalone — no CDN dependencies) ──────────────────

function generateHTML(report) {
  const { summary, perCategory, perSeverity, annotatedManual, fpThreats } = report.metrics;
  const pm = report.paper_metrics;

  // Bar charts (SVG)
  const recallVals    = STRIDE_CATEGORIES.map(c => perCategory[c].recall * 100);
  const precisionVals = STRIDE_CATEGORIES.map(c => perCategory[c].precision * 100);
  const recallBar     = svgHBar(STRIDE_CATEGORIES, recallVals,    "Recall (%) por categoría STRIDE");
  const precisionBar  = svgHBar(STRIDE_CATEGORIES, precisionVals, "Precision (%) por categoría STRIDE");

  // Radar chart (SVG)
  const radarSVG = svgRadar(STRIDE_CATEGORIES, [
    { label: "Recall",    values: recallVals,    stroke: "#22d3ee", fill: "rgba(34,211,238,0.12)" },
    { label: "Precision", values: precisionVals, stroke: "#4ade80", fill: "rgba(74,222,128,0.12)" },
  ]);

  // Threat detail rows
  const mkRow = (t, cls, icon) =>
    `<tr class="${cls}"><td>${icon}</td><td>${t.category}</td><td>${t.component}</td><td>${t.severity}</td></tr>`;
  const tpRows = annotatedManual.filter(t =>  t._matched).map(t => mkRow(t, "tp", "✅ TP")).join("\n");
  const fnRows = annotatedManual.filter(t => !t._matched).map(t => mkRow(t, "fn", "❌ FN")).join("\n");
  const fpRows = fpThreats.map(t => mkRow(t, "fp", "⚠️ FP")).join("\n");

  const catRows = STRIDE_CATEGORIES.map(cat => {
    const m = perCategory[cat];
    const badge = m.covered
      ? '<span class="badge green">✓</span>'
      : '<span class="badge red">✗</span>';
    return `<tr>
      <td>${cat}</td>
      <td class="num">${m.tp}</td><td class="num">${m.fp}</td><td class="num">${m.fn}</td>
      <td class="num">${pct(m.precision)}</td><td class="num">${pct(m.recall)}</td><td class="num">${pct(m.f1)}</td>
      <td>${badge}</td>
    </tr>`;
  }).join("\n");

  const sevRows = Object.entries(perSeverity).map(([sev, m]) =>
    `<tr><td>${sev}</td><td class="num">${m.tp}</td><td class="num">${m.fp}</td><td class="num">${m.fn}</td></tr>`
  ).join("\n");

  // Format comparison section
  const fmtEntries = Object.entries(report.format_comparison || {}).filter(([, v]) => v !== null);
  const formatSection = fmtEntries.length ? `
  <section>
    <h2>🗂️ Comparación por Formato de Entrada</h2>
    <p style="color:#888;font-size:.85rem;margin-bottom:12px">Mismo sistema analizado con código fuente, diagrama Mermaid e imagen.</p>
    <table>
      <thead><tr><th>Formato</th><th>Amenazas</th><th>Recall</th><th>Precision</th><th>F1</th><th>Cobertura total</th><th>Cobertura STRIDE</th></tr></thead>
      <tbody>
        ${fmtEntries.map(([, m]) =>
          `<tr>
            <td>${m.label}</td>
            <td class="num">${m.threatsCount}</td>
            <td class="num">${(m.recall    * 100).toFixed(1)}%</td>
            <td class="num">${(m.precision * 100).toFixed(1)}%</td>
            <td class="num">${(m.f1        * 100).toFixed(1)}%</td>
            <td class="num">${m.totalCoverage.toFixed(1)}%</td>
            <td class="num">${m.strideCoverage.toFixed(1)}%</td>
          </tr>`
        ).join("\n        ")}
      </tbody>
    </table>
  </section>` : "";

  // Paper metrics panel
  const speedupStr = pm.speedupRatio !== null ? `${pm.speedupRatio.toFixed(0)}×` : "N/A";
  const paperPanel = `
  <section>
    <h2>📄 Métricas del Paper (US-08)</h2>
    <div class="paper-grid">
      <div class="pm-item"><span class="pm-label">Cobertura total</span><span class="pm-val">${pm.totalCoverage.toFixed(1)}%</span></div>
      <div class="pm-item"><span class="pm-label">Tasa falsos positivos</span><span class="pm-val">${pm.falsePositiveRate.toFixed(1)}%</span></div>
      <div class="pm-item"><span class="pm-label">Tiempo manual (s)</span><span class="pm-val">${pm.manualTimeSeconds ?? "N/A"}</span></div>
      <div class="pm-item"><span class="pm-label">Tiempo automatizado (s)</span><span class="pm-val">${pm.automatedTimeSeconds ?? "N/A"}</span></div>
      <div class="pm-item"><span class="pm-label">Ratio de velocidad</span><span class="pm-val">${speedupStr}</span></div>
      <div class="pm-item"><span class="pm-label">Ratio diferenciación (manual)</span><span class="pm-val">${pm.differentiationRatioManual.toFixed(2)}</span></div>
      <div class="pm-item"><span class="pm-label">Amenazas inseguro (manual)</span><span class="pm-val">${pm.manualInsecureCount}</span></div>
      <div class="pm-item"><span class="pm-label">Amenazas seguro (manual)</span><span class="pm-val">${pm.manualSecureCount}</span></div>
    </div>
  </section>`;

  // Coverage status mini-list
  const covList = STRIDE_CATEGORIES.map(cat => {
    const cov = perCategory[cat].covered;
    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #1e1e30;font-size:.85rem">
        <span>${cat}</span>
        <span style="color:${cov ? "#4ade80" : "#f87171"};font-weight:600">${cov ? "✓ Cubierta" : "✗ Faltante"}</span>
      </div>`;
  }).join("\n      ");

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>STRIDE Metrics Report — US-08</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d0d1a;color:#e2e8f0;min-height:100vh;padding:24px}
    h1{font-size:1.8rem;color:#fff;margin-bottom:4px}
    .subtitle{color:#888;font-size:.9rem;margin-bottom:28px}
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:14px;margin-bottom:28px}
    .card{background:#1a1a2e;border:1px solid #2d2d44;border-radius:8px;padding:18px;text-align:center}
    .card .label{font-size:.72rem;color:#888;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
    .card .value{font-size:1.85rem;font-weight:700}
    .green{color:#4ade80}.yellow{color:#facc15}.red{color:#f87171}.cyan{color:#22d3ee}
    section{background:#1a1a2e;border:1px solid #2d2d44;border-radius:8px;padding:22px;margin-bottom:22px}
    section h2{font-size:1.05rem;color:#fff;margin-bottom:14px;border-bottom:1px solid #2d2d44;padding-bottom:8px}
    .two-col{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-bottom:22px}
    .three-col{display:grid;grid-template-columns:1fr 1fr 1fr;gap:22px;margin-bottom:22px}
    @media(max-width:900px){.two-col,.three-col{grid-template-columns:1fr}}
    table{width:100%;border-collapse:collapse;font-size:.87rem}
    th{text-align:left;padding:9px 11px;color:#888;font-weight:600;border-bottom:1px solid #2d2d44;text-transform:uppercase;font-size:.72rem;letter-spacing:.5px}
    td{padding:9px 11px;border-bottom:1px solid #1e1e30}
    td.num{text-align:right;font-variant-numeric:tabular-nums}
    tr.tp td:first-child{color:#4ade80}
    tr.fn td:first-child{color:#f87171}
    tr.fp td:first-child{color:#facc15}
    .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.78rem;font-weight:600}
    .badge.green{background:rgba(74,222,128,.15);color:#4ade80;border:1px solid #4ade80}
    .badge.red{background:rgba(248,113,113,.15);color:#f87171;border:1px solid #f87171}
    .paper-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:10px}
    .pm-item{background:#12122a;border-radius:6px;padding:12px 15px;display:flex;flex-direction:column;gap:4px}
    .pm-label{font-size:.72rem;color:#888;text-transform:uppercase;letter-spacing:.5px}
    .pm-val{font-size:1.25rem;font-weight:700;color:#22d3ee}
  </style>
</head>
<body>
  <h1>🔒 STRIDE Metrics Report — US-08</h1>
  <p class="subtitle">Manual vs. Automatizado · Generado ${new Date().toISOString()}</p>

  <!-- Resumen general -->
  <div class="cards">
    <div class="card"><div class="label">Precision</div>
      <div class="value ${summary.precision >= 0.75 ? "green" : summary.precision >= 0.5 ? "yellow" : "red"}">${pct(summary.precision)}</div></div>
    <div class="card"><div class="label">Recall</div>
      <div class="value ${summary.recall >= 0.75 ? "green" : summary.recall >= 0.5 ? "yellow" : "red"}">${pct(summary.recall)}</div></div>
    <div class="card"><div class="label">F1 Score</div>
      <div class="value ${summary.f1 >= 0.75 ? "green" : summary.f1 >= 0.5 ? "yellow" : "red"}">${pct(summary.f1)}</div></div>
    <div class="card"><div class="label">Cobertura STRIDE</div>
      <div class="value cyan">${summary.strideCoverage.toFixed(0)}%</div></div>
    <div class="card"><div class="label">True Positives</div><div class="value green">${summary.tp}</div></div>
    <div class="card"><div class="label">False Positives</div><div class="value yellow">${summary.fp}</div></div>
    <div class="card"><div class="label">False Negatives</div><div class="value red">${summary.fn}</div></div>
  </div>

  ${paperPanel}

  <!-- Gráficas de barras (standalone SVG) -->
  <div class="two-col">
    <section><h2>📊 Recall por categoría STRIDE</h2>${recallBar}</section>
    <section><h2>🎯 Precision por categoría STRIDE</h2>${precisionBar}</section>
  </div>

  <!-- Radar chart (standalone SVG) -->
  <div class="two-col">
    <section><h2>📡 Radar: Recall vs Precision por categoría</h2>${radarSVG}</section>
    <section>
      <h2>🔗 Estado de cobertura STRIDE</h2>
      ${covList}
    </section>
  </div>

  <!-- Tabla por categoría -->
  <section>
    <h2>📋 Métricas por categoría</h2>
    <table>
      <thead><tr><th>Categoría</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th><th>Cubierta</th></tr></thead>
      <tbody>${catRows}</tbody>
    </table>
  </section>

  <div class="two-col">
    <!-- Por severidad -->
    <section>
      <h2>🎯 Resultados por severidad</h2>
      <table>
        <thead><tr><th>Severidad</th><th>TP</th><th>FP</th><th>FN</th></tr></thead>
        <tbody>${sevRows}</tbody>
      </table>
    </section>

    <!-- Fuentes -->
    <section>
      <h2>📂 Fuentes de datos</h2>
      <div style="font-size:.85rem;color:#aaa;line-height:1.9">
        <div><strong style="color:#ccc">Manual inseguro:</strong> ${report.sources.manual_insecure}</div>
        <div><strong style="color:#ccc">Manual seguro:</strong> ${report.sources.manual_secure}</div>
        <div><strong style="color:#ccc">Automatizado:</strong> ${report.sources.automated}</div>
      </div>
    </section>
  </div>

  ${formatSection}

  <!-- Detalle por amenaza -->
  <section>
    <h2>🔍 Clasificación detallada de amenazas</h2>
    <table>
      <thead><tr><th>Resultado</th><th>Categoría</th><th>Componente</th><th>Severidad</th></tr></thead>
      <tbody>
        ${tpRows}
        ${fnRows}
        ${fpRows}
      </tbody>
    </table>
  </section>
</body>
</html>`;
}

// ── LaTeX generation (IEEE tabular format) ────────────────────────────────────

function generateLatex(paperMetrics, perCategory, sources) {
  const pm   = paperMetrics;
  const date = new Date().toISOString().slice(0, 10);

  const speedStr   = pm.speedupRatio !== null ? `${pm.speedupRatio.toFixed(0)}\\texttimes{}` : "N/A";
  const autoTime   = pm.automatedTimeSeconds !== null ? String(pm.automatedTimeSeconds) : "N/A";
  const diffAuto   = pm.differentiationRatioAuto !== null ? pm.differentiationRatioAuto.toFixed(2) : "--";

  const catRows = STRIDE_CATEGORIES.map(cat => {
    const m   = perCategory[cat];
    const cov = m.covered ? "\\checkmark" : "\\texttimes{}";
    return `    ${cat} & ${m.tp} & ${m.fp} & ${m.fn} & ${(m.recall * 100).toFixed(1)}\\% & ${(m.precision * 100).toFixed(1)}\\% & ${cov} \\\\`;
  }).join("\n");

  return `% Auto-generated by compare.js — ${date}
% To include in your paper add: \\input{docs/results-table}
% Requires LaTeX packages: booktabs

%% ─── Table 1: Summary comparison ────────────────────────────────────────────
\\begin{table}[!htb]
\\centering
\\caption{Quantitative Comparison: Manual vs.\\ AI-Agent STRIDE Analysis}
\\label{tab:stride-comparison}
\\begin{tabular}{@{}lrr@{}}
\\toprule
\\textbf{Metric} & \\textbf{Manual} & \\textbf{AI Agent} \\\\
\\midrule
Threats detected --- insecure system & ${pm.manualInsecureCount} & ${pm.automatedCount} \\\\
Threats detected --- secure system   & ${pm.manualSecureCount}   & -- \\\\
Total coverage (\\%)                  & 100.0 & ${pm.totalCoverage.toFixed(1)} \\\\
Recall (\\%)                          & 100.0 & ${(pm.recall * 100).toFixed(1)} \\\\
Precision (\\%)                       & --    & ${(pm.precision * 100).toFixed(1)} \\\\
False positive rate (\\%)             & --    & ${pm.falsePositiveRate.toFixed(1)} \\\\
F1 Score (\\%)                        & --    & ${(pm.f1 * 100).toFixed(1)} \\\\
Analysis time (s)                    & ${pm.manualTimeSeconds ?? "N/A"} & ${autoTime} \\\\
Speedup ratio                        & 1\\texttimes{} & ${speedStr} \\\\
Differentiation ratio                & ${pm.differentiationRatioManual.toFixed(2)} & ${diffAuto} \\\\
STRIDE categories covered            & 6/6   & ${pm.strideCategorisCovered}/6 \\\\
\\bottomrule
\\end{tabular}
\\end{table}

%% ─── Table 2: Per-category breakdown ────────────────────────────────────────
\\begin{table}[!htb]
\\centering
\\caption{Per-Category STRIDE Metrics: AI Agent vs.\\ Manual Ground Truth}
\\label{tab:per-category}
\\begin{tabular}{@{}lrrrrrrc@{}}
\\toprule
\\textbf{Category} & \\textbf{TP} & \\textbf{FP} & \\textbf{FN} & \\textbf{Recall} & \\textbf{Precision} & \\textbf{Covered} \\\\
\\midrule
${catRows}
\\bottomrule
\\end{tabular}
\\\\[3pt]
\\footnotesize{TP = True Positive; FP = False Positive; FN = False Negative.
Coverage = (agent threats / manual threats) $\\times$ 100.
Differentiation = threats(insecure) / threats(secure).
Sources: \\texttt{${path.basename(sources.manual_insecure)}},
\\texttt{${path.basename(sources.automated)}}.
Generated ${date}.}
\\end{table}
`;
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  console.log(col(C.bold, "\n🔍 STRIDE Manual vs. Automated Comparison (US-08)"));
  console.log(col(C.gray, "─".repeat(62)));

  // 1. Load manual analyses (prefer threat-models/ directory)
  const insecurePath = findFile(
    "threat-models/manual-analysis-insecure.json",
    "manual-analysis-insecure.json"
  );
  const securePath = findFile(
    "threat-models/manual-analysis-secure.json",
    "manual-analysis-secure.json"
  );
  if (!insecurePath) { console.error(col(C.red, "❌ manual-analysis-insecure.json not found")); process.exit(1); }
  if (!securePath)   { console.error(col(C.red, "❌ manual-analysis-secure.json not found"));   process.exit(1); }

  const insecureData = loadJSON(insecurePath);
  const secureData   = loadJSON(securePath);
  console.log(`📋 Manual insecure : ${col(C.cyan, insecurePath)}`);
  console.log(`📋 Manual secure   : ${col(C.cyan, securePath)}`);

  // 2. Load automated analysis
  const autoResult = tryLoadJSON("threats-output.json", "combined-report.json");
  if (!autoResult) {
    console.error(col(C.red, "❌ No automated analysis file found (threats-output.json / combined-report.json)"));
    process.exit(1);
  }
  console.log(`🤖 Automated       : ${col(C.cyan, autoResult.file)}`);
  console.log(col(C.gray, "─".repeat(62)));

  // 3. Extract threats
  const manualInsecure = extractThreats(insecureData);
  const manualSecure   = extractThreats(secureData);
  const automated      = extractThreats(autoResult.data);
  const insecureMeta   = extractMeta(insecureData);
  const autoMeta       = extractMeta(autoResult.data);

  console.log(`   Manual insecure threats : ${col(C.yellow, String(manualInsecure.length))}`);
  console.log(`   Manual secure threats   : ${col(C.yellow, String(manualSecure.length))}`);
  console.log(`   Automated threats       : ${col(C.yellow, String(automated.length))}`);

  // 4. Core metrics (insecure manual as ground truth)
  const metrics = computeMetrics(manualInsecure, automated);
  const { summary } = metrics;

  // 5. Paper-specific metrics
  const manualTimeSec  = insecureMeta.analysisTimeSeconds ?? insecureMeta.analysis_time_seconds ?? null;
  const autoTimeSec    = autoMeta.analysis_time_seconds   ?? autoMeta.analysisTimeSeconds       ?? null;
  const speedupRatio   = (manualTimeSec && autoTimeSec && autoTimeSec > 0)
    ? round2(manualTimeSec / autoTimeSec) : null;

  // totalCoverage: agent count / manual insecure count * 100  (per US-08 spec)
  const totalCoverage    = round2(div(automated.length, manualInsecure.length) * 100);
  // falsePositiveRate: FP / total automated * 100
  const falsePositiveRate = round2(div(summary.fp, automated.length) * 100);
  // differentiationRatio: insecure / secure (measures separation power)
  const differentiationRatioManual = round2(div(manualInsecure.length, manualSecure.length));

  const paperMetrics = {
    manualInsecureCount:        manualInsecure.length,
    manualSecureCount:          manualSecure.length,
    automatedCount:             automated.length,
    totalCoverage,
    recall:                     round2(summary.recall),
    precision:                  round2(summary.precision),
    f1:                         round2(summary.f1),
    falsePositiveRate,
    strideCoverage:             round2(summary.strideCoverage),
    strideCategorisCovered:     summary.coveredCategories.length,
    manualTimeSeconds:          manualTimeSec,
    automatedTimeSeconds:       autoTimeSec,
    speedupRatio,
    differentiationRatioManual,
    differentiationRatioAuto:   null,  // set when automated run on secure system exists
  };

  // 6. Format comparison (code / Mermaid / image)
  const formatComparison = {
    code:    computeFormatMetrics(manualInsecure, "Code (Java)",  "threats-output-code.json"),
    mermaid: computeFormatMetrics(manualInsecure, "Mermaid",      "threats-output-mermaid.json"),
    image:   computeFormatMetrics(manualInsecure, "Image",        "threats-output-image.json"),
  };
  // If no format-specific files exist, treat current automated output as "code"
  const hasAnyFormat = Object.values(formatComparison).some(v => v !== null);
  if (!hasAnyFormat) {
    formatComparison.code = {
      label: "Code (Java)",
      file: path.basename(autoResult.file),
      threatsCount: automated.length,
      precision: round2(summary.precision),
      recall:    round2(summary.recall),
      f1:        round2(summary.f1),
      strideCoverage: round2(summary.strideCoverage),
      coveredCategories: summary.coveredCategories,
      totalCoverage,
    };
  }

  // 7. Console report
  console.log(col(C.bold, "\n📊 Métricas globales:"));
  console.log(`   Precision           : ${col(C.green,  pct(summary.precision))}`);
  console.log(`   Recall              : ${col(C.green,  pct(summary.recall))}`);
  console.log(`   F1 Score            : ${col(C.green,  pct(summary.f1))}`);
  console.log(`   Cobertura total     : ${col(C.cyan,   totalCoverage.toFixed(1) + "%")} (${automated.length}/${manualInsecure.length} amenazas)`);
  console.log(`   Tasa falsos posit.  : ${col(C.yellow, falsePositiveRate.toFixed(1) + "%")}`);
  console.log(`   Cobertura STRIDE    : ${col(C.cyan,   summary.strideCoverage.toFixed(1) + "%")} (${summary.coveredCategories.length}/6 categorías)`);
  console.log(`   TP / FP / FN        : ${col(C.green, String(summary.tp))} / ${col(C.yellow, String(summary.fp))} / ${col(C.red, String(summary.fn))}`);
  if (speedupRatio) console.log(`   Ratio velocidad     : ${col(C.cyan, speedupRatio.toFixed(0) + "×")}`);
  console.log(`   Ratio diferenciación: ${col(C.cyan, differentiationRatioManual.toFixed(2))} (inseguro/seguro = ${manualInsecure.length}/${manualSecure.length})`);

  console.log(col(C.bold, "\n📂 Por categoría:"));
  STRIDE_CATEGORIES.forEach(cat => {
    const m   = metrics.perCategory[cat];
    const cov = m.covered ? col(C.green, "✓") : col(C.red, "✗");
    console.log(
      `   ${cov} ${cat.padEnd(22)} P=${pct(m.precision).padStart(6)} R=${pct(m.recall).padStart(6)} F1=${pct(m.f1).padStart(6)} TP=${m.tp} FP=${m.fp} FN=${m.fn}`
    );
  });

  // 8. Build full report object
  const report = {
    generated_at: new Date().toISOString(),
    sources: {
      manual_insecure: insecurePath,
      manual_secure:   securePath,
      automated:       autoResult.file,
    },
    paper_metrics: paperMetrics,
    format_comparison: formatComparison,
    metrics: {
      summary: {
        ...summary,
        strideCoverage: round2(summary.strideCoverage),
        precision:      round2(summary.precision),
        recall:         round2(summary.recall),
        f1:             round2(summary.f1),
      },
      perCategory: Object.fromEntries(
        Object.entries(metrics.perCategory).map(([cat, m]) => [
          cat,
          { ...m, precision: round2(m.precision), recall: round2(m.recall), f1: round2(m.f1) },
        ])
      ),
      perSeverity:    metrics.perSeverity,
      annotatedManual: metrics.annotatedManual.map(({ _key, ...rest }) => rest),
      fpThreats:      metrics.fpThreats,
    },
  };

  // 9. Write outputs
  const jsonOut = path.resolve("metrics-report.json");
  fs.writeFileSync(jsonOut, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(col(C.green, "\n✅ metrics-report.json escrito"));

  const htmlOut = path.resolve("metrics-report.html");
  fs.writeFileSync(htmlOut, generateHTML(report), "utf8");
  console.log(col(C.green, "✅ metrics-report.html escrito (autónomo, sin internet)"));

  const docsDir = path.resolve("docs");
  if (!fs.existsSync(docsDir)) fs.mkdirSync(docsDir, { recursive: true });
  const texOut = path.resolve("docs/results-table.tex");
  fs.writeFileSync(texOut, generateLatex(paperMetrics, report.metrics.perCategory, report.sources), "utf8");
  console.log(col(C.green, "✅ docs/results-table.tex escrito"));

  console.log(col(C.gray, `\n   Abrir HTML : file://${htmlOut}\n`));
}

main();
