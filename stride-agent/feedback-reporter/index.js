/**
 * ST-14.3 - Generador de reporte HTML para modo feedback
 */

'use strict';

const fs = require('fs');

const SEVERITY_COLOR = { Alta: '#f87171', Media: '#fbbf24', Baja: '#60a5fa' };
const STRIDE_COLOR = {
  Spoofing: '#a78bfa',
  Tampering: '#fb923c',
  Repudiation: '#facc15',
  InformationDisclosure: '#38bdf8',
  DenialOfService: '#f87171',
  ElevationOfPrivilege: '#4ade80'
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function scoreColor(score) {
  if (score >= 70) return '#4ade80';
  if (score >= 40) return '#fbbf24';
  return '#f87171';
}

function scoreLabel(score) {
  if (score >= 70) return 'Diseño Seguro';
  if (score >= 40) return 'Mejoras Necesarias';
  return 'Alto Riesgo';
}

function svgGauge(score) {
  const col = scoreColor(score);
  const r = 70;
  const cx = 100;
  const cy = 100;
  const circumference = Math.PI * r;
  const filled = (score / 100) * circumference;
  const gap = circumference - filled;

  return `<svg viewBox="0 0 200 115" xmlns="http://www.w3.org/2000/svg" aria-label="Security score ${score}/100">
  <path d="M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}" fill="none" stroke="#2d2d44" stroke-width="18" stroke-linecap="round"/>
  <path d="M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}" fill="none" stroke="${col}" stroke-width="18"
        stroke-linecap="round" stroke-dasharray="${filled} ${gap}" stroke-dashoffset="0"/>
  <text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="${col}" font-size="32" font-weight="700" font-family="Segoe UI,sans-serif">${score}</text>
  <text x="${cx}" y="${cy + 18}" text-anchor="middle" fill="#888" font-size="12" font-family="Segoe UI,sans-serif">${escapeHtml(scoreLabel(score))}</text>
</svg>`;
}

function renderGoodItems(items) {
  if (!items.length) return '<p style="color:#555;font-style:italic">Sin controles positivos identificados.</p>';
  return items.map(item => {
    const col = STRIDE_COLOR[item.stride_impact] || '#888';
    return `<div class="fb-item fb-good">
  <div class="fb-item-header">
    <span class="fb-badge" style="background:${col}20;color:${col};border-color:${col}">${escapeHtml(item.stride_impact)}</span>
    <span class="fb-item-title">${escapeHtml(item.aspect)}</span>
  </div>
  <div class="fb-item-body">${escapeHtml(item.why_it_matters)}</div>
</div>`;
  }).join('\n');
}

function renderFixItems(items) {
  if (!items.length) return '<p style="color:#555;font-style:italic">Sin vulnerabilidades críticas identificadas.</p>';
  return items.map(item => {
    const sc = SEVERITY_COLOR[item.severity] || '#888';
    const cc = STRIDE_COLOR[item.stride_category] || '#888';
    return `<div class="fb-item fb-fix">
  <div class="fb-item-header">
    <span class="fb-badge" style="background:${sc}20;color:${sc};border-color:${sc}">${escapeHtml(item.severity)}</span>
    <span class="fb-badge" style="background:${cc}20;color:${cc};border-color:${cc}">${escapeHtml(item.stride_category)}</span>
    <span class="fb-item-title">${escapeHtml(item.issue)}</span>
  </div>
  <div class="fb-item-body"><strong>Cómo corregir:</strong> ${escapeHtml(item.how_to_fix)}</div>
</div>`;
  }).join('\n');
}

function renderAddItems(items) {
  if (!items.length) return '<p style="color:#555;font-style:italic">Sin controles adicionales recomendados.</p>';
  return items.map(item => {
    const cc = STRIDE_COLOR[item.stride_category] || '#888';
    return `<div class="fb-item fb-add">
  <div class="fb-item-header">
    <span class="fb-badge" style="background:${cc}20;color:${cc};border-color:${cc}">${escapeHtml(item.stride_category)}</span>
    <span class="fb-item-title">${escapeHtml(item.missing_control)}</span>
  </div>
  <div class="fb-item-body">
    <div>${escapeHtml(item.why_needed)}</div>
    ${item.implementation_hint ? `<div class="fb-hint"><strong>Cómo implementar:</strong> ${escapeHtml(item.implementation_hint)}</div>` : ''}
  </div>
</div>`;
  }).join('\n');
}

function generateFeedbackHTML(feedbackOutput, outputPath) {
  const score  = feedbackOutput.overall_security_score;
  const source = feedbackOutput.metadata.source_name || 'artefacto';
  const date   = feedbackOutput.metadata.generated_at
    ? new Date(feedbackOutput.metadata.generated_at).toLocaleString('es-ES')
    : new Date().toLocaleString('es-ES');

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Feedback — ${escapeHtml(source)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f1e; color: #e0e0e0; padding: 24px; min-height: 100vh; }
  .container { max-width: 900px; margin: 0 auto; }
  header { margin-bottom: 32px; padding-bottom: 16px; border-bottom: 1px solid #2d2d44; }
  h1 { font-size: 1.7em; color: #fff; margin-bottom: 6px; }
  .meta { color: #666; font-size: 0.82em; }
  .summary-box { background: #1a1a2e; border: 1px solid #2d2d44; border-radius: 6px; padding: 20px; margin-bottom: 28px; display: flex; gap: 28px; align-items: center; flex-wrap: wrap; }
  .gauge-wrap { flex-shrink: 0; width: 140px; }
  .gauge-wrap svg { width: 100%; height: auto; }
  .summary-text { flex: 1; min-width: 200px; }
  .summary-text h2 { color: #ccc; font-size: 1em; font-weight: 600; margin-bottom: 8px; }
  .summary-text p { color: #aaa; font-size: 0.92em; line-height: 1.6; }
  .section { background: #1a1a2e; border: 1px solid #2d2d44; border-radius: 6px; padding: 20px; margin-bottom: 20px; }
  .section-title { font-size: 1.05em; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 10px; }
  .section-title.good  { color: #4ade80; }
  .section-title.fix   { color: #f87171; }
  .section-title.add   { color: #60a5fa; }
  .section-count { font-size: 0.8em; background: #2d2d44; padding: 2px 8px; border-radius: 10px; color: #aaa; font-weight: 400; }
  .fb-item { border-left: 3px solid; border-radius: 4px; padding: 12px 14px; margin-bottom: 10px; background: #0f0f1e; }
  .fb-good { border-left-color: #4ade80; }
  .fb-fix  { border-left-color: #f87171; }
  .fb-add  { border-left-color: #60a5fa; }
  .fb-item-header { display: flex; align-items: flex-start; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }
  .fb-badge { font-size: 0.7em; font-weight: 600; padding: 2px 8px; border-radius: 3px; border: 1px solid; white-space: nowrap; flex-shrink: 0; }
  .fb-item-title { font-size: 0.92em; font-weight: 600; color: #fff; flex: 1; min-width: 0; }
  .fb-item-body { font-size: 0.85em; color: #aaa; line-height: 1.55; }
  .fb-hint { margin-top: 6px; color: #888; }
  footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #2d2d44; color: #444; font-size: 0.78em; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Security Feedback — ${escapeHtml(source)}</h1>
    <div class="meta">Generado: ${escapeHtml(date)} | Proveedor: ${escapeHtml(feedbackOutput.metadata.provider || 'N/A')} | Tipo: ${escapeHtml(feedbackOutput.artefact_type)}</div>
  </header>

  <div class="summary-box">
    <div class="gauge-wrap">${svgGauge(score)}</div>
    <div class="summary-text">
      <h2>Resumen del sistema</h2>
      <p>${escapeHtml(feedbackOutput.system_summary)}</p>
    </div>
  </div>

  <div class="section">
    <div class="section-title good">✔ Lo que está bien <span class="section-count">${feedbackOutput.whats_good.length}</span></div>
    ${renderGoodItems(feedbackOutput.whats_good)}
  </div>

  <div class="section">
    <div class="section-title fix">✖ Lo que hay que corregir <span class="section-count">${feedbackOutput.what_to_fix.length}</span></div>
    ${renderFixItems(feedbackOutput.what_to_fix)}
  </div>

  <div class="section">
    <div class="section-title add">+ Lo que hay que agregar <span class="section-count">${feedbackOutput.what_to_add.length}</span></div>
    ${renderAddItems(feedbackOutput.what_to_add)}
  </div>

  <footer>Generado por STRIDE Agent — Attack-Simulation-FDSI</footer>
</div>
</body>
</html>`;

  fs.writeFileSync(outputPath, html, 'utf-8');
}

module.exports = { generateFeedbackHTML };
