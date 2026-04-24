#!/usr/bin/env node
/**
 * check-baseline.js (US-06)
 * Compares current threats against the approved security baseline.
 * Exits with code 1 if new HIGH-severity threats are found.
 * Exits with code 0 if all threats are already in the baseline or are not High.
 */

"use strict";

const fs = require("fs");
const path = require("path");

// ── ANSI colour helpers ──────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};
const color = (c, text) => `${c}${text}${C.reset}`;

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Build a normalised key for a threat: "category|component|severity"
 * Used for stable comparison independent of description wording.
 */
function threatKey(t) {
  const cat = (t.category || "").trim().toLowerCase();
  const comp = (t.component || "").trim().toLowerCase();
  const sev = (t.severity || "").trim().toLowerCase();
  return `${cat}|${comp}|${sev}`;
}

/**
 * Load JSON from a file, returning null if the file is missing or invalid.
 */
function loadJSON(filePath) {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) return null;
  try {
    return JSON.parse(fs.readFileSync(abs, "utf8"));
  } catch (err) {
    console.error(color(C.red, `❌ Failed to parse ${filePath}: ${err.message}`));
    return null;
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────

function main() {
  console.log(color(C.bold, "\n🔒 STRIDE Baseline Check"));
  console.log(color(C.gray, "─".repeat(50)));

  // 1. Load threats (prefer threats-output.json, fall back to combined-report.json)
  let threatsData = loadJSON("threats-output.json");
  let threatsSource = "threats-output.json";

  if (!threatsData) {
    threatsData = loadJSON("combined-report.json");
    threatsSource = "combined-report.json";
  }

  if (!threatsData) {
    console.error(color(C.red, "❌ No threats file found (threats-output.json / combined-report.json)"));
    process.exit(1);
  }

  // Collect all threats from possible locations in the JSON
  let threats = [];
  if (Array.isArray(threatsData.combined_threats)) {
    threats = threatsData.combined_threats;
  } else if (Array.isArray(threatsData.threats)) {
    threats = threatsData.threats;
  } else {
    // Flatten stride_analysis categories
    const stride = threatsData.stride_analysis || {};
    Object.values(stride).forEach((arr) => {
      if (Array.isArray(arr)) threats.push(...arr);
    });
  }

  console.log(`📂 Threats source : ${color(C.cyan, threatsSource)}`);
  console.log(`📊 Threats found  : ${color(C.cyan, String(threats.length))}`);

  // 2. Load baseline
  const baseline = loadJSON("security/baseline.json");
  if (!baseline) {
    console.error(color(C.red, "❌ security/baseline.json not found"));
    process.exit(1);
  }

  const approvedThreats = Array.isArray(baseline.approved_threats)
    ? baseline.approved_threats
    : [];

  const approvedKeys = new Set(approvedThreats.map(threatKey));
  console.log(`📋 Baseline threats: ${color(C.cyan, String(approvedKeys.size))}`);
  console.log(color(C.gray, "─".repeat(50)));

  // 3. Identify new threats that are NOT in the baseline
  const newThreats = threats.filter((t) => !approvedKeys.has(threatKey(t)));
  const newHighThreats = newThreats.filter(
    (t) => (t.severity || "").toLowerCase() === "alta"
  );

  // 4. Print report
  if (newThreats.length === 0) {
    console.log(color(C.green, "✅ All detected threats are in the approved baseline."));
  } else {
    console.log(color(C.yellow, `⚠️  New threats not in baseline: ${newThreats.length}`));
    newThreats.forEach((t) => {
      const sev = (t.severity || "?").toUpperCase();
      const sevColor = sev === "ALTA" ? C.red : C.yellow;
      console.log(
        `   ${color(sevColor, `[${sev}]`)} ${t.category} / ${t.component}`
      );
    });
  }

  if (newHighThreats.length > 0) {
    console.log(
      color(C.red, `\n🚨 FAIL: ${newHighThreats.length} new HIGH-severity threat(s) found!\n`)
    );
    newHighThreats.forEach((t) => {
      console.log(
        color(C.red, `   ✗ [Alta] ${t.category} / ${t.component}`)
      );
    });
    console.log(
      color(
        C.gray,
        "\n   To approve these threats, run: node check-baseline.js --update\n"
      )
    );
    process.exit(1);
  }

  console.log(color(C.green, "\n✅ Baseline check passed. No new High-severity threats.\n"));
  process.exit(0);
}

// Support --update flag to add new threats to the baseline
if (process.argv.includes("--update")) {
  console.log(color(C.yellow, "📝 --update flag detected. Running update-baseline logic…"));

  let threatsData = loadJSON("threats-output.json") || loadJSON("combined-report.json");
  if (!threatsData) {
    console.error(color(C.red, "❌ No threats file found"));
    process.exit(1);
  }

  let threats = [];
  if (Array.isArray(threatsData.combined_threats)) threats = threatsData.combined_threats;
  else if (Array.isArray(threatsData.threats)) threats = threatsData.threats;
  else {
    const stride = threatsData.stride_analysis || {};
    Object.values(stride).forEach((arr) => { if (Array.isArray(arr)) threats.push(...arr); });
  }

  const baseline = loadJSON("security/baseline.json") || { version: "1.0", last_updated: "", approved_threats: [] };
  const approvedThreats = baseline.approved_threats || [];
  const approvedKeys = new Set(approvedThreats.map(threatKey));

  let added = 0;
  threats.forEach((t, i) => {
    if (!approvedKeys.has(threatKey(t))) {
      approvedThreats.push({
        id: `threat-auto-${Date.now()}-${i}`,
        category: t.category,
        component: t.component,
        severity: t.severity,
        approved_date: new Date().toISOString().split("T")[0],
        reason: "Auto-approved via update-baseline",
      });
      added++;
    }
  });

  baseline.approved_threats = approvedThreats;
  baseline.last_updated = new Date().toISOString().split("T")[0];
  fs.writeFileSync(
    path.resolve("security/baseline.json"),
    JSON.stringify(baseline, null, 2) + "\n",
    "utf8"
  );
  console.log(color(C.green, `✅ Baseline updated. Added ${added} new threat(s).`));
  process.exit(0);
}

main();
